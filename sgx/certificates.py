#    -*- coding: utf-8 -*-
#
#     This file is part of sgx.py
#
#     Copyright (C) 2026 SKALE Labs
#
#     sgx.py is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     sgx.py is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with sgx.py.  If not, see <https://www.gnu.org/licenses/>.

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from sgx.constants import CRT_FILENAME
from sgx.utils import SgxError


class SgxCertificateError(SgxError):
    pass


class CertificateMatch(Enum):
    MATCH = 'match'  # the local certificate is the newest issued
    UNEXPECTED_NUMBER = 'unexpected_number'  # as MATCH, but the count differs from the expected
    NOT_LATEST = 'not_latest'  # a newer certificate was issued after it
    NOT_ISSUED = 'not_issued'  # unknown to this wallet's CA database


@dataclass(frozen=True)
class NewestCertificate:
    serial: int
    sha256: bytes
    not_before: datetime
    not_after: datetime
    status: str  # V valid, R revoked, E expired


@dataclass(frozen=True)
class IssuedCertificatesInfo:
    """Client certificates issued by the wallet's CA, from getIssuedCertificatesInfo."""

    certificates_number: int
    server_certificates_number: int
    newest_certificate: NewestCertificate | None

    @classmethod
    def from_result(cls, result):
        """Parses a result in the format sgxwallet documents and rejects anything else."""
        try:
            number = _count(result['certificatesNumber'])
            newest = result['newestCertificate']
            # sgxwallet sends a newest certificate exactly when it has issued any
            if (newest is None) != (number == 0):
                raise ValueError('newestCertificate does not match certificatesNumber')
            if newest is not None:
                newest = NewestCertificate(
                    serial=int(_text('[0-9A-F]+', newest['serial']), 16),
                    sha256=bytes.fromhex(_text('[0-9a-f]{64}', newest['sha256'])),
                    not_before=_utc(newest['notBefore']),
                    not_after=_utc(newest['notAfter']),
                    status=_text('[VRE]', newest['status']),
                )
            return cls(number, _count(result['serverCertificatesNumber']), newest)
        except (KeyError, TypeError, ValueError) as err:
            raise SgxCertificateError(
                f'Malformed getIssuedCertificatesInfo result: {result!r}'
            ) from err

    def check(self, certificate, expected_number=None):
        """Compares an x509.Certificate with the newest certificate the wallet issued. If the
        server does not verify client certificates, NOT_LATEST may be another CA's certificate."""
        newest = self.newest_certificate
        if newest is not None and newest.sha256 == certificate.fingerprint(hashes.SHA256()):
            if expected_number is None or expected_number == self.certificates_number:
                outcome = CertificateMatch.MATCH
            else:
                outcome = CertificateMatch.UNEXPECTED_NUMBER
        elif newest is not None and newest.serial > certificate.serial_number:
            outcome = CertificateMatch.NOT_LATEST
        else:
            outcome = CertificateMatch.NOT_ISSUED
        return CertificateCheck(outcome, self)


@dataclass(frozen=True)
class CertificateCheck:
    outcome: CertificateMatch
    info: IssuedCertificatesInfo

    @property
    def newer_issued_at(self):
        if self.outcome is CertificateMatch.NOT_LATEST:
            return self.info.newest_certificate.not_before
        return None


def load_local_certificate(cert_dir):
    try:
        with open(os.path.join(cert_dir, CRT_FILENAME), 'rb') as crt_file:
            return x509.load_pem_x509_certificate(crt_file.read())
    except (OSError, TypeError, ValueError) as err:  # TypeError: no cert_dir
        raise SgxCertificateError(f'Cannot load {CRT_FILENAME} from {cert_dir!r}') from err


def _count(value):
    # Exact type, because bool is a subclass of int
    if type(value) is not int or value < 0:
        raise ValueError(f'Invalid count {value!r}')
    return value


def _text(pattern, value):
    if not re.fullmatch(pattern, value):
        raise ValueError(f'Invalid value {value!r}')
    return value


def _utc(value):
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
