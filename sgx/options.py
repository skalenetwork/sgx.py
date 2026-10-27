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

from dataclasses import dataclass, fields
from enum import IntEnum

from sgx.utils import SgxError


class SgxServerOptionsError(SgxError):
    pass


class LogLevel(IntEnum):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4


@dataclass(frozen=True)
class ServerFlags:
    log_level: LogLevel
    enclave_log_level: LogLevel
    use_https: bool
    autoconfirm: bool
    enter_backup_key: bool
    reencrypt_database_with_new_sek: bool
    check_cert: bool
    check_zmq_sig: bool
    auto_sign: bool
    generate_test_keys: bool
    check_key_ownership: bool
    thread_pool_size: int


@dataclass(frozen=True)
class EffectiveOptions:
    rpc_port: int  # as bound inside the server, before any port mapping
    rpc_client_certificate_required: bool
    zmq_key_ownership_enforced: bool  # -e is in effect; applies to ZMQ only
    json_rpc_key_ownership_enforced: bool
    sgx_thread_pool_size: int


@dataclass(frozen=True)
class BuildInfo:
    sgx_simulation: bool
    sgx_debug_launch: bool


@dataclass(frozen=True)
class ServerOptions:
    """Options sgxwallet reports about itself, from getServerOptions; they are not attested.
    build is sent only to authenticated callers: HTTPS with the client certificate check."""

    flags: ServerFlags
    effective: EffectiveOptions
    build: BuildInfo | None = None

    @classmethod
    def from_result(cls, result):
        if not isinstance(result, dict):
            raise SgxServerOptionsError(f'Malformed getServerOptions result: {result!r}')
        build = result.get('build')
        return cls(
            _load(ServerFlags, result.get('flags')),
            _load(EffectiveOptions, result.get('effective')),
            None if build is None else _load(BuildInfo, build),
        )


def _load(cls, data):
    # Fields match the camelCase keys ignoring case and underscores: use_https is useHTTPS
    try:
        values = {key.lower(): value for key, value in data.items()}
        kwargs = {f.name: _typed(f.type, values[f.name.replace('_', '')]) for f in fields(cls)}
    except (AttributeError, KeyError, TypeError, ValueError) as err:
        raise SgxServerOptionsError(f'Malformed {cls.__name__}: {data!r}') from err
    return cls(**kwargs)


def _typed(kind, value):
    # Exact types, because bool is a subclass of int
    if type(value) is not (int if kind is LogLevel else kind):
        raise TypeError(f'{value!r} is not {kind.__name__}')
    return kind(value)
