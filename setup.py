from setuptools import (
    find_packages,
    setup,
)

extras_require = {
    'linter': [
        'ruff==0.17.2',
    ],
    'dev': [
        'build==1.6.1',
        'coincurve==13.0.0',
        'python-dotenv==1.2.4',
        'twine==7.0.0',
        'pytest==9.1.1',
        'mock==5.2.0',
        'web3==8.0.0',
    ],
}

extras_require['dev'] = extras_require['linter'] + extras_require['dev']

setup(
    name='sgx.py',
    version='0.12',
    description='SGX',
    url='http://github.com/skalenetwork/sgx.py',
    author='SKALE Labs',
    author_email='support@skalelabs.com',
    install_requires=[
        'cryptography>=50.0.2,<51',
        'cytoolz>=0.12',
        'eth-account>=0.13,<0.15',
        'eth-hash[pycryptodome]>=0.7',
        'eth-utils>=5,<7',
        'hexbytes>=1,<3',
        'pem==23.1.0',
        'pyzmq==27.2.0',
        'requests>=2.33.0',
        'urllib3>=2.8.0',
    ],
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.11,<4',
    extras_require=extras_require,
    package_data={'sgx': ['generate.sh']},
)
