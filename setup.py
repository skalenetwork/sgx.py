from setuptools import (
    find_packages,
    setup,
)

extras_require = {
    'linter': [
        'ruff==0.13.2',
    ],
    'dev': [
        'coincurve==13.0.0',
        'python-dotenv==0.13.0',
        'twine==6.2.0',
        'pytest==8.4.2',
        'mock==5.2.0',
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
        'web3>=6.20.2,<8.0.0',
        'pyzmq==27.1.0',
        'pem==23.1.0',
        'cryptography>=46.0.1,<47.0.0',
    ],
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.11,<4',
    extras_require=extras_require,
    package_data={'sgx': ['generate.sh']},
)
