from setuptools import (
    find_packages,
    setup,
)

extras_require = {
    'linter': [
        "flake8==3.7.9"
    ],
    'dev': [
        "coincurve==13.0.0",
        "python-dotenv==0.13.0",
        "twine==3.1.1",
        "pytest==5.4.2",
        "mock==4.0.2"
    ]
}

extras_require['dev'] = (
    extras_require['linter'] + extras_require['dev']
)

setup(
    name='sgx.py',
    version='0.8',
    description='SGX',
    url='http://github.com/skalenetwork/sgx.py',
    author='SKALE Labs',
    author_email='support@skalelabs.com',
    install_requires=[
      "web3==5.13.1",
      "pyzmq==22.2.1",
      "pem==21.2.0",
      'M2Crypto==0.38.0',
      "eth-account==0.5.3"
    ],
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.7,<4',
    extras_require=extras_require,
    package_data={
        'sgx': ['generate.sh']
    }
)
