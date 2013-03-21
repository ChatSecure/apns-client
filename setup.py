try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='apns-client',
    version='0.1.1',
    author='Sardar Yumatov',
    author_email='ja.doma@gmail.com',
    url='https://bitbucket.org/sardarnl/apns-client',
    description='Python client for Apple Push Notification service (APNs)',
    long_description=open('README.rst').read(),
    packages=['apnsclient'],
    license="Apache 2.0",
    keywords='apns push notification apple messaging iOS',
    install_requires=['pyOpenSSL'],
    classifiers = [ 'Development Status :: 4 - Beta',
                    'Intended Audience :: Developers',
                    'License :: OSI Approved :: Apache Software License',
                    'Programming Language :: Python',
                    'Topic :: Software Development :: Libraries :: Python Modules']
)
