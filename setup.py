from setuptools import setup

setup(
    name='bootstrap-local-manager-plugin',
    version='1.2',
    author='greggigon',
    packages=['local_manager_plugin'],
    description='Plugin for bootstraping manager with CFY CLI on the same host',
    install_requires=[
        'cloudify-plugins-common>=3.2',
        'fabric==1.8.3',
        'six>=1.8.0',
    ]
)
