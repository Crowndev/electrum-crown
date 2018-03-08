#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp
import argparse

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: Electrum Crown requires Python version >= 3.4.0...")

data_files = ['contrib/requirements/' + r for r in ['requirements.txt', 'requirements-hw.txt']]

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-crown.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum.png'])
    ]

setup(
    name="Electrum Crown",
    version=version.PACKAGE_VERSION,
    install_requires=requirements,
    extras_require={
        'hardware': requirements_hw,
    },
    packages=[
        'electrumcrown',
        'electrumcrown_gui',
        'electrumcrown_gui.qt',
        'electrumcrown_plugins',
        'electrumcrown_plugins.audio_modem',
        'electrumcrown_plugins.cosigner_pool',
        'electrumcrown_plugins.email_requests',
        'electrumcrown_plugins.greenaddress_instant',
        'electrumcrown_plugins.hw_wallet',
        'electrumcrown_plugins.keepkey',
        'electrumcrown_plugins.labels',
        'electrumcrown_plugins.ledger',
        'electrumcrown_plugins.trezor',
        'electrumcrown_plugins.digitalbitbox',
        'electrumcrown_plugins.trustedcoin',
        'electrumcrown_plugins.virtualkeyboard',
    ],
    package_dir={
        'electrumcrown': 'lib',
        'electrumcrown_gui': 'gui',
        'electrumcrown_plugins': 'plugins',
    },
    package_data={
        'electrumcrown': [
            'servers.json',
            'servers_testnet.json',
            'currencies.json',
            'checkpoints.json',
            'checkpoints_testnet.json',
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electrum-crown'],
    data_files=data_files,
    description="Lightweight Crown Wallet",
    author="Sirak Ghazaryan",
    author_email="sirak@crown.tech",
    license="MIT Licence",
    url="https://crown.tech",
    long_description="""Lightweight Crown Wallet"""
)
