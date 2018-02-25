Electrum-Crown - Lightweight Crown client
=====================================

::

  Licence: MIT Licence
  Author: Sirak Ghazaryan
  Language: Python
  Homepage:




Getting started
===============

Electrum Crown is a pure python application forked from Electrum. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python-pyqt5

If you downloaded the official package (tar.gz), you can run
Electrum Crown from its root directory (called Electrum), without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum Crown from its root directory, just do::

    ./electron-crown

You can also install Electrum Crown on your system, by running this command::

    python setup.py install

This will download and install the Python dependencies used by
Electrum Crown, instead of using the 'packages' directory.

If you cloned the git repository, you need to compile extra files
before you can run Electrum Crown. Read the next section, "Development
Version".



Development version
===================

Check out the code from Github::

    git clone https://github.com/Crowndev/electrum-crown
    cd electrum-crown

Run install (this should install dependencies)::

    python setup.py install

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-pycurl gettext
    ./contrib/make_locale




Creating Binaries
=================


To create binaries, create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum Crown.

Mac OS X
--------

::

    python setup-release.py py2app

    hdiutil create -fs HFS+ -volname "Electrum-Crown" -srcfolder dist/Electrum-Crown.app dist/electron-cash-VERSION-macosx.dmg

Windows
-------

See `contrib/build-wine/README` file.


Android
-------

See `gui/kivy/Readme.txt` file.
