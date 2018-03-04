#!/bin/bash

# may differ in the future
NAME_ROOT=electrum-crown
PRJ_ROOT=electrum-crown
PYTHON_VERSION=3.5.4

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

cd tmp

for repo in $PRJ_ROOT; do
    if [ -d $repo ]; then
	cd $repo
	git pull
	git checkout crown
	cd ..
    else
	URL=https://github.com/Crowndev/$repo.git
	git clone -b crown $URL $repo
    fi
done

# FIXME workaround for locale and icons, as they are not in github yet
# we presume that data are already generated for now
mkdir -p electrum-locale
mkdir -p electrum-icons
cp -rf /home/sirak/Desktop/electrum-crown/lib/locale electrum-locale
cp -rf /home/sirak/Desktop/electrum-crown/gui/qt/icons_rc.py electrum-icons/

pushd electrum-locale
for i in ./locale/*; do
    dir=$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electrum.mo $i/electrum.po || true
done
popd

pushd $PRJ_ROOT
if [ ! -z "$1" ]; then
    git checkout $1
fi

VERSION=`git describe --tags`
echo "Last commit: $VERSION"
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

rm -rf $WINEPREFIX/drive_c/$NAME_ROOT
cp -r $PRJ_ROOT $WINEPREFIX/drive_c/$NAME_ROOT
cp $PRJ_ROOT/LICENCE .
cp -r electrum-locale/locale $WINEPREFIX/drive_c/$NAME_ROOT/lib/
cp electrum-icons/icons_rc.py $WINEPREFIX/drive_c/$NAME_ROOT/gui/qt/

# Install frozen dependencies
$PYTHON -m pip install -r ../../deterministic-build/requirements.txt

$PYTHON -m pip install -r ../../deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/$NAME_ROOT
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script iself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv electrum-crown-setup.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

echo "Done."
md5sum dist/electrum*exe
