#!/bin/bash

# may differ in the future
NAME_ROOT=electrum-crown
PRJ_ROOT=electrum-crown
#PYTHON_VERSION=3.6.8

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export WINEDEBUG=-all
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python3
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

#here="$(dirname "$(readlink -e "$0")")"
#
#. "$CONTRIB"/build_tools_util.sh

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

for repo in electrum-crown-locale electrum-crown-icons; do
    if [ -d $repo ]; then
	cd $repo
	git pull
	git checkout master
	cd ..
    else
    # FIXME use github of crown
	URL=https://github.com/sirak92/$repo.git
	git clone -b master $URL $repo
    fi
done

pushd electrum-crown-locale
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
cp -r electrum-crown-locale/locale $WINEPREFIX/drive_c/$NAME_ROOT/lib/
cp electrum-crown-icons/icons_rc.py $WINEPREFIX/drive_c/$NAME_ROOT/gui/qt/

# Install frozen dependencies
$PYTHON -m pip install --no-warn-script-location -r "$CONTRIB"/deterministic-build/requirements.txt

$PYTHON -m pip install --no-warn-script-location -r "$CONTRIB"/deterministic-build/requirements-hw.txt

#pushd $WINEPREFIX/drive_c/electrum-crown
## see https://github.com/pypa/pip/issues/2195 -- pip makes a copy of the entire directory
#info "Pip installing Electrum Crown. This might take a long time if the project folder is large."
#$PYTHON -m pip install --no-dependencies --no-warn-script-location .
#popd
pushd $WINEPREFIX/drive_c/$NAME_ROOT
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone and portable versions
wine "C:/python3/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

info "building NSIS installer"
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script itself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv electrum-crown-setup.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

info "Padding binaries to 8-byte boundaries, and fixing COFF image checksum in PE header"
# note: 8-byte boundary padding is what osslsigncode uses:
#       https://github.com/mtrojnar/osslsigncode/blob/6c8ec4427a0f27c145973450def818e35d4436f6/osslsigncode.c#L3047
(
    cd dist
    for binary_file in ./*.exe; do
        info ">> fixing $binary_file..."
        # code based on https://github.com/erocarrera/pefile/blob/bbf28920a71248ed5c656c81e119779c131d9bd4/pefile.py#L5877
        python3 <<EOF
pe_file = "$binary_file"
with open(pe_file, "rb") as f:
    binary = bytearray(f.read())
pe_offset = int.from_bytes(binary[0x3c:0x3c+4], byteorder="little")
checksum_offset = pe_offset + 88
checksum = 0

# Pad data to 8-byte boundary.
remainder = len(binary) % 8
binary += bytes(8 - remainder)

for i in range(len(binary) // 4):
    if i == checksum_offset // 4:  # Skip the checksum field
        continue
    dword = int.from_bytes(binary[i*4:i*4+4], byteorder="little")
    checksum = (checksum & 0xffffffff) + dword + (checksum >> 32)
    if checksum > 2 ** 32:
        checksum = (checksum & 0xffffffff) + (checksum >> 32)

checksum = (checksum & 0xffff) + (checksum >> 16)
checksum = (checksum) + (checksum >> 16)
checksum = checksum & 0xffff
checksum += len(binary)

# Set the checksum
binary[checksum_offset : checksum_offset + 4] = int.to_bytes(checksum, byteorder="little", length=4)

with open(pe_file, "wb") as f:
    f.write(binary)
EOF
    done
)

sha256sum dist/electrum-crown*.exe

#echo "Done."
#md5sum dist/electrum*exe
