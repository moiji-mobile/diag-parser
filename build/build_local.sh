#!/bin/sh

set -ex

mkdir deps || true
cd deps
git clone git://git.osmocom.org/libosmocore || true
cd libosmocore
git fetch || true
git reset --hard 19ec7b948322bbc9457a2b22219c93558a6f931e
autoreconf --install --force
./configure --disable-pcsc --prefix=$PWD/../install ac_cv_path_DOXYGEN=false
make install
cd ../..


export PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig

make LDFLAGS+="-Wl,-rpath,$PWD/deps/install/lib/"
