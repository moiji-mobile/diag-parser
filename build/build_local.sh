#!/bin/sh

set -ex

mkdir deps || true
cd deps
git clone git://git.osmocom.org/libosmocore || true
cd libosmocore
git fetch || true
git reset --hard fef2fa224a754df3f9792d1ddcd3a6d9a73658b1
autoreconf --install --force
./configure --disable-pcsc --prefix=$PWD/../install ac_cv_path_DOXYGEN=false
make install
cd ../..


export PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig

make LDFLAGS+="-Wl,-rpath,$PWD/deps/install/lib/"
