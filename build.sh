#!/bin/sh
set -e

: ${SDK:=iphoneos}
: ${ARCHS:="arm64"}
: ${IPHONEOS_DEPLOYMENT_TARGET:="13.0"}
TARGET_PATH=$PWD/target.${SDK}
export IPHONEOS_DEPLOYMENT_TARGET

cmake \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_SYSROOT=${SDK} \
    -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
    -DBUILD_SHARED_LIBS=NO \
    -DOPENSSL_ROOT_DIR=/Library/libdigidocpp.${SDK} \
    -DDOXYGEN_EXECUTABLE=NOTFOUND \
    -DINSTALL_FRAMEWORKDIR=${TARGET_PATH} \
     -S . -B build.${SDK}
cmake --build build.${SDK}
cmake --install build.${SDK}
