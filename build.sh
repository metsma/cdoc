#!/bin/sh
set -e

OPENSSL_DIR=openssl-1.0.2n
TARGET_PATH=$PWD/target
SYSROOT=$(xcrun -sdk iphoneos --show-sdk-path)
: ${ARCHS:="armv7 armv7s arm64"}
: ${IPHONEOS_DEPLOYMENT_TARGET:="9.0"}
export IPHONEOS_DEPLOYMENT_TARGET
export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
export CXXFLAGS="${CFLAGS} -Wno-null-conversion"

function openssl {
    echo Building ${OPENSSL_DIR}
    if [ ! -f ${OPENSSL_DIR}.tar.gz ]; then
        curl -O https://www.openssl.org/source/${OPENSSL_DIR}.tar.gz
    fi
    rm -rf ${OPENSSL_DIR}
    tar xf ${OPENSSL_DIR}.tar.gz
    pushd ${OPENSSL_DIR}

    CRYPTO=""
    SSL=""
    for ARCH in ${ARCHS}
    do
        if [[ "${ARCH}" == "x86_64" ]]; then
            ./Configure darwin64-x86_64-cc --openssldir=${TARGET_PATH} no-hw
            sed -ie 's!^CFLAG=!CFLAG=-isysroot '${SYSROOT}' !' Makefile
        else
            ./Configure iphoneos-cross --openssldir=${TARGET_PATH} no-hw -Wno-ignored-optimization-argument
            sed -ie 's!-isysroot $(CROSS_TOP)/SDKs/$(CROSS_SDK)!-arch '${ARCH}' -isysroot '${SYSROOT}'!' Makefile
        fi
        make -s depend all install_sw INSTALL_PREFIX=${PWD}/${ARCH} > /dev/null
        make clean
        cp -R ${ARCH}/${TARGET_PATH}/include/openssl ${TARGET_PATH}/include
        CRYPTO="${CRYPTO} ${ARCH}/${TARGET_PATH}/lib/libcrypto.a"
        SSL="${SSL} ${ARCH}/${TARGET_PATH}/lib/libssl.a"
    done
    lipo -create ${CRYPTO} -output ${TARGET_PATH}/lib/libcrypto.a
    lipo -create ${SSL} -output ${TARGET_PATH}/lib/libssl.a
    popd
}

function cdoc {
    echo Building cdoc
    rm -rf build
    mkdir build
    pushd build
    cmake \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_C_COMPILER_WORKS=yes \
        -DCMAKE_CXX_COMPILER_WORKS=yes \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_OSX_SYSROOT=${SYSROOT} \
        -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
        -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
        -DDOXYGEN_EXECUTABLE=NOTFOUND \
        -DINSTALL_FRAMEWORKDIR=${TARGET_PATH} \
        ..
    make install
    popd
}

mkdir -p ${TARGET_PATH}/include ${TARGET_PATH}/lib
case "$@" in
*openssl*) openssl ;;
*all*)
    openssl
    cdoc
    ;;
*)  cdoc ;;
esac
