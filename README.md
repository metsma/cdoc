# cdoc

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://metsma.github.io)

## Building
[![Build Status](https://travis-ci.org/metsma/cdoc.svg?branch=master)](https://travis-ci.org/metsma/cdoc)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/metsma/cdoc?branch=master&svg=true)](https://ci.appveyor.com/project/metsma/cdoc)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake libxml2-dev libssl-dev doxygen

2. Fetch the source

        git clone https://github.com/metsma/cdoc
        cd cdoc

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/cdoc-tool

### OSX

1. Install dependencies from
	* [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)
	* [http://www.cmake.org](http://www.cmake.org)
	* [https://brew.sh](https://brew.sh)

2. Fetch the source

        git clone https://github.com/metsma/cdoc
        cd cdoc

3. Prepare

        brew install openssl

4. Configure

        mkdir build
        cd build
        cmake ..

5. Build

        make

6. Install

        sudo make install

7. Execute

        /Library/Frameworks/cdoc.framework/Versions/0/Resources/cdoc-tool

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Community 2015](https://www.visualstudio.com/downloads/)
	* [Perl](https://www.perl.org/get.html)
	* [7-zip](http://www.7-zip.org)
	* [http://www.cmake.org](http://www.cmake.org) - NB! Build scripts use 32-bit version of CMake
	* [swigwin-3.0.12.zip](http://swig.org/download.html) - Optional, for C# bindings
	* [Wix toolset](http://wixtoolset.org/releases/) - Optional, for creating Windows installation packages

2. Fetch the source

        git clone --recursive https://github.com/metsma/cdoc
        cd cdoc

3. Prepare

        powershell -ExecutionPolicy ByPass -File build.ps1

4. Configure

        mkdir build
        cd build
        cmake ..

   Optional CMake parameters:

       -DSWIG_EXECUTABLE=C:/swigwin-3.0.12/swig.exe

   After running the cmake build, cdoc_csharp.dll along with the C# source files will be created.

5. Build

        nmake

6. Alternative to steps 4. and 5. -

        Run the build script in PowerShell:
        ./build.ps1 -openssl -libxml2 -cdoc

    The build script builds executables and installation media for all
    platforms (x86 and x64 / Debug and Release with debug symbols)

7. Execute

        cdoc-tool.exe

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact for assistance by email [abi@id.ee](mailto:abi@id.ee) or [www.id.ee](http://www.id.ee).

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
