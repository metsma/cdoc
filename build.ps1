#powershell -ExecutionPolicy ByPass -File build.ps1 [-openssl] [-libxml] [-cdoc]
param(
	[string]$target = "C:\build",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$cmake = "C:\Program Files (x86)\CMake\bin\cmake.exe",
	[string]$vstarget = "12",
	[string]$vsver = "$($vstarget).0",
	[string]$msbuild = "C:\Program Files (x86)\MSBuild\$vsver\Bin\MSBuild.exe",
	[string]$VSINSTALLDIR = "C:\Program Files (x86)\Microsoft Visual Studio $vsver",
	[string]$vcvars = "$VSINSTALLDIR\VC\vcvarsall.bat",
	[string]$opensslver = "openssl-1.0.2n",
	[string]$libxml2ver = "libxml2-2.9.7",
	[switch]$openssl = $false,
	[switch]$libxml2 = $false,
	[switch]$cdoc = $false
)

$source = split-path -parent $MyInvocation.MyCommand.Definition
if(!(Test-Path -Path $target)){
	New-Item -ItemType directory -Path $target > $null
}

[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$client = new-object System.Net.WebClient

function openssl() {
	Push-Location -Path $target
	$client.DownloadFile("https://www.openssl.org/source/$opensslver.tar.gz", "$target\$opensslver.tar.gz")
	& $7zip x "$opensslver.tar.gz" > $null
	& $7zip x "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86 "&&" perl Configure VC-WIN32 no-asm no-hw no-engines "&&" ms\do_ms "&&" nmake /nologo -f ms\ntdll.mak install INSTALLTOP=\OpenSSL-Win32 OPENSSLDIR=\OpenSSL-Win32\bin
	Pop-Location
	Remove-Item $opensslver -Force -Recurse

	& $7zip x "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86_amd64 "&&" perl Configure VC-WIN64A no-asm no-hw no-engines "&&" ms\do_win64a "&&" nmake /nologo -f ms\ntdll.mak install INSTALLTOP=\OpenSSL-Win64 OPENSSLDIR=\OpenSSL-Win64\bin
	Pop-Location
	Remove-Item $opensslver -Force -Recurse
	Remove-Item "$opensslver.tar"
	Pop-Location
}

function libxml2() {
	Push-Location -Path $target
	$client.DownloadFile("http://xmlsoft.org/sources/$libxml2ver.tar.gz", "$target\$libxml2ver.tar.gz")
	& $7zip x "$libxml2ver.tar.gz"
	& $7zip x "$libxml2ver.tar"
	Push-Location -Path "$libxml2ver\win32"
	& cscript configure.js iconv=no iso8859x=yes "prefix=$target\libxml2\x86"
	& $vcvars x86 "&&" nmake -f Makefile.msvc install
	Pop-Location
	Remove-Item $libxml2ver -Force -Recurse

	& $7zip x "$libxml2ver.tar"
	Push-Location -Path "$libxml2ver\win32"
	& cscript configure.js iconv=no iso8859x=yes "prefix=$target\libxml2\x64"
	& $vcvars x86_amd64 "&&" nmake -f Makefile.msvc install
	Pop-Location
	Remove-Item $libxml2ver -Force -Recurse
	Remove-Item "$libxml2ver.tar" -Force -Recurse
	Pop-Location
}

function cdoc() {
	foreach($platform in @("x86", "x64")) {
		$buildpath = $platform + "build"
		switch ($platform)
		{ 'x86' {
			$openssl = '/OpenSSL-Win32'
		} 'x64' {
			$openssl = '/OpenSSL-Win64'
		}}
		Remove-Item $buildpath -Force -Recurse > $null
		New-Item -ItemType directory -Path $buildpath > $null
		Push-Location -Path $buildpath
		& $vcvars $platform "&&" $cmake "-GNMake Makefiles" "-DCMAKE_BUILD_TYPE=RelWithDebInfo" "-DCMAKE_INSTALL_PREFIX=../$platform" "-DCMAKE_INSTALL_LIBDIR=bin" `
			"-DOPENSSL_ROOT_DIR=$openssl" `
			"-DLIBXML2_LIBRARIES=$target/libxml2/$platform/lib/libxml2.lib" `
			"-DLIBXML2_INCLUDE_DIR=$target/libxml2/$platform/include/libxml2" `
			$source "&&" nmake /nologo install
		Pop-Location
	}
}

if($openssl) {
	openssl
}
if($libxml2) {
	libxml2
}
if($cdoc) {
	cdoc
}
if(!$openssl -and !$libxml2 -and !$cdoc) {
	cdoc
}
Pop-Location
