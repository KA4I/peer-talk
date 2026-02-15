<#
.SYNOPSIS
    Cross-compiles libmsquic.so for Android from Windows.

.DESCRIPTION
    Builds MsQuic (with quictls/OpenSSL) for Android arm64 using the Android NDK.
    This is needed because System.Net.Quic.dll ships in the .NET Android runtime
    pack but Microsoft does not provide a pre-built libmsquic.so for Android.

    The script:
    1. Clones MsQuic (with submodules) if not already present
    2. Patches OpenSSL's android config and unix-checker for Windows cross-compilation
    3. Configures and builds OpenSSL (quictls) for android-arm64
    4. Patches MsQuic's CMakeLists.txt to accept pre-built OpenSSL
    5. Builds MsQuic with Ninja
    6. Copies libmsquic.so to runtimes/android-arm64/native/

.PARAMETER NdkPath
    Path to Android NDK (default: C:\DEV\android-ndk\android-ndk-r27c).
    Must be NDK r25+ with Clang toolchain.

.PARAMETER MsQuicDir
    Directory to clone/use MsQuic source (default: C:\DEV\msquic).

.PARAMETER AndroidABI
    Target ABI (default: arm64-v8a). Also supports armeabi-v7a, x86, x86_64.

.PARAMETER AndroidAPI
    Minimum Android API level (default: 29).

.EXAMPLE
    .\build-msquic-android.ps1
    .\build-msquic-android.ps1 -NdkPath "D:\android-ndk-r27c" -AndroidABI "arm64-v8a"
#>

param(
    [string]$NdkPath = "C:\DEV\android-ndk\android-ndk-r27c",
    [string]$MsQuicDir = "C:\DEV\msquic",
    [string]$AndroidABI = "arm64-v8a",
    [int]$AndroidAPI = 29
)

$ErrorActionPreference = "Stop"

# --- ABI to OpenSSL/arch mappings ---
$abiMap = @{
    "arm64-v8a"   = @{ openssl = "android-arm64"; arch = "aarch64"; rid = "android-arm64" }
    "armeabi-v7a" = @{ openssl = "android-arm";   arch = "arm";     rid = "android-arm"   }
    "x86"         = @{ openssl = "android-x86";    arch = "i686";    rid = "android-x86"   }
    "x86_64"      = @{ openssl = "android-x86_64"; arch = "x86_64";  rid = "android-x64"  }
}

if (-not $abiMap.ContainsKey($AndroidABI)) {
    throw "Unsupported AndroidABI: $AndroidABI. Supported: $($abiMap.Keys -join ', ')"
}

$abi = $abiMap[$AndroidABI]
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ScriptDir "runtimes\$($abi.rid)\native"

# --- Verify prerequisites ---
Write-Host "=== Checking prerequisites ===" -ForegroundColor Cyan

# Android NDK
if (-not (Test-Path "$NdkPath\source.properties")) {
    throw "Android NDK not found at $NdkPath. Download from https://developer.android.com/ndk/downloads"
}
Write-Host "  NDK: $NdkPath"

# Strawberry Perl (or any Windows Perl with Win32 module)
$perl = Get-Command perl -ErrorAction SilentlyContinue
if (-not $perl) {
    throw "Perl not found. Install Strawberry Perl from https://strawberryperl.com"
}
Write-Host "  Perl: $($perl.Source)"

# CMake
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    $cmake = Get-Item "C:\Program Files\CMake\bin\cmake.exe" -ErrorAction SilentlyContinue
    if (-not $cmake) {
        throw "CMake not found. Install from https://cmake.org/download/"
    }
}
$cmakePath = if ($cmake.Source) { $cmake.Source } else { $cmake.FullName }
Write-Host "  CMake: $cmakePath"

# Ninja
$ninja = Get-Command ninja -ErrorAction SilentlyContinue
if (-not $ninja) {
    # Check common locations
    $ninjaLocations = @(
        "C:\DEV\vcpkg\downloads\tools\ninja\*\ninja.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\*\ninja.exe"
    )
    foreach ($loc in $ninjaLocations) {
        $found = Get-Item $loc -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ninja = $found; break }
    }
    if (-not $ninja) {
        throw "Ninja not found. Install via: winget install Ninja-build.Ninja"
    }
}
$ninjaPath = if ($ninja.Source) { $ninja.Source } else { $ninja.FullName }
Write-Host "  Ninja: $ninjaPath"

# NDK make (used for OpenSSL build)
$ndkPrebuilt = "$NdkPath\toolchains\llvm\prebuilt\windows-x86_64"
$ndkMake = "$NdkPath\prebuilt\windows-x86_64\bin\make.exe"
if (-not (Test-Path $ndkMake)) {
    throw "NDK make not found at $ndkMake"
}

# Git (for MSYS commands like sh.exe used by make)
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    throw "Git not found. Required for MSYS shell utilities."
}
$gitDir = Split-Path (Split-Path $git.Source)
$gitUsrBin = Join-Path $gitDir "usr\bin"
Write-Host "  Git usr/bin: $gitUsrBin"

# --- Step 1: Clone MsQuic ---
Write-Host "`n=== Step 1: MsQuic source ===" -ForegroundColor Cyan
if (-not (Test-Path "$MsQuicDir\CMakeLists.txt")) {
    Write-Host "  Cloning MsQuic..."
    git clone --recurse-submodules --depth 1 https://github.com/microsoft/msquic.git $MsQuicDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone MsQuic" }
} else {
    Write-Host "  Using existing MsQuic at $MsQuicDir"
}

# --- Step 2: Patch OpenSSL for Windows cross-compilation ---
Write-Host "`n=== Step 2: Patching OpenSSL for Windows cross-compile ===" -ForegroundColor Cyan

$androidConf = "$MsQuicDir\submodules\quictls\Configurations\15-android.conf"
$unixChecker = "$MsQuicDir\submodules\quictls\Configurations\unix-checker.pm"

# Patch 15-android.conf: normalize paths for Windows Perl
$confContent = Get-Content $androidConf -Raw
$patchMarker = '# [PATCHED] Windows cross-compile path normalization'

if ($confContent -notmatch [regex]::Escape($patchMarker)) {
    Write-Host "  Patching 15-android.conf..."

    # 1. After canonpath($ndk), add path normalization
    $confContent = $confContent -replace '(\$ndk = canonpath\(\$ndk\);)',
        "`$1`n            $patchMarker`n            `$ndk =~ s|\\\\|/|g;  # normalize to forward slashes on Windows`n            `$ndk =~ s|^[A-Za-z]:/|/|;  # strip drive letter for consistent matching"

    # 2. After which("clang"), add Win32::GetLongPathName for 8.3 paths
    $confContent = $confContent -replace '(my \$clang_path = which\("clang"\);)',
        "`$1`n            if (`$^O eq 'MSWin32' && defined &Win32::GetLongPathName) {`n                `$clang_path = Win32::GetLongPathName(`$clang_path) // `$clang_path;`n            }`n            `$clang_path =~ s|\\\\|/|g;`n            `$clang_path =~ s|^[A-Za-z]:/|/|;"

    # 3. Add llvm-ar fallback when path matching fails on Windows
    $arFallback = @'
                } else {
                    # Fallback: if llvm-ar is on PATH but path matching fails (Windows)
                    my $ar_path = which("llvm-ar");
                    if ($ar_path) {
                        $user{AR} = "llvm-ar";
                        $user{ARFLAGS} = [ "rs" ];
                        $user{RANLIB} = ":";
                    }
                }
'@
    # Only add fallback if not already present
    if ($confContent -notmatch 'Fallback: if llvm-ar is on PATH') {
        # This regex finds the closing brace of the llvm-ar if block and adds the fallback
        $confContent = $confContent -replace '(\s+\$user\{AR\} = "llvm-ar";\s+\$user\{ARFLAGS\} = \[ "rs" \];\s+\$user\{RANLIB\} = ":";\s+\})',
            "`$1$arFallback"
    }

    Set-Content $androidConf $confContent -NoNewline
    Write-Host "  Patched 15-android.conf"
} else {
    Write-Host "  15-android.conf already patched"
}

# Patch unix-checker.pm: skip Unix path check for cross-compilation
$checkerContent = Get-Content $unixChecker -Raw
if ($checkerContent -notmatch 'ANDROID_NDK_ROOT') {
    Write-Host "  Patching unix-checker.pm..."
    $checkerContent = $checkerContent -replace "(use File::Spec::Functions qw\(:DEFAULT rel2abs\);)",
        @"
`$1

# When cross-compiling from Windows to Android, rel2abs produces backslash
# paths even though the target is Unix. Skip the check in this case.
if (`$ENV{ANDROID_NDK_ROOT} || `$ENV{CROSS_COMPILE}) {
    # cross-compiling, skip Unix path check
} els
"@
    # Change the original 'if' to 'elsif' (the 'els' above joins with the existing 'if')
    # Actually let's do a cleaner replacement
    $checkerContent = Get-Content $unixChecker -Raw
    $checkerContent = $checkerContent -replace '(use File::Spec::Functions qw\(:DEFAULT rel2abs\);)\s*\n\s*(if \(rel2abs)',
        @"
`$1

# When cross-compiling from Windows to Android, skip Unix path check
if (`$ENV{ANDROID_NDK_ROOT} || `$ENV{CROSS_COMPILE}) {
    # cross-compiling, skip Unix path check
} els`$2
"@
    Set-Content $unixChecker $checkerContent -NoNewline
    Write-Host "  Patched unix-checker.pm"
} else {
    Write-Host "  unix-checker.pm already patched"
}

# --- Step 3: Build OpenSSL for Android ---
Write-Host "`n=== Step 3: Building OpenSSL ($($abi.openssl)) ===" -ForegroundColor Cyan

$opensslBuildDir = "$MsQuicDir\openssl-$($abi.rid)"
$opensslInstallDir = "$opensslBuildDir\install"

if (Test-Path "$opensslInstallDir\lib\libssl.a") {
    Write-Host "  OpenSSL already built at $opensslInstallDir"
} else {
    # Create build directory
    New-Item -ItemType Directory -Force $opensslBuildDir | Out-Null
    Push-Location $opensslBuildDir

    try {
        # Set up environment
        $env:ANDROID_NDK_ROOT = $NdkPath
        $ndkBinPath = "$ndkPrebuilt\bin"

        # Save original PATH and prepend NDK tools + Git usr/bin
        $origPath = $env:PATH
        $env:PATH = "$ndkBinPath;$gitUsrBin;$env:PATH"

        Write-Host "  Configuring OpenSSL..."
        & perl "$MsQuicDir\submodules\quictls\Configure" `
            $($abi.openssl) `
            "-D__ANDROID_API__=$AndroidAPI" `
            --prefix="$opensslInstallDir" `
            --openssldir=/usr/local/ssl `
            enable-tls1_3 no-makedepend no-dgram no-ssl3 no-psk no-srp `
            no-zlib no-egd no-idea no-rc5 no-rc4 no-afalgeng `
            no-comp no-cms no-ct no-srtp no-ts no-gost no-dso no-ec2m `
            no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 no-ssl `
            no-ssl3-method no-tls1-method no-tls1_1-method no-tls1_2-method `
            no-dtls1-method no-dtls1_2-method `
            no-siphash no-whirlpool no-aria no-bf no-blake2 no-sm2 no-sm3 no-sm4 `
            no-camellia no-cast no-md4 no-mdc2 no-ocb no-rc2 no-rmd160 `
            no-scrypt no-seed no-weak-ssl-ciphers no-shared no-tests `
            no-uplink no-cmp no-fips no-padlockeng no-siv no-legacy no-deprecated `
            --libdir=lib 2>&1

        if ($LASTEXITCODE -ne 0) { throw "OpenSSL Configure failed" }

        # Post-process Makefile: convert backslashes to forward slashes
        # NDK make uses sh.exe which eats backslashes
        Write-Host "  Post-processing Makefile (backslash to forward slash)..."
        $makefile = Get-Content "$opensslBuildDir\Makefile" -Raw
        $makefile = $makefile -replace '\\(?=[a-zA-Z0-9_\.])', '/'
        Set-Content "$opensslBuildDir\Makefile" $makefile -NoNewline

        Write-Host "  Building OpenSSL (install_dev)..."
        $perlExe = (Get-Command perl).Source -replace '\\', '/'
        # Use -j1 on Windows to avoid race conditions with generated headers
        & $ndkMake "PERL=$perlExe" install_dev -j1 2>&1

        if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }

        # Verify output
        if (-not (Test-Path "$opensslInstallDir\lib\libssl.a")) {
            throw "OpenSSL build completed but libssl.a not found"
        }
        if (-not (Test-Path "$opensslInstallDir\lib\libcrypto.a")) {
            throw "OpenSSL build completed but libcrypto.a not found"
        }

        $sslSize = (Get-Item "$opensslInstallDir\lib\libssl.a").Length
        $cryptoSize = (Get-Item "$opensslInstallDir\lib\libcrypto.a").Length
        Write-Host "  OpenSSL built: libssl.a ($sslSize bytes), libcrypto.a ($cryptoSize bytes)" -ForegroundColor Green

    } finally {
        $env:PATH = $origPath
        Pop-Location
    }
}

# --- Step 4: Patch MsQuic CMakeLists.txt for pre-built OpenSSL ---
Write-Host "`n=== Step 4: Patching MsQuic CMakeLists.txt ===" -ForegroundColor Cyan

$cmakeLists = "$MsQuicDir\submodules\CMakeLists.txt"
$cmakeContent = Get-Content $cmakeLists -Raw

if ($cmakeContent -notmatch 'QUIC_OPENSSL_PREBUILT_DIR') {
    Write-Host "  Adding QUIC_OPENSSL_PREBUILT_DIR support..."

    # Insert pre-built OpenSSL block before the original build logic
    $prebuiltBlock = @'
set(QUIC_OPENSSL_PREBUILT_DIR "" CACHE PATH "Path to pre-built OpenSSL install directory (skips internal build)")

if (QUIC_OPENSSL_PREBUILT_DIR)
    message(STATUS "Using pre-built OpenSSL from: ${QUIC_OPENSSL_PREBUILT_DIR}")
    set(OPENSSL_DIR ${QUIC_OPENSSL_PREBUILT_DIR})
    set(LIBSSL_PATH ${OPENSSL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBCRYPTO_PATH ${OPENSSL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})

    add_custom_target(OpenSSL_Target)
    set_property(TARGET OpenSSL_Target PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}helpers")

    add_library(OpenSSLQuic INTERFACE)
    add_dependencies(OpenSSLQuic OpenSSL_Target)
    target_include_directories(OpenSSLQuic INTERFACE
        $<BUILD_INTERFACE:${OPENSSL_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    if (QUIC_USE_SYSTEM_LIBCRYPTO)
        include(FindOpenSSL)
        if (OPENSSL_FOUND)
            target_link_libraries(OpenSSLQuic INTERFACE OpenSSL::Crypto)
        else()
            target_link_libraries(OpenSSLQuic INTERFACE ${LIBCRYPTO_PATH})
        endif()
    else()
        target_link_libraries(OpenSSLQuic INTERFACE ${LIBCRYPTO_PATH})
    endif()
    target_link_libraries(OpenSSLQuic INTERFACE ${LIBSSL_PATH})
    add_library(OpenSSLQuic::OpenSSLQuic ALIAS OpenSSLQuic)

else()

'@
    $cmakeContent = $cmakeContent -replace [regex]::Escape('set(OPENSSL_DIR ${QUIC_BUILD_DIR}/${QUIC_OPENSSL})'),
        "set(OPENSSL_DIR `${QUIC_BUILD_DIR}/`${QUIC_OPENSSL})`n$prebuiltBlock"

    # Close the outer if/else at the end (add endif after the last endif)
    # The file ends with: add_library(OpenSSLQuic::OpenSSLQuic ALIAS OpenSSLQuic)\n\nendif()
    $cmakeContent = $cmakeContent -replace '(add_library\(OpenSSLQuic::OpenSSLQuic ALIAS OpenSSLQuic\)\s*\n\s*endif\(\))\s*$',
        "`$1`n`nendif() # if(QUIC_OPENSSL_PREBUILT_DIR)`n"

    Set-Content $cmakeLists $cmakeContent -NoNewline
    Write-Host "  Patched CMakeLists.txt"
} else {
    Write-Host "  CMakeLists.txt already patched"
}

# Also patch SYSTEM= env var syntax for Windows (if not already done)
$cmakeContent = Get-Content $cmakeLists -Raw
if ($cmakeContent -match 'COMMAND SYSTEM=\$\{CMAKE_HOST_SYSTEM_NAME\}' -and
    $cmakeContent -notmatch 'COMMAND \$\{CMAKE_COMMAND\} -E env SYSTEM=') {
    Write-Host "  Fixing SYSTEM= env var for Windows..."
    $cmakeContent = $cmakeContent -replace 'COMMAND SYSTEM=\$\{CMAKE_HOST_SYSTEM_NAME\}',
        'COMMAND ${CMAKE_COMMAND} -E env SYSTEM=${CMAKE_HOST_SYSTEM_NAME}'
    Set-Content $cmakeLists $cmakeContent -NoNewline
}

# --- Step 5: Configure and build MsQuic ---
Write-Host "`n=== Step 5: Building MsQuic ===" -ForegroundColor Cyan

$msquicBuildDir = "$MsQuicDir\build-$($abi.rid)"
$opensslInstallUnix = $opensslInstallDir -replace '\\', '/'

Push-Location $MsQuicDir
try {
    Write-Host "  Configuring MsQuic..."
    & $cmakePath -B $msquicBuildDir `
        -G Ninja `
        -DCMAKE_MAKE_PROGRAM="$ninjaPath" `
        -DCMAKE_TOOLCHAIN_FILE="$NdkPath\build\cmake\android.toolchain.cmake" `
        -DANDROID_ABI=$AndroidABI `
        -DANDROID_PLATFORM="android-$AndroidAPI" `
        -DCMAKE_BUILD_TYPE=Release `
        -DQUIC_TLS_LIB=quictls `
        "-DQUIC_OPENSSL_PREBUILT_DIR=$opensslInstallUnix" `
        -DQUIC_BUILD_SHARED=ON `
        -DQUIC_ENABLE_LOGGING=OFF `
        -DQUIC_BUILD_TOOLS=OFF `
        -DQUIC_BUILD_TEST=OFF `
        -DQUIC_BUILD_PERF=OFF 2>&1

    if ($LASTEXITCODE -ne 0) { throw "MsQuic CMake configure failed" }

    Write-Host "  Building MsQuic..."
    & $cmakePath --build $msquicBuildDir --config Release 2>&1

    if ($LASTEXITCODE -ne 0) { throw "MsQuic build failed" }
} finally {
    Pop-Location
}

# --- Step 6: Copy output ---
Write-Host "`n=== Step 6: Copying libmsquic.so ===" -ForegroundColor Cyan

$soPath = "$msquicBuildDir\bin\Release\libmsquic.so"
if (-not (Test-Path $soPath)) {
    throw "Build succeeded but libmsquic.so not found at $soPath"
}

New-Item -ItemType Directory -Force $OutputDir | Out-Null
Copy-Item $soPath "$OutputDir\libmsquic.so" -Force

$soSize = (Get-Item "$OutputDir\libmsquic.so").Length

# Verify architecture
$objdump = "$ndkPrebuilt\bin\llvm-objdump.exe"
if (Test-Path $objdump) {
    $archInfo = & $objdump -f "$OutputDir\libmsquic.so" 2>&1
    Write-Host "  $archInfo"
}

Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "  libmsquic.so ($soSize bytes) -> $OutputDir"
Write-Host "  Include in .csproj:" -ForegroundColor Yellow
Write-Host @"
  <ItemGroup>
    <Content Include="runtimes\$($abi.rid)\native\libmsquic.so" Pack="true" PackagePath="runtimes\$($abi.rid)\native">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </Content>
  </ItemGroup>
"@
