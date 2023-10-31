@echo OFF

SET DEVELOPMENT_BUILD=1
SET APPLICATION_PORT=6969
SET REQUEST_THREAD_COUNT=8

SET CODE_PATH=..\code
SET DATA_PATH=..\data
SET BUILD_PATH=..\build

SET PACKAGE_PATH=d:\bsp\build\bsp-package
SET DEPLOYMENT_PATH=d:\inetpub\bsp

SET COMPILER_FLAGS=-nologo -Z7 -Od -FC -diagnostics:column
SET COMPILER_FLAGS=%COMPILER_FLAGS% -WX -W4 -wd4201 -wd4204 -wd4702
SET COMPILER_FLAGS=%COMPILER_FLAGS% -DAPPLICATION_PORT=%APPLICATION_PORT%
SET COMPILER_FLAGS=%COMPILER_FLAGS% -DDEVELOPMENT_BUILD=%DEVELOPMENT_BUILD%
SET COMPILER_FLAGS=%COMPILER_FLAGS% -DWORKING_DIRECTORY=%DEPLOYMENT_PATH%
SET COMPILER_FLAGS=%COMPILER_FLAGS% -DREQUEST_THREAD_COUNT=%REQUEST_THREAD_COUNT%

IF %DEVELOPMENT_BUILD%==1 (
   SET COMPILER_FLAGS=%COMPILER_FLAGS% -wd4100 -wd4101 -wd4189
)

SET LINKER_FLAGS=libfcgi.lib advapi32.lib

IF NOT EXIST %BUILD_PATH% mkdir %BUILD_PATH%
PUSHD %BUILD_PATH%

REM NOTE(law): On Windows we are left to compile fcgi for ourselves. We add the
REM requisite headers and libraries (both .lib and .dll) to the code and build
REM directories, respectively.

SET INCLUDE=%CODE_PATH%;%INCLUDE%
SET LIB=%BUILD_PATH%;%LIB%

REM NOTE(law): Compile the executable.
cl %CODE_PATH%\platform_win32.c %COMPILER_FLAGS% -Febsp /link %LINKER_FLAGS%

REM NOTE(law): Create the package directories.
IF NOT EXIST %PACKAGE_PATH%      mkdir %PACKAGE_PATH%
IF NOT EXIST %PACKAGE_PATH%\css  mkdir %PACKAGE_PATH%\css
IF NOT EXIST %PACKAGE_PATH%\html mkdir %PACKAGE_PATH%\html
IF NOT EXIST %PACKAGE_PATH%\logs mkdir %PACKAGE_PATH%\logs

REM NOTE(law) Copy executables into package.
copy %BUILD_PATH%\bsp.exe     %PACKAGE_PATH%\
copy %BUILD_PATH%\libfcgi.dll %PACKAGE_PATH%\

REM NOTE(law) Copy data assets into package.
copy %DATA_PATH%\favicon.ico  %PACKAGE_PATH%\
copy %DATA_PATH%\css\*        %PACKAGE_PATH%\css\
copy %DATA_PATH%\html\*       %PACKAGE_PATH%\html\

REM NOTE(law) Copy package to deployment directory.
rmdir /s /q %DEPLOYMENT_PATH%
move %PACKAGE_PATH% %DEPLOYMENT_PATH%

POPD
