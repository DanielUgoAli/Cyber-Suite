@echo off
echo Cyber-Suite Installer
echo =====================

echo Checking for Git...
where git >nul 2>&1
if %errorLevel% neq 0 (
    echo Git is not installed or not in PATH.
    echo Please install Git from https://git-scm.com/downloads
    pause
    exit /b 1
)

echo Checking for Python...
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Set installation directory
set INSTALL_DIR="%APPDATA%\Cyber-Suite"

REM Create installation directory if it doesn't exist
if not exist %INSTALL_DIR% mkdir %INSTALL_DIR%

echo Installing Cyber-Suite to %INSTALL_DIR%...

REM Clone repository
echo Cloning repository...
git clone https://github.com/DanielUgoAli/Cyber-Suite.git %INSTALL_DIR%
if %errorLevel% neq 0 (
    echo Failed to clone repository.
    pause
    exit /b 1
)

REM Install requirements
echo Installing Python requirements...
cd /d %INSTALL_DIR%
python -m pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo Warning: Failed to install some requirements.
    echo You may need to install them manually.
)

REM Create desktop shortcut
echo Creating desktop shortcut...
set SHORTCUT_PATH="%USERPROFILE%\Desktop\Cyber-Suite.lnk"
echo Set oWS = WScript.CreateObject("WScript.Shell") > "%TEMP%\CreateShortcut.vbs"
echo sLinkFile = %SHORTCUT_PATH% >> "%TEMP%\CreateShortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%TEMP%\CreateShortcut.vbs"
echo oLink.TargetPath = "%INSTALL_DIR%\CyberSuite.bat" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.WorkingDirectory = %INSTALL_DIR% >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Description = "Cyber-Suite" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.IconLocation = "powershell.exe,0" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Save >> "%TEMP%\CreateShortcut.vbs"
cscript //NoLogo "%TEMP%\CreateShortcut.vbs"
del "%TEMP%\CreateShortcut.vbs"

REM Create Start Menu shortcut
echo Creating Start Menu shortcut...
set STARTMENU_PATH="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Cyber-Suite.lnk"
echo Set oWS = WScript.CreateObject("WScript.Shell") > "%TEMP%\CreateStartShortcut.vbs"
echo sLinkFile = %STARTMENU_PATH% >> "%TEMP%\CreateStartShortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%TEMP%\CreateStartShortcut.vbs"
echo oLink.TargetPath = "%INSTALL_DIR%\CyberSuite.bat" >> "%TEMP%\CreateStartShortcut.vbs"
echo oLink.WorkingDirectory = %INSTALL_DIR% >> "%TEMP%\CreateStartShortcut.vbs"
echo oLink.Description = "Cyber-Suite" >> "%TEMP%\CreateStartShortcut.vbs"
echo oLink.IconLocation = "powershell.exe,0" >> "%TEMP%\CreateStartShortcut.vbs"
echo oLink.Save >> "%TEMP%\CreateStartShortcut.vbs"
cscript //NoLogo "%TEMP%\CreateStartShortcut.vbs"
del "%TEMP%\CreateStartShortcut.vbs"

REM Create a CyberSuite.bat file to launch the GUI
echo Creating CyberSuite.bat launch file...
echo @echo off > "%INSTALL_DIR%\CyberSuite.bat"
echo cd /d "%INSTALL_DIR%" >> "%INSTALL_DIR%\CyberSuite.bat"
echo python gui.py >> "%INSTALL_DIR%\CyberSuite.bat"
echo pause >> "%INSTALL_DIR%\CyberSuite.bat"

echo.
echo Installation completed successfully!
echo Cyber-Suite has been installed to %INSTALL_DIR%
echo Shortcuts have been created on your Desktop and in the Start Menu.
echo.
pause
