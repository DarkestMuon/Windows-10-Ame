:: Windows 10 AME BATCH Script
:: v2004.2021.04.03

@echo off
pushd "%~dp0"

echo.
echo  :: Checking For Administrator Elevation...
echo.
timeout /t 1 /nobreak > NUL
openfiles > NUL 2>&1
if %errorlevel%==0 (
        echo Elevation found! Proceeding...
) else (
        echo  :: You are NOT running as Administrator
        echo.
        echo     Right-click and select ^'Run as Administrator^' and try again.
        echo     Press any key to exit...
        pause > NUL
        exit
)

goto menu

:menu
cls
echo.
echo  :: WINDOWS 10 AME SETUP SCRIPT Version 2021.04.03
echo. 
echo     This script gives you a list-style overview to execute many commands
echo. 
echo  :: NOTE: For Windows 10 Build 20H2 Only
echo. 
echo     1. Run Pre-Amelioration
echo     2. Run Post-Amelioration
echo     3. User Permissions
echo     4. Set AME Wallpaper
echo     5. Restart System
echo. 
echo  :: Type a 'number' and press ENTER
echo  :: Type 'exit' to quit
echo.

set /P menu=
	if %menu%==1 GOTO preame
	if %menu%==2 GOTO programs
	if %menu%==3 GOTO user
	if %menu%==4 GOTO wallpaper		
	if %menu%==5 GOTO reboot
	if %menu%==exit GOTO EOF
else (
	cls
	echo.
	echo  :: Incorrect Input Entered
	echo.
	echo     Please type a 'number' or 'exit'
	echo     Press any key to retrn to the menu...
	echo.
	pause > NUL
	goto menu
)
		
:preame
cls
:: DotNet 3.5 Installation from install media
cls
echo.
echo  :: Installing .NET 3.5 for Windows 10
echo.
echo     Windows 10 normally opts to download this runtime via Windows Update.
echo     However, it can be installed with the original installation media.
echo     .NET 3.5 is necessary for certain programs and games to function.
echo.
echo  :: Please mount the Windows 10 installation media and specify a drive letter.
echo.
echo  :: Type a 'drive letter' e.g. D: and press ENTER
echo  :: Type 'exit' to return to the menu
echo.
set /P drive=
if %drive%==exit GOTO menu
	dism /online /enable-feature /featurename:NetFX3 /All /Source:%drive%\sources\sxs /LimitAccess

cls
echo.
echo  :: Disabling Windows Update
timeout /t 2 /nobreak > NUL
net stop wuauserv
sc config wuauserv start= disabled

cls
echo.
echo  :: Disabling Data Logging Services
timeout /t 2 /nobreak > NUL
taskkill /f /im explorer.exe

:: Disabling Tracking Services and Data Collection
cls
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1

:: Disable and Delete Tasks
cls
schtasks /change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE > NUL 2>&1
cls
schtasks /change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE > NUL 2>&1
cls
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE > NUL 2>&1
cls
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE > NUL 2>&1
cls
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Clip\License Validation" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Maps\MapsToastTask" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /f > NUL 2>&1
cls
schtasks /delete /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /f > NUL 2>&1
cls

:: Add Task to restrict administrator login and display a message to the user when logging into the desktop with the administrator account
SetLocal EnableDelayedExpansion
(
echo ^<?xml version="1.0" encoding="UTF-16"?^>
echo ^<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"^>
echo   ^<RegistrationInfo^>
echo     ^<Date^>2021-02-10T19:24:15.5621439^</Date^>
echo     ^<Author^>WINDOWS-PC\Administrator^</Author^>
echo     ^<URI^>\Log-off admin user^</URI^>
echo   ^</RegistrationInfo^>
echo   ^<Triggers^>
echo     ^<LogonTrigger^>
echo       ^<Enabled^>true^</Enabled^>
echo       ^<UserId^>WINDOWS-PC\Administrator^</UserId^>
echo     ^</LogonTrigger^>
echo   ^</Triggers^>
echo   ^<Principals^>
echo     ^<Principal id="Author"^>
echo       ^<UserId^>System^</UserId^>
echo       ^<LogonType^>InteractiveToken^</LogonType^>
echo       ^<RunLevel^>LeastPrivilege^</RunLevel^>
echo     ^</Principal^>
echo   ^</Principals^>
echo   ^<Settings^>
echo     ^<MultipleInstancesPolicy^>IgnoreNew^</MultipleInstancesPolicy^>
echo     ^<DisallowStartIfOnBatteries^>true^</DisallowStartIfOnBatteries^>
echo     ^<StopIfGoingOnBatteries^>true^</StopIfGoingOnBatteries^>
echo     ^<AllowHardTerminate^>true^</AllowHardTerminate^>
echo     ^<StartWhenAvailable^>false^</StartWhenAvailable^>
echo     ^<RunOnlyIfNetworkAvailable^>false^</RunOnlyIfNetworkAvailable^>
echo     ^<IdleSettings^>
echo       ^<StopOnIdleEnd^>true^</StopOnIdleEnd^>
echo       ^<RestartOnIdle^>false^</RestartOnIdle^>
echo     ^</IdleSettings^>
echo     ^<AllowStartOnDemand^>true^</AllowStartOnDemand^>
echo     ^<Enabled^>true^</Enabled^>
echo     ^<Hidden^>false^</Hidden^>
echo     ^<RunOnlyIfIdle^>false^</RunOnlyIfIdle^>
echo     ^<WakeToRun^>false^</WakeToRun^>
echo     ^<ExecutionTimeLimit^>PT72H^</ExecutionTimeLimit^>
echo     ^<Priority^>7^</Priority^>
echo   ^</Settings^>
echo   ^<Actions Context="Author"^>
echo     ^<Exec^>
echo       ^<Command^>cmd.exe^</Command^>
echo       ^<Arguments^>/c c:\windows\system32\logoff.exe^</Arguments^>
echo     ^</Exec^>
echo   ^</Actions^>
echo ^</Task^>
)>> C:\AME-Log-off-admin.xml

SetLocal EnableDelayedExpansion
(
echo ^<?xml version="1.0" encoding="UTF-16"?^>
echo ^<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"^>
echo  ^<RegistrationInfo^>
echo    ^<Date^>2021-02-10T20:04:12.7491874^</Date^>
echo    ^<Author^>WINDOWS-PC\Administrator^</Author^>
echo    ^<URI^>\Log-off admin message^</URI^>
echo  ^</RegistrationInfo^>
echo  ^<Triggers^>
echo    ^<LogonTrigger^>
echo      ^<Enabled^>true^</Enabled^>
echo      ^<UserId^>WINDOWS-PC\Administrator^</UserId^>
echo    ^</LogonTrigger^>
echo  ^</Triggers^>
echo  ^<Principals^>
echo    ^<Principal id="Author"^>
echo      ^<UserId^>System^</UserId^>
echo      ^<RunLevel^>HighestAvailable^</RunLevel^>
echo    ^</Principal^>
echo  ^</Principals^>
echo  ^<Settings^>
echo    ^<MultipleInstancesPolicy^>IgnoreNew^</MultipleInstancesPolicy^>
echo    ^<DisallowStartIfOnBatteries^>true^</DisallowStartIfOnBatteries^>
echo    ^<StopIfGoingOnBatteries^>true^</StopIfGoingOnBatteries^>
echo    ^<AllowHardTerminate^>true^</AllowHardTerminate^>
echo    ^<StartWhenAvailable^>false^</StartWhenAvailable^>
echo    ^<RunOnlyIfNetworkAvailable^>false^</RunOnlyIfNetworkAvailable^>
echo    ^<IdleSettings^>
echo      ^<StopOnIdleEnd^>true^</StopOnIdleEnd^>
echo      ^<RestartOnIdle^>false^</RestartOnIdle^>
echo    ^</IdleSettings^>
echo    ^<AllowStartOnDemand^>true^</AllowStartOnDemand^>
echo    ^<Enabled^>true^</Enabled^>
echo    ^<Hidden^>false^</Hidden^>
echo    ^<RunOnlyIfIdle^>false^</RunOnlyIfIdle^>
echo    ^<DisallowStartOnRemoteAppSession^>false^</DisallowStartOnRemoteAppSession^>
echo    ^<UseUnifiedSchedulingEngine^>true^</UseUnifiedSchedulingEngine^>
echo    ^<WakeToRun^>false^</WakeToRun^>
echo    ^<ExecutionTimeLimit^>PT72H^</ExecutionTimeLimit^>
echo    ^<Priority^>7^</Priority^>
echo  ^</Settings^>
echo  ^<Actions Context="Author"^>
echo    ^<Exec^>
echo      ^<Command^>powershell.exe^</Command^>
echo      ^<Arguments^>Write-Output  'Logging in as the Administrator user is not supported on AME.' 'Please login using a different account.' ^| Msg *^</Arguments^>
echo    ^</Exec^>
echo  ^</Actions^>
echo ^</Task^>
)>> C:\AME-Log-off-admin-message.xml

schtasks /create /xml C:\AME-Log-off-admin.xml /tn "AME Log-off admin" /ru administrator /it
schtasks /create /xml C:\AME-Log-off-admin-message.xml /tn "AME Log-off admin message" /ru administrator /it

:: Registry Edits
cls
echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DownloadMode /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v UseActionCenterExperience /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 0x1 /f > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f > NUL 2>&1

:: Remove SecurityHealth from startup
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f


:: Turns off Windows blocking installation of files downloaded from the internet
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f > NUL 2>&1

:: Disables SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v ContentEvaluation /t REG_DWORD /d 0 /f > NUL 2>&1

:: Remove Metadata Tracking
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f > NUL 2>&1

:: New Control Panel cleanup - List of commands: https://winaero.com/ms-settings-commands-in-windows-10/
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "showonly:display;nightlight;sound;notifications;quiethours;powersleep;batterysaver;tabletmode;multitasking;clipboard;remote-desktop;about;bluetooth;connecteddevices;printers;mousetouchpad;devices-touchpad;typing;pen;autoplay;usb;network-status;network-cellular;network-wifi;network-wificalling;network-wifisettings;network-ethernet;network-dialup;network-vpn;network-airplanemode;network-mobilehotspot;datausage;network-proxy;personalization-background;personalization-start;fonts;colors;lockscreen;themes;taskbar;defaultapps;videoplayback;startupapps;dateandtime;regionformatting;gaming;gamemode;easeofaccess-display;easeofaccess-colorfilter;easeofaccess-audio;easeofaccess-easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-speechrecognition;easeofaccess-eyecontrol;easeofaccess-keyboard;easeofaccess-mouse;cortana-windowssearch;search-moredetails" /f > NUL 2>&1

:: Decrease shutdown time
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeOut /t REG_SZ /d 2000 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v HungAppTimeout /t REG_SZ /d 2000 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v AutoEndTasks /t REG_SZ /d 1 /f > NUL 2>&1

:: Disabling And Stopping Services
cls
sc config diagtrack start= disabled
cls
sc config RetailDemo start= disabled
cls
sc config diagnosticshub.standardcollector.service start= disabled
cls
sc config DiagTrack start= disabled
cls
sc config dmwappushservice start= disabled
cls
sc config HomeGroupListener start= disabled
cls
sc config HomeGroupProvider start= disabled
cls
sc config lfsvc start= disabled
cls
sc config MapsBroker start= disabled
cls
sc config NetTcpPortSharing start= disabled
cls
sc config RemoteAccess start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config SharedAccess start= disabled
cls
sc config StorSvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config WbioSrvc start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config wscsvc start= disabled
cls
sc config XblAuthManager start= disabled
cls
sc config XblGameSave start= disabled
cls
sc config XboxNetApiSvc start= disabled
cls
net stop wlidsvc
sc config wlidsvc start= disabled
cls
:: Disable SMBv1. Effectively mitigates EternalBlue, popularly known as WannaCry.
PowerShell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
sc config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc config mrxsmb10 start= disabled

:: Cleaning up the This PC Icon Selection
cls
echo.
echo  :: Removing all Folders from MyPC
timeout /t 2 /nobreak
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f > NUL 2>&1

:: Disabling Storage Sense
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense" /f > NUL 2>&1

:: Disabling Cortana and Removing Search Icon from Taskbar
cls
echo.
echo  :: Disabling Cortana
timeout /t 2 /nobreak
taskkill /f /im SearchUI.exe

cls
echo.
echo  :: Fixing Search
timeout /t 2 /nobreak
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD 0 /f  > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "HasAboveLockTips" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d 1 /f > NUL 2>&1
:: Batch magic to search for the current user SID and disable the web search in the stock start menu, this is the equivalent of enabling some group policy that does the same thing, will need to keep in mind if new users are to be added as they will also need this registry entry.
:: This bit here sends the output of a command to a variable
:: There is the assumption that the account the script is being run with has admin privileges, it will otherwise not work. If following the official documentation then it works fine.
for /f "tokens=* USEBACKQ" %%i in (`wmic useraccount where "name="%username%"" get sid ^| findstr "S-"`) do set currentusername=%%i
:: Trim 3 empty spaces off the end of the returned string
set currentusername=%currentusername:~0,-3%
reg add "HKEY_USERS\%currentusername%\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f > NUL 2>&1
:: Firewall rules to prevent the startmenu from talking
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block Search SearchApp.exe" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe|Name=Block Search SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" /f > NUL 2>&1
::reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block Search Package" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Search Package|Desc=Block Search Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757|Platform=2:6:2|Platform2=GTEQ|" /f > NUL 2>&1

:: Disable Timeline
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f > NUL 2>&1

:: Fixing Windows Explorer
cls
echo.
echo  :: Setup Windows Explorer
timeout /t 2 /nobreak
:: Removes the shake to minimze all other windows gesture
::reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\CABFolder\CLSID" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.cab\CLSID" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\CompressedFolder\CLSID" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.zip\CLSID" /f > NUL 2>&1

:: Remove the Open with Paint 3D from the explorer context menu
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" /f > NUL 2>&1

:: Clear PageFile at shutdown and ActiveProbing, commented out due to long shutdown time
::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /t REG_DWORD /d 0 /f > NUL 2>&1

:: Set Time to UTC
reg add "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f > NUL 2>&1

::Disable Users On Login Screen
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f > NUL 2>&1

::Disable The Lock Screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f > NUL 2>&1


:: Removing AppXPackages, the ModernUI Apps, including Cortana
:: Unprovision built in apps, the list in this command is a whitelist, all other apps are removed
Powershell -Command "& { Get-AppxProvisionedPackage -Online | Where-Object { -Not (Select-String -SimpleMatch -Quiet -InputObject $_.PackageName -Pattern (@('Microsoft.Windows.StartMenuExperienceHost*', 'Microsoft.Windows.ShellExperienceHost*', '*windows.immersivecontrolpanel*', '*Windows.Search*' ,'*Microsoft.549981C3F5F10*', '*Microsoft.VCLibs*', '*Microsoft.NET*', '*Microsoft.DesktopAppInstaller*', '*Microsoft.UI*', '*Microsoft.Windows.CapturePicker*', '*Windows.PrintDialog*', '*Windows.CBSPreview*', '*NcsiUwpApp*', '*Microsoft.Windows.XGpuEjectDialog*', '*Microsoft.Win32WebViewHost*', '*Microsoft.Windows.Apprep.ChxApp*', '*1527c705-839a-4832-9118-54d4Bd6a0c89*', '*c5e2524a-ea46-4f67-841f-6a9465d9d515*', '*E2A4F912-2574-4A75-9BB0-0D023378592B*', '*F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE*', '*Microsoft.AccountsControl*', '*Microsoft.Windows.ParentalControls*', '*Microsoft.LockApp*', '*Microsoft.CredDialogHost*', '*Microsoft.WebpImageExtension*', '*Microsoft.WebMediaExtensions_1.0.20875.0_x64__8wekyb3d8bbwe*', '*Microsoft.VP9VideoExtensions*', '*Microsoft.ScreenSketch*', '*Microsoft.HEIFImageExtension*')) | Sort-Object | Get-Unique) } | Remove-AppxProvisionedPackage -Online }"
call :title_remove_appx_packages
:: Remove Cortana from all users
PowerShell -Command "Get-AppxPackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage"
call :title_remove_appx_packages
:: Wildcard removal for the rest of the apps
PowerShell -Command "Get-AppxPackage *3DViewer* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *AssignedAccessLockApp* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *PinningConfirmationDialog* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *SecureAssessmentBrowser* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Windows.SecHealth* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *FeedbackHub* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *MixedReality* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Microsoft.Caclulator* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Sticky* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Store* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *ECApp* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *MSPaint* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *wallet* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *LockApp* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *MicrosoftEdgeDevToolsClient* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *YourPhone* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *ContentDeliveryManager* | Remove-AppxPackage"
call :title_remove_appx_packages
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage"
call :title_remove_appx_packages
:: Remove Edge, both the new and old version
cd "C:\Program Files (x86)\Microsoft\Edge\Application\8*\Installer"
start setup.exe --uninstall --system-level --verbose-logging --force-uninstall
cls
goto removeedge

:next
timeout /t 30 /nobreak
:: Disabling One Drive
cls
echo.
echo  :: Uninstalling OneDrive
timeout /t 2 /nobreak > NUL

set x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
 
taskkill /f /im OneDrive.exe > NUL 2>&1
ping 127.0.0.1 -n 5 > NUL 2>&1
 
if exist %x64% (
%x64% /uninstall
) else (
echo "OneDriveSetup.exe installer not found, skipping."
)
ping 127.0.0.1 -n 8 > NUL 2>&1

rd "%USERPROFILE%\OneDrive" /Q /S > NUL 2>&1
rd "C:\OneDriveTemp" /Q /S > NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S > NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S > NUL 2>&1

echo.
echo Removing OneDrive from the Explorer Side Panel.
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1

:: Editing Hosts File, works sometimes, unreliable
cls
echo.
echo  :: Editing Hosts File
timeout /t 2 /nobreak

SET NEWLINE=^& echo.

FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 choice.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 wes.df.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 watson.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "survey.watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 survey.watson.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "watson.live.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 watson.live.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "statsfe2.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 statsfe2.ws.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "corpext.msitadfs.glbdns2.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "compatexchange.cloudapp.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 compatexchange.cloudapp.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "cs1.wpc.v0cdn.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 cs1.wpc.v0cdn.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "a-0001.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 a-0001.a-msedge.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "fe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 fe2.update.microsoft.com.akadns.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "statsfe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 statsfe2.update.microsoft.com.akadns.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "sls.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 sls.update.microsoft.com.akadns.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "diagnostics.support.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 diagnostics.support.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "corp.sts.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 corp.sts.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "statsfe1.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 statsfe1.ws.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "pre.footprintpredict.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 pre.footprintpredict.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "i1.services.social.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 i1.services.social.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "i1.services.social.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 i1.services.social.microsoft.com.nsatc.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "feedback.windows.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 feedback.windows.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "feedback.microsoft-hohm.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 feedback.microsoft-hohm.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "feedback.search.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 feedback.search.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "cdn.content.prod.cms.msn.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 cdn.content.prod.cms.msn.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "cdn.content.prod.cms.msn.com.edgekey.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 cdn.content.prod.cms.msn.com.edgekey.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "e10663.g.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 e10663.g.akamaiedge.net>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "dmd.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 dmd.metaservices.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "schemas.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 schemas.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "go.microsoft.com" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 go.microsoft.com>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.76.0.0/14" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.76.0.0/14>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.96.0.0/12" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.96.0.0/12>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.124.0.0/16" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.124.0.0/16>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.112.0.0/13" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.112.0.0/13>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.125.0.0/17" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.125.0.0/17>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.74.0.0/15" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.74.0.0/15>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.80.0.0/12" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.80.0.0/12>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "40.120.0.0/14" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 40.120.0.0/14>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "137.116.0.0/16" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 137.116.0.0/16>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "23.192.0.0/11" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 23.192.0.0/11>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "23.32.0.0/11" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 23.32.0.0/11>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "23.64.0.0/14" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 23.64.0.0/14>>%WINDIR%\System32\drivers\etc\hosts
FIND /C /I "23.55.130.182" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^0.0.0.0 23.55.130.182>>%WINDIR%\System32\drivers\etc\hosts

:: Enable Legacy F8 Bootmenu
bcdedit /set {default} bootmenupolicy legacy
:: Disable Recovery
bcdedit /set {current} recoveryenabled no

:: Disable Hibernation to make NTFS accessable outside of Windows
powercfg /h off
:: Set Performance Plan to High Performance and display to never turn off
powercfg /S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /change monitor-timeout-ac 0

goto reboot

:programs
cls
echo.
echo  :: Checking For Internet Connection...
echo.
timeout /t 2 /nobreak > NUL
ping -n 1 archlinux.org -w 20000 >nul
if %errorlevel% == 0 (
echo Internet Connection Found! Proceeding...
) else (
	echo  :: You are NOT connected to the Internet
	echo.
        echo     Please enable your Networking adapter and connect to try again.
        echo     Press any key to retry...
        pause > NUL
        goto programs
)

cls
echo.
echo  :: Installing Packages...
echo.
timeout /t 1 /nobreak > NUL
		
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin

:: Add/Remove packages here. Use chocolatey to 'search' for packages matching a term to get the proper name or head over to https://chocolatey.org/packages
:: Recommended optional packages include: libreoffice steam adobeair ffmpeg mpv youtube-dl directx cygwin babun transmission-qt audacity cdrtfe obs syncthing keepass

@powershell -NoProfile -ExecutionPolicy Bypass -Command "choco install -y --force --allow-empty-checksums firefox thunderbird open-shell vlc 7zip jpegview vcredist-all directx python3 onlyoffice wget cascadiamono"

:: Remove Windows Security from Start Menu
cls
echo.
echo  :: Installing Packages...
echo.
PowerShell -Command "wget -O PSTools.zip https://download.sysinternals.com/files/PSTools.zip"
PowerShell -Command "wget -O remove_SecHealthUI_stub.py https://git.ameliorated.info/malte/scripts/raw/branch/master/PYTHON/remove_SecHealthUI_stub.py"
7z e PSTools.zip psexec.exe -y
start psexec.exe -i -s cmd.exe /c %CD%\remove_SecHealthUI_stub.py
timeout /t 5 /nobreak > NUL
@powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage -all *Microsoft.Windows.SecHealthUI* | Remove-AppPackage -AllUsers"
del psexec.exe
del PSTools.zip
del remove_SecHealthUI_stub.py

:: Configure Open-Shell
:testos
cls
echo.
echo :: Configuring Open-Shell
echo.
echo Due to restrictions with batch scripting it is required that you to 
echo manually open the Open-Shell start menu for the first time.
echo.
echo Instructions:
echo   1. Click Start
echo   2. Click OK to close the Open-Shell Settings window
echo   3. Open the Start Menu once more and then return to the CMD window
echo.
echo Press any key to continue:
echo.
pause > NUL
set SHRTCT="%HOMEDRIVE%\Users\%username%\AppData\Roaming\OpenShell\Pinned\startscreen.lnk"
if exist %SHRTCT% (
	del %HOMEDRIVE%\Users\%username%\AppData\Roaming\OpenShell\Pinned\startscreen.lnk /f /q > NUL 2>&1
	goto configureopenshell
) else (
	goto testos
)

:configureopenshell
for /f "tokens=* USEBACKQ" %%i in (`wmic useraccount where "name="%username%"" get sid ^| findstr "S-"`) do set currentusername=%%i
set currentusername=%currentusername:~0,-3%
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\OpenShell" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\OpenShell\Settings" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\ClassicExplorer" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\ClassicExplorer\Settings" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\ClassicExplorer" /v "ShowedToolbar" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\ClassicExplorer" /v "NewLine" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\ClassicExplorer\Settings" /v "ShowStatusBar" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu" /v "ShowedStyle2" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu" /v "CSettingsDlg" /t REG_BINARY /d c80100001a0100000000000000000000360d00000100000000000000 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu" /v "OldItems" /t REG_BINARY /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu" /v "ItemRanks" /t REG_BINARY /d 0 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\MRU" /v "0" /t REG_SZ /d "C:\Windows\regedit.exe" /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "Version" /t REG_DWORD /d 04040098 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "AllProgramsMetro" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "RecentMetroApps" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "StartScreenShortcut" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "SearchInternet" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "SearchPath" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "GlassOverride" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "GlassColor" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "SkinW7" /t REG_SZ /d "Midnight" /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "SkinVariationW7" /t REG_SZ /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "SkinOptionsW7" /t REG_MULTI_SZ /d "USER_IMAGE=1"\0"SMALL_ICONS=0"\0"LARGE_FONT=0"\0"DISABLE_MASK=0"\0"OPAQUE=0"\0"TRANSPARENT_LESS=0"\0"TRANSPARENT_MORE=1"\0"WHITE_SUBMENUS2=0" /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "SkipMetro" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKEY_USERS\%currentusername%\SOFTWARE\OpenShell\StartMenu\Settings" /v "MenuItems7" /t REG_MULTI_SZ /d "Item1.Command=user_files"\0"Item1.Settings=NOEXPAND"\0"Item2.Command=user_documents"\0"Item2.Settings=NOEXPAND"\0"Item3.Command=user_pictures"\0"Item3.Settings=NOEXPAND"\0"Item4.Command=user_music"\0"Item4.Settings=NOEXPAND"\0"Item5.Command=user_videos"\0"Item5.Settings=NOEXPAND"\0"Item6.Command=downloads"\0"Item6.Settings=NOEXPAND"\0"Item7.Command=homegroup"\0"Item7.Settings=ITEM_DISABLED"\0"Item8.Command=separator"\0"Item9.Command=games"\0"Item9.Settings=TRACK_RECENT|NOEXPAND|ITEM_DISABLED"\0"Item10.Command=favorites"\0"Item10.Settings=ITEM_DISABLED"\0"Item11.Command=recent_documents"\0"Item12.Command=computer"\0"Item12.Settings=NOEXPAND"\0"Item13.Command=network"\0"Item13.Settings=ITEM_DISABLED"\0"Item14.Command=network_connections"\0"Item14.Settings=ITEM_DISABLED"\0"Item15.Command=separator"\0"Item16.Command=control_panel"\0"Item16.Settings=TRACK_RECENT"\0"Item17.Command=pc_settings"\0"Item17.Settings=TRACK_RECENT"\0"Item18.Command=admin"\0"Item18.Settings=TRACK_RECENT|ITEM_DISABLED"\0"Item19.Command=devices"\0"Item19.Settings=ITEM_DISABLED"\0"Item20.Command=defaults"\0"Item20.Settings=ITEM_DISABLED"\0"Item21.Command=help"\0"Item21.Settings=ITEM_DISABLED"\0"Item22.Command=run"\0"Item23.Command=apps"\0"Item23.Settings=ITEM_DISABLED"\0"Item24.Command=windows_security"\0"Item24.Settings=ITEM_DISABLED"\0" /f > NUL 2>&1

:: Creates a shortcut in the Open-Shell start menu
SETLOCAL ENABLEDELAYEDEXPANSION
SET LinkName=Firefox
SET Esc_LinkDest=%%HOMEDRIVE%%\Users\%username%\AppData\Roaming\OpenShell\Pinned\!LinkName!.lnk
SET Esc_LinkTarget=%%HOMEDRIVE%%\Program Files\Mozilla Firefox\Firefox.exe
SET cSctVBS=CreateShortcut.vbs
(
  echo Set oWS = WScript.CreateObject^("WScript.Shell"^) 
  echo sLinkFile = oWS.ExpandEnvironmentStrings^("!Esc_LinkDest!"^)
  echo Set oLink = oWS.CreateShortcut^(sLinkFile^) 
  echo oLink.TargetPath = oWS.ExpandEnvironmentStrings^("!Esc_LinkTarget!"^)
  echo oLink.Save
)1>!cSctVBS!
cscript //nologo .\!cSctVBS!
DEL !cSctVBS! /f /q

SETLOCAL ENABLEDELAYEDEXPANSION
SET LinkName=Mozilla Thunderbird
SET Esc_LinkDest=%%HOMEDRIVE%%\Users\user\AppData\Roaming\OpenShell\Pinned\!LinkName!.lnk
SET Esc_LinkTarget=%%HOMEDRIVE%%\Program Files\Mozilla Thunderbird\Thunderbird.exe
SET cSctVBS=CreateShortcut.vbs
(
  echo Set oWS = WScript.CreateObject^("WScript.Shell"^) 
  echo sLinkFile = oWS.ExpandEnvironmentStrings^("!Esc_LinkDest!"^)
  echo Set oLink = oWS.CreateShortcut^(sLinkFile^) 
  echo oLink.TargetPath = oWS.ExpandEnvironmentStrings^("!Esc_LinkTarget!"^)
  echo oLink.Save
)1>!cSctVBS!
cscript //nologo .\!cSctVBS!
DEL !cSctVBS! /f /q

del silent_installers.7z /f /q > NUL 2>&1
del OldNewExplorerCfg.exe /f /q > NUL 2>&1
del OldCalculatorforWindows10Cfg.exe /f /q > NUL 2>&1
del hardentoolsCfg.exe /f /q > NUL 2>&1

:: Download and configure OldNewExplorer
cls
echo.
echo  :: Installing Third Party Programs
echo.
echo Downloading...
PowerShell -Command "wget -O silent_installers.7z https://wiki.ameliorated.info/lib/exe/fetch.php?media=silent_installers.7z" > NUL 2>&1
cls
echo.
echo  :: Installing Third Party Programs
echo.
echo Extracting...
7z x silent_installers.7z > NUL 2>&1
cls
echo.
echo  :: Installing OldNewExplorer
echo.
echo Installing, please wait...
start OldNewExplorerCfg.exe > NUL 2>&1
timeout /t 15 /nobreak
taskkill /f /im explorer.exe > NUL 2>&1
taskkill /f /im OldNewExplorerCfg.exe > NUL 2>&1
start OldNewExplorerCfg.exe > NUL 2>&1
timeout /t 15 /nobreak
taskkill /f /im OldNewExplorerCfg.exe > NUL 2>&1
cls
echo.
echo  :: Installing Old Calculator for Windows 10
echo.
start OldCalculatorforWindows10Cfg.exe > NUL 2>&1
timeout /t 10 /nobreak
cls
echo.
echo  :: Installing hardentools
echo.
start hardentoolsCfg.exe > NUL 2>&1
cls
echo.
echo  :: Installing hardentools
echo.
timeout /t 30 /nobreak
:: hide hidden files in Windows Explorer again, hardentools turns this on
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 0 /f > NUL 2>&1
del silent_installers.7z /f /q > NUL 2>&1
del hardentoolsCfg.exe /f /q > NUL 2>&1
del OldCalculatorforWindows10Cfg.exe /f /q > NUL 2>&1
del OldNewExplorerCfg.exe /f /q > NUL 2>&1
goto reboot

:wallpaper
cls
echo.
echo  :: AME Wallpaper
echo.
echo     Install AME wallpapers? y/n 
echo.
echo  :: Type y to inject AME wallpapers
echo  :: Type n to return to the main menu
echo.
set /P menu=
	if %menu%==y GOTO installwallpaper
	if %menu%==n GOTO menu
else (
	cls
	echo.
	echo  :: Incorrect Input Entered
	echo.
	echo     Please type y/n
	echo     Press any key to retrn to the menu...
	echo.
	pause > NUL
	goto wallpaper
)

:installwallpaper
cls
echo.
echo  :: Checking For Internet Connection...
echo.
timeout /t 2 /nobreak > NUL
ping -n 1 archlinux.org -w 20000 >nul
if %errorlevel% == 0 (
echo Internet Connection Found! Proceeding...
) else (
	echo  :: You are NOT connected to the Internet
	echo.
        echo     Please enable your Networking adapter and connect to try again.
        echo     Press any key to retry...
        pause > NUL
        goto installwallpaper
)
cls
echo.
echo  :: AME Wallpaper
echo.
echo     Downloading AME wallpapers...
echo.
PowerShell -Command "wget -O master.zip https://git.ameliorated.info/malte/scripts/archive/master.zip" > NUL 2>&1
cls
echo.
echo  :: AME Wallpaper
echo.
echo     Injecting AME wallpapers...
echo.
7z e master.zip -aoa scripts\Wallpapers -y > NUL 2>&1
7z e ame_wallpaper_1440_bitmap.zip -y > NUL 2>&1
takeown /f C:\Windows\Web\Screen\*.jpg > NUL 2>&1
icacls C:\Windows\Web\Screen\*.jpg /reset > NUL 2>&1
takeown /f C:\Windows\Web\Screen\*.png > NUL 2>&1
icacls C:\Windows\Web\Screen\*.png /reset > NUL 2>&1
takeown /f C:\Windows\Web\Wallpaper\Windows\*.jpg > NUL 2>&1
icacls C:\Windows\Web\Wallpaper\Windows\*.jpg /reset > NUL 2>&1
takeown /f C:\Windows\Web\4K\Wallpaper\Windows\*.jpg > NUL 2>&1
icacls C:\Windows\Web\4K\Wallpaper\Windows\*.jpg /reset > NUL 2>&1
copy img100.jpg C:\Windows\Web\Screen\ /Y > NUL 2>&1
copy img103.png C:\Windows\Web\Screen\ /Y > NUL 2>&1
copy img0.jpg C:\Windows\Web\Wallpaper\Windows\ /Y > NUL 2>&1
copy img0_*.jpg C:\Windows\Web\4K\Wallpaper\Windows\ /Y > NUL 2>&1
copy *.bmp C:\Windows\Web\Wallpaper\Windows\ /Y > NUL 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d C:\Windows\Web\Wallpaper\Windows\ame_wallpaper_1440.bmp /f > NUL 2>&1

:: Delete Cache
takeown /f C:\ProgramData\Microsoft\Windows\SystemData > NUL 2>&1
icacls C:\ProgramData\Microsoft\Windows\SystemData /reset > NUL 2>&1
takeown /f C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18 > NUL 2>&1
icacls C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18 /reset > NUL 2>&1
takeown /f C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly > NUL 2>&1
icacls C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly /reset > NUL 2>&1
takeown /f C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z > NUL 2>&1
icacls C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z /reset > NUL 2>&1
takeown /f C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z\*.jpg > NUL 2>&1
icacls C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z\*.jpg /reset > NUL 2>&1
del C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z\*.jpg /f /q > NUL 2>&1
del master.zip /f /q > NUL 2>&1
rmdir .\Wallpapers /f /q > NUL 2>&1
del ame_wallpaper_1440_bitmap.zip /f /q > NUL 2>&1
del .\*.jpg /f /q > NUL 2>&1
del .\*.png /f /q > NUL 2>&1
del .\*.bmp /f /q > NUL 2>&1
goto reboot

:: Open User preferences to configure administrator/user permissions
:user
cls
echo.
echo  :: Manual User Permission Adjustment...
echo.
timeout /t 2 /nobreak > NUL

net user administrator /active:yes
:: attempt to add the logoff scripts to Windows
schtasks /create /xml C:\AME-Log-off-admin.xml /tn "AME Log-off admin" /ru administrator /it
schtasks /create /xml C:\AME-Log-off-admin-message.xml /tn "AME Log-off admin message" /ru administrator /it
netplwiz

goto menu

:reboot
echo.
echo  :: WINDOWS 10 AME SETUP SCRIPT Version 2021.04.03
echo.
cls
echo A reboot is required to complete setup.
echo.
echo Press any key to reboot
pause > NUL
shutdown -r -t 1 -f

:title_remove_appx_packages
cls
echo.
echo  :: Removing AppXPackages
echo.
exit /b 0

:removeedge
  setlocal enabledelayedexpansion
  set FN=%TEMP%\install_wim_tweak.tmp
  call :extract-embedded-bin "%FN%"
  start %FN% /o /l
  start %FN% /o /c Microsoft-Windows-Internet-Browser-Package /r
  start %FN% /h /o /l
  goto :next
:extract-embedded-bin <1=OutFileName>
setlocal
set MBEGIN=-1
for /f "useback tokens=1 delims=: " %%a in (`findstr /B /N /C:"-----BEGIN CERTIFICATE-----" "%~f0"`) DO (
  set /a MBEGIN=%%a-1
)
if "%MBEGIN%"=="-1" (
  endlocal
  exit /b -1
)
:: Delete previous output files
if exist "%~1.tmp" del "%~1.tmp"
if exist "%~1" del "%~1"  
for /f "useback skip=%MBEGIN% tokens=* delims=" %%a in ("%~f0") DO (
  echo %%a >>"%~1.tmp"
)
certutil -decode "%~1.tmp" "%~1" >nul 2>&1
del "%~1.tmp"
endlocal
exit /b 0

:: Do not be alarmed, this is install_wim_tweak.exe encoded in base64. The source can be found here: https://git.ameliorated.info/lucid/win6x_registry_tweak
-----BEGIN CERTIFICATE-----
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
AAAGKj4CKDAAAAYW/gEoLQAABioyAn52AAAKKHoAAAoqAAAAQlNKQgEAAQAAAAAA
DAAAAHYyLjAuNTA3MjcAAAAABQBsAAAARBMAACN+AACwEwAARBgAACNTdHJpbmdz
AAAAAPQrAABwEgAAI1VTAGQ+AAAQAAAAI0dVSUQAAAB0PgAAdBAAACNCbG9iAAAA
AAAAAAIAAAFX36I/CR8AAAD6ATMAFgAAAQAAAFAAAAAUAAAAkwAAADcAAABGAAAA
AQAAAIUAAAB3AAAAGgAAAAEAAAABAAAAEAAAAAIAAAADAAAABAAAAAEAAAACAAAA
BQAAAAYAAAABAAAAAQAAAAIAAAABAAAAAQAAAAIAAAACAAAAAgAAAAAA6A0BAAAA
AAAGAAMNehIGAHANehIGABQMSBIPANwSAAAGAEEMWxIGAJYLWxIGAFUM7w8GAMAM
7w8GAFcN7w8GACMN7w8GADwN7w8GAGwM7w8GAIcM7w8GAPILmhIGAOAPDBQGAKQM
DBQGALsL9hcGAKwVdg8GAEYAZQgGAAwQdg8KAPUUSBIGAEsXLwAGAPEIxA4GAAMK
JQ8GABUYJQ8GAAEAZQgGAEIJdg8GAA8AZQgKAKQLFREGANULSBIGAHsLehIGAPIQ
mhIGAEQQyw8KAEIL4g4KACgM4g4GAEAAdg8GAD8Adg8GAE4Jdg8GAD0Sdg8GAN0M
7w8GACULPhQGAPQMdg8GAIIPdg8GACYOdg8GAL8Kdg8GANwJdg8GAHERdg8GAL8Q
dg8GAFsUehIGAAYXdg8GAFoJdg8GAAsWdg8GAFEOlwYGANEJlwYGALoXLwAGAG8Q
dg8KAF4QSBIKACYKSBIGAEURlwYGAFIRlwYGACYYxA4GAAIRxA4GAKEOLwAGACMV
JQ8GANcILwAGACgUJQ8GAMkKJQ8GAAYYJQ8GAAcSPhQGANYQlwYGAOMQlwYGAHUX
7w8GAG0K7w8GAMMPdg8GAPgKdg8GAG0Jdg8GAKINdg8GALwOWxIGAPUAdg8GAHwW
PhQAAAAAsQAAAAAAAQABAAAAEABlD48OSQABAAEAAAAQAKESWBNJABAAEgCBABAA
mg/dFxgAEgAWAAEAEADAFN0XEAATABsAgQAQAKIV3RdJABMAHgABABAAwgjdF0kA
EwAiAAEAEAApCd0XSQAUACQAAQAQAD0T3RelADIAJwABAQAA8grdF60AMgArAAEB
AADbCt0XrQBEACsAAQEAAOsK3RetAFIAKwABAQAAkhPdF60AcQArAAEBAACyE90X
rQB2ACsAAQAQADkA3RdJAIUAKwAJARAAgwL9FLUAjgA4AAkBEAAcB/0UtQCQADgA
CQEQAE4H/RS1AJEAOAAAAQAAugAAAEkAkwA4ABMBAACUAAAAtQCUADgAUYANB9YN
EQCDF9YNUYD0B9YNUYDsBdYNMQDIENYNUYCFBtYNEQC2CNkNEQDNCdYNEQA2ENYN
EQCXENYNEQDsE9wNEQC3CtkNMQBBDtYNEQDEENYNEQD+E9kNEQCHD+QNEQAVC+kN
AQDFCSsCIQDHCO4NVoBxA9YNVoBWA9YNVoC8BNYNVoCuAtYNVoCMBNYNVoB0BNYN
VoDFAtYNVoDqBNYNVoDJA9YNVoDvA9YNVoDpAtYNVoAAA9YNVoADBNYNVoDQBNYN
VoDRAtYNVoBbBNYNVoDgA9YNVoApA9YNVoCgA9YNVoA5A9YNVoAfBNYNVoBABNYN
VoCmBNYNVoCxA9YNVoBHA9YNVoAtBNYNVoCGA9YNVoATA9YNIQCmE/INIQDHCPYN
BgZPCPoNVoBMBf0NVoAuBv0NVoDrAP0NVoDtBv0NVoDgBf0NVoB0Af0NVoA2Af0N
VoB+Bf0NVoCyBf0NVoAaBv0NVoAGBv0NVoAvCP0NVoApAv0NVoAOAf0NVoBTBf0N
VoCUBf0NVoD6Bf0NBgZPCPoNVoAOCAEOVoAYBQEOVoA6BQEOVoAjCAEOVoCIAgEO
VoAtBwEOVoBiBwEOVoC/BwEOVoBjAgEOVoB2BwEOVoArAQEOVoByBQEOVoCkBQEO
BgZPCPoNVoBMBQUOVoAuBgUOVoDrAAUOVoDtBgUOVoDgBQUOVoB0AQUOVoA2AQUO
VoB+BQUOVoCyBQUOVoAaBgUOVoAGBgUOVoAvCAUOVoApAgUOVoAOAQUOVoBTBQUO
VoCUBQUOVoD6BQUOVoAoBQUOVoD4AAUOVoBNAgUOVoBwBgUOVoAbAQUOVoBhBQUO
VoCbAgUOVoCoBwUOVoDZAAUOVoA+BgUOVoBWBgUOVoD7BAUOVoCHBwUOBgZPCPoN
VoCtCPINVoDvFfINVoCdCPINVoCpFPINBgZPCAkOVoAWAgwOVoADAgwOVoDUBwwO
VoDfAQwOVoDkBwwOVoDxAQwOVoChBgwOVoC6BgwOVoCxAQwOVoDIAQwOVoCNAQwO
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
DAATEqoBJAAXFroB2QAsEMIBKQLOFv8AMQE6CwYAyQGODRAAyQHEERAAyQGzFhAA
yQGGFhAAyQHXFhAAYQGbFccBYQGbFc4BqQCgFtkBOQLNCMIAqQCyEdkBcQHCFV8A
cQGrEF8AFAAhEgYAYQF9D8IAYQFRFO8BFACZCPoBFAC5EAYAkQAhEgYAQQJpFwIC
QQJlCggCSQK/Dw4CkQAkDsIAWQKYCRQCWQJcFx0CAQEhEiMCOQF+ECsCOQHPFy4C
OQHRFUICcQKgEdUAOQHDFy4CeQL+DU4CcQIPDmICcQIuEmkCSQFuFnACgQJtD3YC
gQKZCMIBSQEuFoUAkQF+F4sCSQEhEgYAcQKJEdUAcQL5Bl8ADgAEAKECDgAMAMgC
DgAQAPkCDgAYADoDDgBQACIHDgBUAE8HDgBYAIoHDgBcALUHDgBgAOYHDgBkAB0I
DgBoAFAIDgBsAG0IDgBwAJQIDgB0AMUIDgB4APAIDgB8ACEJDgCAAEwJDgCEAIsJ
DgCIAMoJDgCMAP0JDgCQADIKDgCUAFUKDgCYAHoKDgCcAKEKDgCgAMIKDgCkAOMK
DgCoABwLDgCsAEsLDgCwAH4LDgC0AKELDgC4AMoLDgC8AAEMCQDMADAMCQDQADUM
CQDUADoMCQDYAD8MCQDcAEQMCQDgAEkMCQDkADUMCQDoADUMCQDsADUMCQDwAE4M
CQD0AFMMCQD4AFgMCQD8AF0MCQAAAWIMCQAEAWcMCQAIAWwMCQAMAXEMCQAUAXYM
CQAYAXsMCQAcAYAMCQAgAYUMCQAkAYoMCQAoAY8MCQAsAZQMCQAwAZkMCQA0AZ4M
CQA4AaMMCQA8AagMCQBAAa0MCQBEATUMCQBMATAMCQBQATUMCQBUAToMCQBYAT8M
CQBcAUQMCQBgAUkMCQBkATUMCQBoATUMCQBsATUMCQBwAU4MCQB0AVMMCQB4AVgM
CQB8AV0MCQCAAWIMCQCEAWcMCQCIAWwMCQCMAXEMCQCQAXYMCQCUAXsMCQCYAYAM
CQCcAYUMCQCgAYoMCQCkAY8MCQCoAZQMCQCsAZkMCQCwAZ4MCQC0AbIMCQC4AbcM
CQC8AbwMCQDAAcEMCQDIAcYMCQDMAXYMCQDQAXsMCQDUAWIMBwDcAcsMBwDgAc4M
BwDkAdEMBwDoAdQMBwDsAdcMBwDwAdoMBwD0Ad0MBwD4AeAMBwD8AeMMBwAAAuYM
BwAEAukMBwAIAuwMBwAMAu8MBwAQAvIMCAAUAsYMCAAYAnYMCAAcAsYMCAAgAsYM
CAAkAvUMCAAoAvoMCAAsAv8MDgAwAgQNDgA0Ah0NJwB7AHYMKQCbAC8PLgALAAcP
LgATABAPLgAbAC8PLgAjADgPLgArAD4PLgAzAGgPLgA7AIMPLgBDAK4PLgBLAGgP
LgBTAMoPLgBbAPgPLgBjAA4QLgBrABsQSQCbAC8PYwCDACYQYwCLAHYMYwCTAHYM
IwGrAGcQQwGzAHYMYwGzAHYMgwGzAHYMowGzAHYMwwGzAHYMYwKTAHYMCAAGADYN
AQASAAAAFAA0AMYAAwEdAVcBcAGNAZsB1AHfATQCOQJIAlMCWAJ7AgMAAQAJAAMA
AADyEPUOAAAdC/sOAABxDwEPAgATAAMAAgAUAAUAAQAVAAUAAgAnAAcABgA+ACkA
Dw8CDyAAUgCnAbMBvwEAAWMA6xEBAEABZQDTFAEAQAFnAH8JAQBAAWkAqQ8CAEYB
awCnDQIARgFtADcTAgBEiAAAkwAEgAAAAQAEAAcAAAAAAAAAAACPDgAAAgAAAAAA
AAAAAAAAmAJXCAAAAAACAAAAAAAAAAAAAACYAnYPAAAAAAAAAAABAAAAqxIAABQA
EwAAAAAAEwAcDwEAAAATACwXEgCxABIA9AEBAAYAAgBtAAAAAElFbnVtZXJhYmxl
YDEASUVudW1lcmF0b3JgMQBBZHZhcGkzMgBLZXJuZWwzMgBNaWNyb3NvZnQuV2lu
MzIAVUludDMyAERpY3Rpb25hcnlgMgA1MkExQTBGQzlDNkYzMjdEMDlDNzU2NDQ4
NzAyRkNDOUM1RjlDQ0Q1ODU3MkVFMDY2RTU5NTE1OTY3OERGNTYzAF9fU3RhdGlj
QXJyYXlJbml0VHlwZVNpemU9MTgAPE1vZHVsZT4APFByaXZhdGVJbXBsZW1lbnRh
dGlvbkRldGFpbHM+AFBST0NFU1NfU0VUX1FVT1RBAFdSSVRFX0RBQwBHQwBQUk9D
RVNTX0NSRUFURV9USFJFQUQAR0VORVJJQ19SRUFEAFBST0NFU1NfVk1fUkVBRABU
T0tFTl9SRUFEAFNUQU5EQVJEX1JJR0hUU19SRUFEAEVSUk9SX05PVF9BTExfQVNT
SUdORUQARVJST1JfTk9ORV9NQVBQRUQAU1RBTkRBUkRfUklHSFRTX1JFUVVJUkVE
AFNFX0RBQ0xfUFJPVEVDVEVEAFNFX1NBQ0xfUFJPVEVDVEVEAFNFX0RBQ0xfQVVU
T19JTkhFUklURUQAU0VfU0FDTF9BVVRPX0lOSEVSSVRFRABTRV9EQUNMX0RFRkFV
TFRFRABTRV9TQUNMX0RFRkFVTFRFRABTRV9HUk9VUF9ERUZBVUxURUQAU0VfT1dO
RVJfREVGQVVMVEVEAE1BWElNVU1fQUxMT1dFRABTRV9STV9DT05UUk9MX1ZBTElE
AFBST0NFU1NfU0VUX1NFU1NJT05JRABUT0tFTl9BREpVU1RfU0VTU0lPTklEAEdl
dE5hdGl2ZUxVSUQAVE9LRU5fUVVFUllfU09VUkNFAFBST0NFU1NfRFVQX0hBTkRM
RQBTRV9JTkNSRUFTRV9RVU9UQV9OQU1FAFNFX1RDQl9OQU1FAFNFX0NSRUFURV9Q
QUdFRklMRV9OQU1FAFNFX1NZU1RFTV9QUk9GSUxFX05BTUUAU0VfU1lTVEVNVElN
RV9OQU1FAFNFX01BTkFHRV9WT0xVTUVfTkFNRQBTRV9SRVNUT1JFX05BTUUAU0Vf
REVCVUdfTkFNRQBTRV9VTkRPQ0tfTkFNRQBTRV9BU1NJR05QUklNQVJZVE9LRU5f
TkFNRQBTRV9DUkVBVEVfVE9LRU5fTkFNRQBTRV9FTkFCTEVfREVMRUdBVElPTl9O
QU1FAFNFX1NIVVRET1dOX05BTUUAU0VfUkVNT1RFX1NIVVRET1dOX05BTUUAU0Vf
VEFLRV9PV05FUlNISVBfTkFNRQBTRV9CQUNLVVBfTkFNRQBTRV9MT0FEX0RSSVZF
Ul9OQU1FAFNFX1BST0ZfU0lOR0xFX1BST0NFU1NfTkFNRQBTRV9BVURJVF9OQU1F
AFNFX1NZTkNfQUdFTlRfTkFNRQBTRV9TWVNURU1fRU5WSVJPTk1FTlRfTkFNRQBT
RV9DUkVBVEVfUEVSTUFORU5UX05BTUUAU0VfTUFDSElORV9BQ0NPVU5UX05BTUUA
U0VfVU5TT0xJQ0lURURfSU5QVVRfTkFNRQBTRV9DSEFOR0VfTk9USUZZX05BTUUA
U0VfTE9DS19NRU1PUllfTkFNRQBTRV9JTkNfQkFTRV9QUklPUklUWV9OQU1FAFNF
X1NFQ1VSSVRZX05BTUUAUFJPQ0VTU19TVVNQRU5EX1JFU1VNRQBGQUxTRQBUT0tF
Tl9EVVBMSUNBVEUAUFJPQ0VTU19URVJNSU5BVEUAVE9LRU5fSU1QRVJTT05BVEUA
REVMRVRFAEdFTkVSSUNfV1JJVEUAUFJPQ0VTU19WTV9XUklURQBUT0tFTl9XUklU
RQBTVEFOREFSRF9SSUdIVFNfV1JJVEUAR0VORVJJQ19FWEVDVVRFAFRPS0VOX0VY
RUNVVEUAU1RBTkRBUkRfUklHSFRTX0VYRUNVVEUAVFJVRQBTRV9TRUxGX1JFTEFU
SVZFAFNZTkNIUk9OSVpFAFJFR0lTVFJZX1BBVEgAR0VORVJJQ19BTEwAU1BFQ0lG
SUNfUklHSFRTX0FMTABTVEFOREFSRF9SSUdIVFNfQUxMAFJFQURfQ09OVFJPTABD
TgBQUk9DRVNTX1NFVF9JTkZPUk1BVElPTgBQUk9DRVNTX1FVRVJZX0lORk9STUFU
SU9OAFBST0NFU1NfVk1fT1BFUkFUSU9OAFBST0dSQU1fSEVMUF9JTkZPAFN5c3Rl
bS5JTwBTRV9EQUNMX0FVVE9fSU5IRVJJVF9SRVEAU0VfU0FDTF9BVVRPX0lOSEVS
SVRfUkVRAEVSUk9SX0lOU1VGRklDSUVOVF9CVUZGRVIAV1JJVEVfT1dORVIAVGhy
b3dFeGNlcHRpb25Gb3JIUgBISVZFX01PVU5UX0RJUgBUT0tFTl9QUklWSUxFR0VT
AFRPS0VOX0FESlVTVF9QUklWSUxFR0VTAEdldE5hdGl2ZUxVSURfQU5EX0FUVFJJ
QlVURVMAVE9LRU5fQURKVVNUX0dST1VQUwBUT0tFTl9BTExfQUNDRVNTAFBST0NF
U1NfQUxMX0FDQ0VTUwBFUlJPUl9TVUNDRVNTAFBST0NFU1NfQ1JFQVRFX1BST0NF
U1MAVE9LRU5fQURKVVNUX0RFRkFVTFQAU0VfREFDTF9QUkVTRU5UAFNFX1NBQ0xf
UFJFU0VOVABISVZFX01PVU5UX1BPSU5UAGNvbnNvbGVYAFRPS0VOX0FTU0lHTl9Q
UklNQVJZAFRPS0VOX1FVRVJZAEFDQ0VTU19TWVNURU1fU0VDVVJJVFkAY29uc29s
ZVkAdmFsdWVfXwBtc2NvcmxpYgBuYWNjAFN5c3RlbS5Db2xsZWN0aW9ucy5HZW5l
cmljAG5wcm9jAGdldF9JZABkd1Byb2Nlc3NJZABBZGQARW5hYmxlZABlbmFibGVk
AERpc2FibGVkAF9mYWlsZWQAcGlkAEx1aWQAX2x1aWQAUmVhZFRvRW5kAFJlZ2lz
dHJ5VmFsdWVLaW5kAFJlcGxhY2UASWRlbnRpdHlSZWZlcmVuY2UAZHdFcnJDb2Rl
AGdldF9NZXNzYWdlAEVuYWJsZVByaXZpbGVnZQBUb2tlblByaXZpbGVnZQBwcml2
aWxlZ2UASUNvbXBhcmFibGUASURpc3Bvc2FibGUAUnVudGltZUZpZWxkSGFuZGxl
AFJ1bnRpbWVUeXBlSGFuZGxlAENsb3NlSGFuZGxlAElzTnVsbEhhbmRsZQBHZXRU
eXBlRnJvbUhhbmRsZQBUb2tlbkhhbmRsZQBiSW5oZXJpdEhhbmRsZQBfaGFuZGxl
AF9ia3BGaWxlAG5maWxlAENvbnNvbGUAQWRkQWNjZXNzUnVsZQBSZW1vdmVBY2Nl
c3NSdWxlAFJlZ2lzdHJ5QWNjZXNzUnVsZQBzZXRfV2luZG93U3R5bGUAUHJvY2Vz
c1dpbmRvd1N0eWxlAHNldF9GaWxlTmFtZQBscFN5c3RlbU5hbWUAc3lzdGVtTmFt
ZQBscE5hbWUAR2V0TmFtZQBBc3NlbWJseU5hbWUAbmtleW5hbWUAUmVhZExpbmUA
V3JpdGVMaW5lAGdldF9OZXdMaW5lAENvbWJpbmUATG9jYWxNYWNoaW5lAF9vbmxp
bmUAVmFsdWVUeXBlAEFjY2Vzc0NvbnRyb2xUeXBlAFRva2VuQWNjZXNzVHlwZQBQ
cm9jZXNzQWNjZXNzVHlwZQBnZXRfQ3VsdHVyZQBzZXRfQ3VsdHVyZQByZXNvdXJj
ZUN1bHR1cmUAQ29sbGVjdGlvbkJhc2UAQ2xvc2UARGlzcG9zZQBFZGl0b3JCcm93
c2FibGVTdGF0ZQBQcmV2aW91c1N0YXRlAE5ld1N0YXRlAERlbGV0ZQBXcml0ZQBD
b21waWxlckdlbmVyYXRlZEF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAEdlbmVyYXRl
ZENvZGVBdHRyaWJ1dGUAVW52ZXJpZmlhYmxlQ29kZUF0dHJpYnV0ZQBEZWJ1Z2dl
ck5vblVzZXJDb2RlQXR0cmlidXRlAE5ldXRyYWxSZXNvdXJjZXNMYW5ndWFnZUF0
dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAEVkaXRvckJyb3dzYWJsZUF0dHJp
YnV0ZQBDb21WaXNpYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUA
QXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0
dHJpYnV0ZQBTZWN1cml0eVBlcm1pc3Npb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNj
cmlwdGlvbkF0dHJpYnV0ZQBEZWZhdWx0TWVtYmVyQXR0cmlidXRlAEZsYWdzQXR0
cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQ
cm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2Vt
Ymx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0
ZQBzZXRfVXNlU2hlbGxFeGVjdXRlAEJ5dGUATG9va3VwUHJpdmlsZWdlVmFsdWUA
R2V0VmFsdWUAU2V0VmFsdWUAdmFsdWUATG9hZEhpdmUAVW5sb2FkSGl2ZQBpbnN0
YWxsX3dpbV90d2Vhay5leGUAU3VwcHJlc3NGaW5hbGl6ZQBTaXplT2YAUnVuUmVn
AEVuZGluZwBUb1N0cmluZwBTdWJzdHJpbmcAZGlzcG9zaW5nAFBhY2tMb2cAcmVn
aXN0cnlQYXRoAGdldF9MZW5ndGgAUmV0dXJuTGVuZ3RoAEJ1ZmZlckxlbmd0aABF
bmRzV2l0aABTdGFydHNXaXRoAGluc3RhbGxfd2ltX3R3ZWFrAFJlZ2lzdHJ5S2V5
UGVybWlzc2lvbkNoZWNrAE1hcnNoYWwAU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBh
bAB2YWwAU3lzdGVtLkNvbXBvbmVudE1vZGVsAENoZWNrQ2FsbABBZHZhcGkzMi5k
bGwAa2VybmVsMzIuZGxsAHR5cGVDb2xsAFN5c3RlbS5TZWN1cml0eS5BY2Nlc3ND
b250cm9sAEdldEFjY2Vzc0NvbnRyb2wAU2V0QWNjZXNzQ29udHJvbABQcm9ncmFt
AGdldF9JdGVtAFN5c3RlbQBUcmltAEVudW0AcmVzb3VyY2VNYW4AaFRva2VuAEFj
Y2Vzc1Rva2VuAFRyeU9wZW5Qcm9jZXNzVG9rZW4ATWFpbgBnZXRfVmVyc2lvbgBT
eXN0ZW0uR2xvYmFsaXphdGlvbgBTZWN1cml0eUFjdGlvbgBTeXN0ZW0uUmVmbGVj
dGlvbgBjb2xsZWN0aW9uAEV4Y2VwdGlvbgBDb3JyZWN0Q29uc29sZVBvc3Rpb24A
Q29tcGFyZVRvAF9oaXZlRmlsZUluZm8AQ3VsdHVyZUluZm8AZ2V0X1N0YXJ0SW5m
bwBQcm9jZXNzU3RhcnRJbmZvAENvbnNvbGVLZXlJbmZvAFplcm8AUmVnU2V0T3du
ZXNoaXAAQ29tcABfY29tcABnZXRfQ3Vyc29yVG9wAHNldF9DdXJzb3JUb3AAQ2xl
YXIAQ2hhcgBfY3IAUHJvZ3JhbUhlYWRlcgBTdHJlYW1SZWFkZXIAVGV4dFJlYWRl
cgBnZXRfUmVzb3VyY2VNYW5hZ2VyAFNlY3VyaXR5SWRlbnRpZmllcgBTeXN0ZW0u
Q29kZURvbS5Db21waWxlcgBTZXRPd25lcgBnZXRfVXNlcgBudXNlcgBTdHJlYW1X
cml0ZXIAVGV4dFdyaXRlcgBzZXRfRm9yZWdyb3VuZENvbG9yAENvbnNvbGVDb2xv
cgBSZXNldENvbG9yAEdldEhSRm9yTGFzdFdpbjMyRXJyb3IAR2V0TGFzdFdpbjMy
RXJyb3IAZ2V0X1N0YW5kYXJkRXJyb3IAc2V0X1JlZGlyZWN0U3RhbmRhcmRFcnJv
cgBHZXRMYXN0RXJyb3IAU2V0TGFzdEVycm9yAFRocm93TGFzdEVycm9yAElFbnVt
ZXJhdG9yAEdldEVudW1lcmF0b3IALmN0b3IALmNjdG9yAFN0cnVjdHVyZVRvUHRy
AEludFB0cgBwdHIAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLklu
dGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAFN5
c3RlbS5SZXNvdXJjZXMAaW5zdGFsbF93aW1fdHdlYWsuUHJvcGVydGllcy5SZXNv
dXJjZXMucmVzb3VyY2VzAERlYnVnZ2luZ01vZGVzAFVuc2FmZUVuYWJsZURpc2Fi
bGVQcml2aWxlZ2VzAERpc2FibGVBbGxQcml2aWxlZ2VzAEdldE5hdGl2ZVRva2Vu
UHJpdmlsZWdlcwBBZGp1c3RUb2tlblByaXZpbGVnZXMAcHJpdmlsZWdlcwBpbnN0
YWxsX3dpbV90d2Vhay5Qcm9wZXJ0aWVzAEdldFZhbHVlTmFtZXMAR2V0U3ViS2V5
TmFtZXMAUHJpdmlsZWdlQXR0cmlidXRlcwBfYXR0cmlidXRlcwBTZWN1cml0eURl
c2NyaXB0b3JDb250cm9sRmxhZ3MAYWxsb3dlZEFyZ3MAUHJvY2Vzc0NtZEFyZ3MA
X2NtZExpbmVBcmdzAGFyZ3MAX3ZpcwBDb250YWlucwBTeXN0ZW0uU2VjdXJpdHku
UGVybWlzc2lvbnMAQWNjZXNzQ29udHJvbFNlY3Rpb25zAFN5c3RlbS5Db2xsZWN0
aW9ucwBnZXRfQ2hhcnMAUnVudGltZUhlbHBlcnMAZHdEZXNpcmVkQWNjZXNzAGRl
c2lyZWRBY2Nlc3MAUmVnUmVtb3ZlQWNjZXNzAFJlZ1NldEZ1bGxBY2Nlc3MAVXNl
ZEZvckFjY2VzcwBoUHJvY2VzcwBBY2Nlc3NUb2tlblByb2Nlc3MAT3BlblByb2Nl
c3MASW5pdFByb2Nlc3MAR2V0Q3VycmVudFByb2Nlc3MATWljcm9zb2Z0LldpbjMy
LlNlY3VyaXR5LldpbjMyU3RydWN0cwBSZWdpc3RyeVJpZ2h0cwBzZXRfQXJndW1l
bnRzAG5Bcmd1bWVudHMARXhpc3RzAFJlbW92ZUNvbXBvbmVudFN1YmtleXMAQ2xl
YW5Db21wb25lbnRTdWJrZXlzAExpc3RDb21wb25lbnRTdWJrZXlzAENvbmNhdABG
b3JtYXQARGlzcG9zYWJsZU9iamVjdABnZXRfQ3Vyc29yTGVmdABzZXRfQ3Vyc29y
TGVmdABvcF9FeHBsaWNpdABTcGxpdABXYWl0Rm9yRXhpdABFbmFibGVkQnlEZWZh
dWx0AGZ1bmNSZXN1bHQARW52aXJvbm1lbnQAZ2V0X0N1cnJlbnQAR2V0Q3VycmVu
dABnZXRfQ291bnQAUHJpdmlsZWdlQ291bnQAR2V0UGF0aFJvb3QAdG90AEhpZ2hQ
YXJ0AExvd1BhcnQAU3RhcnQAZ2V0X0lubmVyTGlzdABBcnJheUxpc3QAc2V0X1Jl
ZGlyZWN0U3RhbmRhcmRJbnB1dABnZXRfU3RhbmRhcmRPdXRwdXQAc2V0X1JlZGly
ZWN0U3RhbmRhcmRPdXRwdXQATW92ZU5leHQAc2V0X0NyZWF0ZU5vV2luZG93AGlu
ZGV4AEluaXRpYWxpemVBcnJheQBUb0NoYXJBcnJheQBEZWxldGVTdWJLZXkAT3Bl
blN1YktleQBSZWFkS2V5AHR5cGVLZXkAQ29udGFpbnNLZXkAblBhcmVudEtleQBS
ZWdpc3RyeUtleQBua2V5AGdldF9Bc3NlbWJseQBHZXRFeGVjdXRpbmdBc3NlbWJs
eQBDb3B5AF9wa2dEaXJlY3RvcnkAZ2V0X1N5c3RlbURpcmVjdG9yeQBnZXRfQ3Vy
cmVudERpcmVjdG9yeQBSZWdpc3RyeQBvcF9FcXVhbGl0eQBvcF9JbmVxdWFsaXR5
AE1pY3Jvc29mdC5XaW4zMi5TZWN1cml0eQBTeXN0ZW0uU2VjdXJpdHkAT2JqZWN0
U2VjdXJpdHkAUmVnaXN0cnlTZWN1cml0eQBXaW5kb3dzSWRlbnRpdHkASXNOdWxs
T3JFbXB0eQAAg+dVAFMAQQBHAEUAIAA6ACAACgAgACAAIABpAG4AcwB0AGEAbABs
AF8AdwBpAG0AXwB0AHcAZQBhAGsAIABbAC8AcAAgADwAUABhAHQAaAA+AF0AIABb
AC8AYwAgADwAUABhAGMAawBhAGcAZQBOAGEAbQBlAD4AIAAoAG8AcAB0AGkAbwBu
AGEAbAApAF0AIABbAC8APwBdAAoACgBSAEUATQBBAFIASwBTACAAOgAgAAoAIAAg
ACAALwBwADwAUABhAHQAaAA+ACAAIAAgACAAIABVAHMAZQAgACcALwBwACcAIABz
AHcAaQB0AGMAaAAgAHQAbwAgAHAAcgBvAHYAaQBkAGUAIABwAGEAdABoACAAdABv
ACAAbQBvAHUAbgB0AGUAZAAgAGkAbgBzAHQAYQBsAGwALgB3AGkAbQAKACAAIAAg
AC8AbwAgACAAIAAgACAAIAAgACAAIAAgACAAVQBzAGUAIAAnAC8AbwAnACAAdABv
ACAAcgB1AG4AIABvAG4AIABjAHUAcgByAGUAbgB0ACAAVwBpAG4AZABvAHcAcwAK
ACAAIAAgAC8AYwAgADwAQwBvAG0AcABvAG4AZQBuAHQATgBhAG0AZQA+ACAAIABV
AHMAZQAgACcALwBjACcAIAB0AG8AIABzAGgAbwB3ACAAYQAgAHMAcABlAGMAaQBm
AGkAYwAgAHAAYQBjAGsAYQBnAGUACgAgACAAIAAvAD8AIAAgACAAIAAgACAAIAAg
ACAAIAAgAFUAcwBlACAAJwAvAD8AJwAgAHMAdwBpAHQAYwBoACAAdABvACAAZABp
AHMAcABsAGEAeQAgAHQAaABpAHMAIABpAG4AZgBvAAoAIAAgACAALwBsACAAIAAg
ACAAIAAgACAAIAAgACAAIABPAHUAdABwAHUAdABzACAAYQBsAGwAIABwAGEAYwBr
AGEAZwBlAHMAIAB0AG8AIAAiAFAAYQBjAGsAYQBnAGUAcwAuAHQAeAB0ACIACgBF
AFgAQQBNAFAATABFACAAOgAgAAoAIAAgACAAIABpAG4AcwB0AGEAbABsAF8AdwBp
AG0AXwB0AHcAZQBhAGsAIAAvAHAAIABDADoAXAB0AGUAbQBwACAAZgBpAGwAZQBz
AFwAbQBvAHUAbgB0AAoAIAAgACAAIABpAG4AcwB0AGEAbABsAF8AdwBpAG0AXwB0
AHcAZQBhAGsAIAAvAGMAIABNAGkAYwByAG8AcwBvAGYAdAAtAEgAeQBwAGUAcgAt
AFYALQBDAG8AbQBtAG8AbgAtAEQAcgBpAHYAZQByAHMALQBQAGEAYwBrAGEAZwBl
AAF7CgBQAGwAZQBhAHMAZQAgAG0AYQBrAGUAIABzAHUAcgBlACAAeQBvAHUAIAB1
AHMAZQAgAGwAbwB3AGUAcgBjAGEAcwBlACAAZgBvAHIAIAB0AGgAZQAgAC8AcAAs
ACAALwBjACwAIAAvAG8AIABhAG4AZAAgAC8AbAAAAQCAr1QAeQBwAGUAIAB0AGgA
ZQAgAG4AYQBtAGUAIABvAGYAIAB0AGgAZQAgAHAAYQBjAGsAYQBnAGUALAAgAGkA
ZgAgAG4AbwB0AGgAaQBuAGcAIABpAHMAIABlAG4AdABlAHIAZQBkACAAYQBsAGwA
IABwAGEAYwBrAGEAZwBlAHMAIAB3AGkAbABsACAAYgBlACAAbQBhAGQAZQAgAHYA
aQBzAGkAYgBsAGUAIAA6AABBVwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMA
MgBcAGMAbwBuAGYAaQBnAFwAUwBPAEYAVABXAEEAUgBFAAAlTQBvAHUAbgB0AFAA
YQB0AGgAIAA6ACAATwBuAGwAaQBuAGUAACd3AGkAbgBkAG8AdwBzADYAXwB4AF8A
cwBvAGYAdAB3AGEAcgBlAAARUwBvAGYAdAB3AGEAcgBlAABFVAB5AHAAZQAgAHAA
YQB0AGgAIAB0AG8AIABtAG8AdQBuAHQAZQBkACAAaQBuAHMAdABhAGwAbAAuAHcA
aQBtACAAOgAAH00AbwB1AG4AdABQAGEAdABoACAAOgAgAHsAMAB9AAADIgAAgItS
AGUAZwBpAHMAdAByAHkAIABmAGkAbABlACAAbgBvAHQAIABmAG8AdQBuAGQALAAg
AHAAbABlAGEAcwBlACAAbQBhAGsAZQAgAHMAdQByAGUAIAB5AG8AdQByACAAbQBv
AHUAbgB0ACAAcABhAHQAaAAgAGkAcwAgAGMAbwByAHIAZQBjAHQAIQAAA34AABtD
AG8AbQBwAG8AbgBlAG4AdAAgADoAIAAiAABZCgAtAC0ALQAtAC0ALQAtAC0ALQAt
AC0ALQAtAC0ALQAtAC0ALQBTAHQAYQByAHQAaQBuAGcALQAtAC0ALQAtAC0ALQAt
AC0ALQAtAC0ALQAtAC0ALQAtAAFTQwByAGUAYQB0AGkAbgBnACAAQgBLAFAAIABv
AGYAIAByAGUAZwBpAHMAdAByAHkAIABmAGkAbABlAC4ALgAuACAAIAAgACAAIAAg
ACAAIAAgAAAXUwBPAEYAVABXAEEAUgBFAEIASwBQAAAFTwBLAABTTQBvAHUAbgB0
AGkAbgBnACAAcgBlAGcAaQBzAHQAcgB5ACAAZgBpAGwAZQAuAC4ALgAgACAAIAAg
ACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAAxSABLAEwATQBcAHcAaQBuAGQAbwB3
AHMANgBfAHgAXwBzAG8AZgB0AHcAYQByAGUAAAlGAEEASQBMAABNVwByAGkAdABp
AG4AZwAgAHQAbwAgAEwAbwBnACAAKABQAGEAYwBrAGEAZwBlAHMALgB0AHgAdAAp
ACAAIAAgACAAIAAgACAAIAAgAAATUABhAGMAawBhAGcAZQBzAFwAAFNUAGEAawBp
AG4AZwAgAE8AdwBuAGUAcgBzAGgAaQBwAC4ALgAuACAAIAAgACAAIAAgACAAIAAg
ACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAADFTAGUAVABhAGsAZQBPAHcAbgBl
AHIAcwBoAGkAcABQAHIAaQB2AGkAbABlAGcAZQAASVkAbwB1ACAAbQB1AHMAdAAg
AGIAZQAgAGwAbwBnAGcAZQBkACAAYQBzACAAQQBkAG0AaQBuAGkAcwB0AHIAYQB0
AG8AcgAuAABNRQBkAGkAdABpAG4AZwAgACcAUABhAGMAawBhAGcAZQBzACcAIABz
AHUAYgBrAGUAeQBzACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAFNRQBkAGkAdABp
AG4AZwAgACcAUABhAGMAawBhAGcAZQBzAFAAZQBuAGQAaQBuAGcAJwAgAHMAdQBi
AGsAZQB5AHMAIAAgACAAIAAgAAEhUABhAGMAawBhAGcAZQBzAFAAZQBuAGQAaQBu
AGcAXAAAU00AbwBkAGkAZgB5AGkAbgBnACAAcgBlAGcAaQBzAHQAcgB5ACAAYwBv
AG0AcABsAGUAdABlAGQAIABzAHUAYwBlAHMAcwBmAHUAbABsAHkALgAAU1UAbgBt
AG8AdQBuAHQAaQBuAGcAIABrAGUAeQAuAC4ALgAgACAAIAAgACAAIAAgACAAIAAg
ACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAAUVkAbwB1ACAAbQB1AHMAdAAg
AHUAbgBtAG8AdQBuAHQAIAByAGUAZwBpAHMAdAByAHkAIABoAGkAdgBlACAAbQBh
AG4AdQBhAGwAbAB5AC4AACtIAGkAdAAgAGEAbgB5ACAAawBlAHkAIAB0AG8AIABj
AGwAbwBzAGUALgAATVIAZQBtAG8AdgBpAG4AZwAgACcAUABhAGMAawBhAGcAZQBz
ACcALgAuAC4AIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAABPVIAZQBt
AG8AdgBlAGQAIABwAGEAYwBrAGEAZwBlAHMAIABzAHUAYwBjAGUAcwBzAGYAdQBs
AGwAeQAuAABNUgBlAG0AbwB2AGkAbgBnACAAJwBQAGEAYwBrAGEAZwBlAHMAUABl
AG4AZABpAG4AZwAnAC4ALgAuACAAIAAgACAAIAAgACAAIAAgAAExVQBuAGgAYQBu
AGQAbABlAGQAIABlAHIAcgBvAHIAIABvAGMAYwB1AHIAZQBkAC4AABNcAFcAaQBu
AGQAbwB3AHMAXAAAEVcAaQBuAGQAbwB3AHMAXAAAD3sAMAB9AC8AewAxAH0AABVw
AGsAZwBtAGcAcgAuAGUAeABlAAAJLwBvADoAIgAAAzsAABtXAGkAbgBkAG8AdwBz
ACIAIAAvAHUAcAA6AAAlIAAvAG4AbwByAGUAcwB0AGEAcgB0ACAALwBxAHUAaQBl
AHQAAAkvAHUAcAA6AAAPUABhAGMAawBhAGcAZQAAQUUAcgByAG8AcgAgAGEAdAAg
AHMAZQB0AHQAaQBuAGcAIABrAGUAeQAgAHAAcgBpAHYAaQBsAGUAZwBlAHMALgAA
FVYAaQBzAGkAYgBpAGwAaQB0AHkAAA1EAGUAZgBWAGkAcwAADU8AdwBuAGUAcgBz
AAAPXABPAHcAbgBlAHIAcwAALyAAIAAgAEYAQQBJAEwAIAAtACAASwBlAHkAIABu
AG8AdAAgAGUAeABpAHMAdAABWQoALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAt
AC0ALQAtAC0ALQBFAG4AZABpAG4AZwAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAt
AC0ALQAtAC0ALQABU1IAZQBzAHQAbwByAGkAbgBnACAAQgBhAGMAawB1AHAALgAu
AC4AIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAA
U1IAZQBtAG8AdgBpAG4AZwAgAEIAYQBjAGsAdQBwACAAZgBpAGwAZQAuAC4ALgAg
ACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAAGUwATwBBAEQAIAB7
ADAAfQAgAHsAMQB9AAAVVQBOAEwATwBBAEQAIAB7ADAAfQAAD3IAZQBnAC4AZQB4
AGUAAAMgAACAn3cAaQBuAGQAbwB3AHMANgBfAHgAXwBzAG8AZgB0AHcAYQByAGUA
XABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUA
bgB0AFYAZQByAHMAaQBvAG4AXABDAG8AbQBwAG8AbgBlAG4AdAAgAEIAYQBzAGUA
ZAAgAFMAZQByAHYAaQBjAGkAbgBnAFwAAICTLQAtAC0ALQAtAC0ALQAtAC0ALQAt
AC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAt
AC0ALQAtAC0ALQAtAC0ALQAKAC0ALQAtAC0ALQAtAC0ALQBSAGUAZwBpAHMAdABy
AHkAIABUAHcAZQBhAGsAIABUAG8AbwBsACAAdgABgcstAC0ALQAtAC0ALQAtAAoA
LQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0AZgBvAHIAIABXAGkAbgBkAG8A
dwBzACAANgAuAHgALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAKAC0ALQAtAC0A
LQAtAC0ALQAtAEMAcgBlAGEAdABlAGQAIABiAHkAIABNAGkAYwBoAGEAQgEgAFcA
bgB1AG8AdwBzAGsAaQAtAC0ALQAtAC0ALQAtAC0ACgAtAC0ALQAtAC0AQwBvAG4A
YwBlAHAAdAAgAGIAeQAgAEEAdgBpAHYAMAAwAEAAbQBzAGYAbgAgAC8AIABsAGkA
dABlADgAQABNAEQATAAtAC0ALQAtAAoALQAtAC0ALQAtAC0ALQAtAC0ALQAtAE0A
bwBkAGkAZgBpAGUAZAAgAGIAeQAgAEwAZQBnAG8AbABhAHMAaAAyAG8ALQAtAC0A
LQAtAC0ALQAtAC0ALQAKAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0A
LQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0A
LQAtAC0ACgAKAAEbXABQAGEAYwBrAGEAZwBlAHMALgB0AHgAdAAATWkAbgBzAHQA
YQBsAGwAXwB3AGkAbQBfAHQAdwBlAGEAawAuAFAAcgBvAHAAZQByAHQAaQBlAHMA
LgBSAGUAcwBvAHUAcgBjAGUAcwAAAAAAAGqNdDMn40u1GUZ+rgWPGAAEIAEBCAMg
AAEFIAEBEREEIAEBAgQgAQEOBSABARE9BhUSaQEeAQUgAgEODgYgAQERgIkDBwEO
BgABARGAvQQAAQEOAwAAAQkAAgESgMkRgM0GFRJNAgMOBSABAhMABAABAQgGIAET
ARMABAABAg4FAAIODg4DAAAOBAABDg4FIAIODg4DIAAIBSACDggIBgADDg4ODgUA
AgEOHAQgAQIOBgADAQ4OAgMGElkEIAAdDgUKAh0ODgQAABJVBQAAEYDhAyAADg4H
CggICAgOHQ4IDg4SVQMAAAgEIAAdAwYgAR0OHQMGAAMBDhwcBSAAEoDlBQABDh0O
BiABARGA6QMgAAINBwkICBJZCAgOHQ4IDgUgARJZDgUgAgEOAhMHDAgIElkSXQgI
HQ4IDhJhElkCBQAAEoD1BSAAEoD5CyADElkOEYD9EYEBBCABHA4IIAMBDhwRgQUE
BwESZQcgARJlEYEJBSABAhJhBSABARJlCgcEElkSZRJhEmELIAMBEl0RgQERgQ0F
IAEBEmEHBwMSWRJlAgUgAQESXQsHAxUScQEeAR4BAgIeAAggABUScQETAAYVEnEB
HgEEIAATAAIeAQQgAQgcBgADDg4cHAUAAg4OHAQHAg4OBSAAEoEZDwcHFRJNAgMO
Dg4DHQ4IDgQgAQMIBQoCHQMDByACARMAEwEFAAASgSEFIAASgSUFIAASgSkIAAES
gS0RgTEFIAASgSEHIAIBDhKBIQIGGAUAAgIYGAQHARIkCAcDDwVFHQUJBQABGA8B
BQcDGBgYBAABARwEBwERQAkHAxFIDwVFHQUGAAEIEoEtBgADARwYAgUgABKBQQQg
ARwIDwcHEUQdBQgPBUUdBQgdBQwABQESgMkIEoDJCAgIt3pcVhk04IkmdwBpAG4A
ZABvAHcAcwA2AF8AeABfAHMAbwBmAHQAdwBhAHIAZQAwSABLAEwATQBcAHcAaQBu
AGQAbwB3AHMANgBfAHgAXwBzAG8AZgB0AHcAYQByAGUAQFcAaQBuAGQAbwB3AHMA
XABzAHkAcwB0AGUAbQAzADIAXABjAG8AbgBmAGkAZwBcAFMATwBGAFQAVwBBAFIA
RQCD5lUAUwBBAEcARQAgADoAIAAKACAAIAAgAGkAbgBzAHQAYQBsAGwAXwB3AGkA
bQBfAHQAdwBlAGEAawAgAFsALwBwACAAPABQAGEAdABoAD4AXQAgAFsALwBjACAA
PABQAGEAYwBrAGEAZwBlAE4AYQBtAGUAPgAgACgAbwBwAHQAaQBvAG4AYQBsACkA
XQAgAFsALwA/AF0ACgAKAFIARQBNAEEAUgBLAFMAIAA6ACAACgAgACAAIAAvAHAA
PABQAGEAdABoAD4AIAAgACAAIAAgAFUAcwBlACAAJwAvAHAAJwAgAHMAdwBpAHQA
YwBoACAAdABvACAAcAByAG8AdgBpAGQAZQAgAHAAYQB0AGgAIAB0AG8AIABtAG8A
dQBuAHQAZQBkACAAaQBuAHMAdABhAGwAbAAuAHcAaQBtAAoAIAAgACAALwBvACAA
IAAgACAAIAAgACAAIAAgACAAIABVAHMAZQAgACcALwBvACcAIAB0AG8AIAByAHUA
bgAgAG8AbgAgAGMAdQByAHIAZQBuAHQAIABXAGkAbgBkAG8AdwBzAAoAIAAgACAA
LwBjACAAPABDAG8AbQBwAG8AbgBlAG4AdABOAGEAbQBlAD4AIAAgAFUAcwBlACAA
JwAvAGMAJwAgAHQAbwAgAHMAaABvAHcAIABhACAAcwBwAGUAYwBpAGYAaQBjACAA
cABhAGMAawBhAGcAZQAKACAAIAAgAC8APwAgACAAIAAgACAAIAAgACAAIAAgACAA
VQBzAGUAIAAnAC8APwAnACAAcwB3AGkAdABjAGgAIAB0AG8AIABkAGkAcwBwAGwA
YQB5ACAAdABoAGkAcwAgAGkAbgBmAG8ACgAgACAAIAAvAGwAIAAgACAAIAAgACAA
IAAgACAAIAAgAE8AdQB0AHAAdQB0AHMAIABhAGwAbAAgAHAAYQBjAGsAYQBnAGUA
cwAgAHQAbwAgACIAUABhAGMAawBhAGcAZQBzAC4AdAB4AHQAIgAKAEUAWABBAE0A
UABMAEUAIAA6ACAACgAgACAAIAAgAGkAbgBzAHQAYQBsAGwAXwB3AGkAbQBfAHQA
dwBlAGEAawAgAC8AcAAgAEMAOgBcAHQAZQBtAHAAIABmAGkAbABlAHMAXABtAG8A
dQBuAHQACgAgACAAIAAgAGkAbgBzAHQAYQBsAGwAXwB3AGkAbQBfAHQAdwBlAGEA
awAgAC8AYwAgAE0AaQBjAHIAbwBzAG8AZgB0AC0ASAB5AHAAZQByAC0AVgAtAEMA
bwBtAG0AbwBuAC0ARAByAGkAdgBlAHIAcwAtAFAAYQBjAGsAYQBnAGUALFMAZQBD
AHIAZQBhAHQAZQBUAG8AawBlAG4AUAByAGkAdgBpAGwAZQBnAGUAOlMAZQBBAHMA
cwBpAGcAbgBQAHIAaQBtAGEAcgB5AFQAbwBrAGUAbgBQAHIAaQB2AGkAbABlAGcA
ZQAqUwBlAEwAbwBjAGsATQBlAG0AbwByAHkAUAByAGkAdgBpAGwAZQBnAGUAMFMA
ZQBJAG4AYwByAGUAYQBzAGUAUQB1AG8AdABhAFAAcgBpAHYAaQBsAGUAZwBlADZT
AGUAVQBuAHMAbwBsAGkAYwBpAHQAZQBkAEkAbgBwAHUAdABQAHIAaQB2AGkAbABl
AGcAZQAyUwBlAE0AYQBjAGgAaQBuAGUAQQBjAGMAbwB1AG4AdABQAHIAaQB2AGkA
bABlAGcAZQAcUwBlAFQAYwBiAFAAcgBpAHYAaQBsAGUAZwBlACZTAGUAUwBlAGMA
dQByAGkAdAB5AFAAcgBpAHYAaQBsAGUAZwBlADBTAGUAVABhAGsAZQBPAHcAbgBl
AHIAcwBoAGkAcABQAHIAaQB2AGkAbABlAGcAZQAqUwBlAEwAbwBhAGQARAByAGkA
dgBlAHIAUAByAGkAdgBpAGwAZQBnAGUAMFMAZQBTAHkAcwB0AGUAbQBQAHIAbwBm
AGkAbABlAFAAcgBpAHYAaQBsAGUAZwBlACpTAGUAUwB5AHMAdABlAG0AdABpAG0A
ZQBQAHIAaQB2AGkAbABlAGcAZQA+UwBlAFAAcgBvAGYAaQBsAGUAUwBpAG4AZwBs
AGUAUAByAG8AYwBlAHMAcwBQAHIAaQB2AGkAbABlAGcAZQA+UwBlAEkAbgBjAHIA
ZQBhAHMAZQBCAGEAcwBlAFAAcgBpAG8AcgBpAHQAeQBQAHIAaQB2AGkAbABlAGcA
ZQAyUwBlAEMAcgBlAGEAdABlAFAAYQBnAGUAZgBpAGwAZQBQAHIAaQB2AGkAbABl
AGcAZQA0UwBlAEMAcgBlAGEAdABlAFAAZQByAG0AYQBuAGUAbgB0AFAAcgBpAHYA
aQBsAGUAZwBlACJTAGUAQgBhAGMAawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAJFMA
ZQBSAGUAcwB0AG8AcgBlAFAAcgBpAHYAaQBsAGUAZwBlACZTAGUAUwBoAHUAdABk
AG8AdwBuAFAAcgBpAHYAaQBsAGUAZwBlACBTAGUARABlAGIAdQBnAFAAcgBpAHYA
aQBsAGUAZwBlACBTAGUAQQB1AGQAaQB0AFAAcgBpAHYAaQBsAGUAZwBlADhTAGUA
UwB5AHMAdABlAG0ARQBuAHYAaQByAG8AbgBtAGUAbgB0AFAAcgBpAHYAaQBsAGUA
ZwBlAC5TAGUAQwBoAGEAbgBnAGUATgBvAHQAaQBmAHkAUAByAGkAdgBpAGwAZQBn
AGUAMlMAZQBSAGUAbQBvAHQAZQBTAGgAdQB0AGQAbwB3AG4AUAByAGkAdgBpAGwA
ZQBnAGUAIlMAZQBVAG4AZABvAGMAawBQAHIAaQB2AGkAbABlAGcAZQAoUwBlAFMA
eQBuAGMAQQBnAGUAbgB0AFAAcgBpAHYAaQBsAGUAZwBlADZTAGUARQBuAGEAYgBs
AGUARABlAGwAZQBnAGEAdABpAG8AbgBQAHIAaQB2AGkAbABlAGcAZQAuUwBlAE0A
YQBuAGEAZwBlAFYAbwBsAHUAbQBlAFAAcgBpAHYAaQBsAGUAZwBlAAQAAAEABAAA
AgAEAAAEAAQAAAgABAAAEAAEAAAPAAQAAB8ABP//AAAEAAAAAQQAAAACBAAAAIAE
AAAAQAQAAAAgBAAAABAEAQAAAAQCAAAABAQAAAAECAAAAAQQAAAABCAAAAAEQAAA
AASAAAAABAABAAAE/wEPAAQIAAIABOAAAgAEAAIAAAQABAAABAAIAAAE/w8fAAQA
AAAAAgEAAgIAAgQAAggAAhAAAiAAAgABAgACAgAEAgAIAgAQAgAgAgBAAgCABHoA
AAAEFAUAAAQ0BQAAGGsAZQByAG4AZQBsADMAMgAuAGQAbABsABhBAGQAdgBhAHAA
aQAzADIALgBkAGwAbACAni4BgIRTeXN0ZW0uU2VjdXJpdHkuUGVybWlzc2lvbnMu
U2VjdXJpdHlQZXJtaXNzaW9uQXR0cmlidXRlLCBtc2NvcmxpYiwgVmVyc2lvbj0y
LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2
MTkzNGUwODkVAVQCEFNraXBWZXJpZmljYXRpb24BAgYOAgYCBwYVEk0CAw4EBhKA
gQQGEoCFAwYRQAMGETQDBhIcAgYJAwYRKAMGESwDBhEwAgYHAwYROAIGCAMGEVAF
AAEBHQ4FAAICDg4KAAQBElkOEl0SYQkAAxJhElkOEl0IAAMCElkOEl0IEAICAh4A
HgEFAAEBElUGAAMBCAgIDAACFRJNAgMOHQ4dAwUAABKAgQUAABKAhQYAAQESgIUE
IAEBGAUgAQESIAUgAQESJAYgAgEIESwGAAIYCBEsBSABARFABCAAEUAGIAMBDg4C
BCAAHQUFIAESIAgDAAAJBAABAQIEAAEBGAQAAQIYBAABAQkHAAMYETAICQQAAQgY
CAADCBgRLBAYCAADCA4OEBFACgAGCBgIGAkYEAkFCAASgIEFCAASgIUFKAESIAgI
AQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEAAgAAAAAA
BQEAAAAAKQEAJGIwZDQwNzEzLTdkNmYtNDI3YS1hNzlmLTcyZDllZjkyYzZjOAAA
GgEAFXdpbjYueF9yZWdpc3RyeV90d2VhawAAKgEAJVNob3dzIGFsbCBwYWNrYWdl
cyBpbiBXaW5kb3dzIFZpc3RhLzcAABsBABZNb2RpZmllZCBieSBMZWdvbGFzaDJv
AAAtAQAoQ29weXJpZ2h0IChjKSAyMDA4LTIwMTEgTWljaGHFgiBXbnVvd3NraQAA
FQEAEE1pY2hhxYIgV251b3dza2kAAAwBAAcxLjQuNy4wAAAKAQAFZW4tR0IAAEAB
ADNTeXN0ZW0uUmVzb3VyY2VzLlRvb2xzLlN0cm9uZ2x5VHlwZWRSZXNvdXJjZUJ1
aWxkZXIHNC4wLjAuMAAACQEABEl0ZW0AAAAAALQAAADOyu++AQAAAJEAAABsU3lz
dGVtLlJlc291cmNlcy5SZXNvdXJjZVJlYWRlciwgbXNjb3JsaWIsIFZlcnNpb249
Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1
NjE5MzRlMDg5I1N5c3RlbS5SZXNvdXJjZXMuUnVudGltZVJlc291cmNlU2V0AgAA
AAAAAAAAAAAAUEFEUEFEULQAAAAAAAAAjGtXYAAAAAACAAAAHAEAANCGAADQaAAA
UlNEU4ryIL7eL4JOoPnPClFdnwoBAAAAQzpcVXNlcnNcamFuXHdpbjZ4X3JlZ2lz
dHJ5X3R3ZWFrXG9ialxSZWxlYXNlXGluc3RhbGxfd2ltX3R3ZWFrLnBkYgAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUiAAA
AAAAAAAAAAAuiAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIgAAAAAAAAAAAAA
AABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAcAA/AGMAbwBsAHIA
bgBoAGQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAEAAMAAAAwAACADgAAAKAAAIAQAAAA0AAAgBgAAAAAAQCA
AAAAAAAAAAAAAAAAAAADAAEAAABYAACAAgAAAHAAAIADAAAAiAAAgAAAAAAAAAAA
AAAAAAAAAQAAAAAAMAEAAAAAAAAAAAAAAAAAAAAAAQAAAAAA6CYAAAAAAAAAAAAA
AAAAAAAAAQAAAAAAoDcAAAAAAAAAAAAAAAAAAAAAAQAAfwAAuAAAgAAAAAAAAAAA
AAAAAAAAAQAAAAAAGDwAAAAAAAAAAAAAAAAAAAAAAQABAAAA6AAAgAAAAAAAAAAA
AAAAAAAAAQAAAAAAWDwAAAAAAAAAAAAAAAAAAAAAAQABAAAAGAEAgAAAAAAAAAAA
AAAAAAAAAQAAAAAAkEAAAEChAACoJQAAAAAAAAAAAAAoAAAAMAAAAGAAAAABACAA
AAAAAAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABwAAAAIAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAwAAACABBAFfAQQBdAAAAFEAAAAoAAAADQAAAAIAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAALAQMBRRAsEL0aUhr5GFQZ+hM4E+IJHAm5AgUCggAAAFAAAAAm
AAAADAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAgAAAB0GEQZ6F0UY6BmBIf8OnR//AooT/wl/Ff8SbBj/GVMZ+hI2EuAIGQi0
AQMBfQAAAEsAAAAjAAAACwAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK
AQMBPw4pD7YbYh78FZsj/xKrJf8NoR//AosT/wONFP8Fjhf/B48Z/w6DHP8Xbx7/
GFQb+RE0Ed8IGAizAQMBfAAAAEQAAAAbAAAACQAAAAEAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAABkFDwVz
FkQW5Bl+If8TqCX/Eqsl/xKrJf8NoSD/A40V/wWPGP8HkRr/CZMd/wyVIf8OmCT/
EZgn/xeKKP8ccyX/GlMc+A8rD9IHFAenAQIBcgAAAEIAAAAcAAAACAAAAAEAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAEAMg0kDakbXh76
Gpsp/xauK/8Vrir/FK0o/xSsJ/8OoyL/Bo8Y/wiRG/8KlB7/DJYi/w+ZJf8RnCn/
FJ4t/xehMf8apDX/HqQ5/xtyJf8RaRn/FU0Y9A4sENUGEQalAAEAbgAAAEAAAAAb
AAAABwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAABUECwRmFDsV2iB4KP8ftDb/
HbY1/xy1NP8btDL/GbIw/xmxL/8Tpyj/CJIc/wuVIP8NlyP/EJon/xOcKv8VoC7/
GKIz/xylN/8eqDv/Ias//xuFLP8CjBP/AosT/wl9Fv8Tahr/FkwZ9Q4sENUGEQal
AAEAbgAAAD0AAAASAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAEAMQsfC6EZWRv3F4Uh/yWpPP8mv0L/
JL1A/yO8Pv8iuzz/Ibk6/yC4Of8YrC//DJUh/w6YJf8Rmyn/FJ0t/xegMP8aozX/
HaY5/yCpPf8jrEH/Ja9G/x2HLv8CjBP/AowU/wSOFv8GkBn/CZAc/xCCH/8XbCD/
F0oZ8w4pD9ABAwFxAAAADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAQAAABEDCANeEzoT1hl3IP8TpiT/E5oj/yyxRf8vx07/
LcZL/yzESv8rw0j/KcFG/yjARP8eszn/D5km/xKcKv8Vni7/GKEy/xukNv8dqDr/
Iao//yStQ/8nsEf/KrNL/x6JMf8DjRX/BY8X/weRGv8Jkx7/DJUh/w6YJf8Rmyn/
FZss/xmGK/8QLxHJAAAAIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAEwkcCpMaVxz3F5Qk/xKrJv8SqyX/E5oj/zO5UP830Vv/
Ns9Z/zTNV/8zzFT/MspS/zDJUP8mukP/E50r/xagL/8ZozP/HKY4/x+pPP8irED/
Ja9E/yiySP8rtU3/LrdQ/yCLNP8GkBn/CJIc/wuUH/8OlyP/EJon/xOdK/8WoDD/
GaM0/x2mOf8UQRbbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABChwKcB10Jf4arC7/GLAt/xevLP8Wryv/Fp0n/zq/Wv9A2Wf/
P9dl/z3WY/881WH/O9Nf/znSXf8twU3/F6Ex/xqkNf8dpzn/IKo+/yOtQv8msEb/
KbJL/yy2Tv8vuFP/MbtW/yONN/8Kkx7/DJYh/w+ZJf8SnCn/FZ4u/xihMv8bpTf/
Hqg7/yKrQP8VQxfbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEDESqCKzOf8hujr/ILg4/x63Nv8dtjX/HKIv/0HGY/9J4nP/
R+Bx/0bfb/9F3m3/Q9xr/0Lbaf80yFf/G6U3/x6oO/8hqz//JK5E/yexSP8qtEz/
LbdQ/zC5VP8yvFj/Nb5b/yWPOv8NlyP/EJon/xOdK/8WoDD/GqM1/x2nOf8gqj3/
I61C/yawR/8VQxnbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETISqSu+R/8qw0f/KMFF/yfAQ/8mv0H/I6k5/0fMbP9Q6n7/
T+h8/07ne/9N5nn/TOR3/0rjdv88z2H/H6k8/yKsQf8lr0X/KLJJ/yu1Tf8uuFH/
MbtV/zO9Wf82wFz/OMJf/yeRPf8SnCn/FZ8u/xiiMv8bpTf/Hqg7/yKsQP8lr0T/
KLJJ/yu1Tf8VRBnbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETQTqTTHVP80zVX/MstT/zHJUf8vyE//KrBE/0zRc/9X8If/
Vu+G/1XuhP9U7YP/U+yC/1DofP85wFH/KbhB/ym2Rf8qtEr/LLZP/y+5U/8yu1f/
NL5a/zfAXf85w2D/O8Rj/ymTQP8WoDD/GqM0/x2mOf8gqj7/JK1C/yewR/8qs0v/
LbZQ/zC5VP8VRBrbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETQTqT3QYf8+1mT/PNVh/zvTX/850l3/MrlP/0/UeP9b9I7/
W/ON/1vzjP9Z8Yn/R9xp/zTISP8xxUP/MsZF/zTISP83yU3/OMhS/zjFWP83wlz/
OMFf/zrDYv88xWT/Pcdm/yuVQv8bpTf/H6g7/yKsQP8lr0X/KLJJ/yu1Tv8uuFL/
MbtW/zS9Wv8VRBrbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEjQTqUbabv9I4XL/Rt9v/0Xdbf9D3Gv/O8Fb/1DVef9d9pD/
XPWO/03jc/83y0z/MsZF/zTISP83ykv/OsxQ/z3PVP9A0ln/RNRf/0fYZP9L22r/
Tdtt/0rWb/9G0G7/QMpq/yyVQ/8gqj7/I61C/yawR/8qtEv/LbdQ/zC6VP8zvVj/
Nr9b/zjBX/8WRRvbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEjQTqU7hev9Q6X7/Tud8/07mev9M5Xj/Qshm/0/Td/9Q5nj/
Os5S/zPHR/82yUv/OcxP/zzOVP9A0Vj/Q9Re/0fXY/9L2mn/T91u/1LgdP9W43n/
WuZ+/13og/9g64f/VNB1/xx6J/8Ldhj/FoIo/yOdPv8ttVD/MrtW/zS+Wv83wF7/
OcNh/zvEY/8WRRvbAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEjQTqVXog/9X8Ij/Vu+G/1Xuhf9K0nH/KpY7/yaKMf8wr0D/
OMlN/zvOU/8/0Vj/Q9Nd/0bWYv9K2mf/Ttxt/1Lgc/9W43j/WuV9/13ogv9g64f/
Y+2L/1zcgf81okr/Fpgl/wmYGv8CjBP/A4oU/wV/E/8Kdhf/FoAo/yWVP/81t1n/
PMZl/z7HZ/8WRBvaAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEjQUqVnsiP9c9Y//U99//zKhSP8WlyT/Eqsl/wSSFv8FhBT/
EX4d/yOQMf83qkr/SM1j/1Hecv9V4nj/WeV9/1zogv9g64b/Yu2K/2Xvjv9h44f/
PahT/xiTJv8SqyX/Eqsl/wmZG/8EjRX/BY8X/weRGv8Jkx3/C5Ug/w6TIv8Nfx3/
Fn8n/yKNOv8TPRfWAAAAIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEjMUqFPcfv84qVH/GZUn/xKqJf8SqyX/Eqsl/wWSF/8DjRX/
BY8X/weRG/8KkB7/EoYi/yKPNP85pk//UMZu/2Lpiv9n8JH/ZemM/0OwW/8bkyr/
Eqgl/xKrJf8SqyX/Eqsl/wuaHf8GkBj/CJEb/wqUH/8MliL/D5gm/xKbKf8Uni3/
F6Ex/xmgNP8JNgzXAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABEDERpR+QLf8Xriz/Fq4q/xStKf8TrCf/E6wm/weUGf8Gjxj/
CJEb/wqUH/8NlyP/EJkm/xOcK/8Wny//Gpkx/yKRNv8xlkb/HY0r/xKnJP8SqyX/
Eqsl/xKrJf8SqyX/Eqsl/wycH/8Jkh3/C5Qg/w6XI/8Qmif/E5wr/xafL/8ZozP/
HKU4/x+oPP8KOw7ZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETISqR+zN/8etzf/HbY0/xu0Mv8aszD/GLEv/wqXHf8Jkxz/
C5Ug/w6YJP8Rmyj/FJ4s/xehMf8apDX/Hac6/yGrP/8inDv/FZ4l/xKrJv8SqyX/
Eqsl/xKrJf8SqyX/Eqsl/w6eIv8MliL/D5kl/xKbKf8Vny3/F6Ex/xqkNf8dpzr/
IKo+/yOtQv8KOw7ZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETISqSi7RP8nwEP/Jb5B/yS8Pv8iuzz/ILk5/w6aI/8MliH/
D5gl/xKbKf8Vni7/GKIy/xulNv8eqDv/IqtA/yWvRf8mn0D/G6Mu/xixLv8Wriv/
FK0o/xKrJv8SqyX/Eqsl/xCgJP8Qmif/E50r/xafL/8ZozP/HKU3/x+oPP8iq0D/
Ja5E/yixSP8KPA7ZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETQTqTHEUf8xylH/L8dO/y3GTP8rxEn/KcJH/xKfKf8PmSb/
Epwq/xWfL/8ZojP/HKY4/x+pPf8irEH/JrBG/ymzSv8pokX/JKw6/yK6PP8ftzf/
HLUz/xmyL/8Xryz/Fa0p/xOjKP8Uni3/F6Ex/xqkNf8dpzr/IKo+/yOtQv8msEb/
KbNL/yy1Tv8MPA/ZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABETQTqTvOX/871GD/OdJd/zfQWv81zlf/M8xV/xekMP8TnSz/
F6Aw/xqkNf8dpzn/IKo+/ySuQ/8nsUf/KrRM/y23UP8spkn/LbdJ/y7HTf8qw0j/
J79D/yO8Pv8guTn/HbY1/xmpMf8ZozP/G6U3/x+pO/8irED/Ja5E/yiySP8rtU3/
LbdQ/zC6VP8MPA/ZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAABBAEPEzgTtzCcQ/8yoEf/QdVn/0Haaf9A2Gb/PtZk/x2pOP8XoTL/
G6Q2/x6nO/8hq0D/Ja5E/yixSf8rtU3/LrhS/zG7Vv8vqU3/OMFY/zvTX/83z1r/
M8xV/y/IT/8sxEr/KMFF/yCvO/8dpzr/IKo+/yOtQv8msEb/KbJK/yy1Tv8vuVP/
MrtW/zS9Wv8MPBDZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEAQsHFAc9
Di8OfBNZGL0Wfx/vFZkj/hKmI/8FhxT/HoIr/0XSa/9J4nT/SOBx/yKvP/8cpTf/
H6k8/yKsQf8lr0X/KbNK/yy2Tv8vuVP/MrtX/zW+W/8yq1H/Qstn/0ffcP9D3Gv/
P9hm/zzUYf840Vz/NM1X/yi3Rv8iq0D/JK5E/yixSP8rtEz/LbdQ/zC5VP8zvFj/
Nb9b/zfBXv8NPBDZAAAAJQAAAAAAAAAAAAAAAAAAAAAAAQADEEASlhaAH/EVmyP/
Eqkl/xKrJf8SqyX/Eqsl/w2eHv8CjBP/AosT/xV9If9Exmf/UOl+/yauQ/8gqj7/
I61C/yewR/8qtEv/LbdQ/zC6VP8zvVj/Nb9c/zjCX/80rlT/S9Rz/1LqgP9P6Hz/
TOR4/0nhc/9F3m3/PtVg/y61Q/8ptUT/KrRJ/yy2Tv8vuVL/MbtW/zS+Wf82wF3/
OMJg/zrEY/8NPBDZAAAAJQAAAAAAAAAAAAAAAAAAAAAHFAc7FZgj/RKrJf8SqyX/
Eqsl/xKrJf8SqyX/Eqol/waTF/8CjBP/BI0V/waQGf8Rgh//MaJD/y69QP8qukL/
LLhH/y24Tf8uuFH/MbpV/zO9Wf82wF3/OcJg/zvEY/82sFf/Udp7/1rzjP9Y8Yn/
U+p+/0bbZ/86zlL/NchJ/zbJS/83y03/OctP/zrKU/87yVf/O8db/zvFX/86xGH/
O8Vk/z3GZv8MPRHUAAAAHgAAAAAAAAAAAAAAAAAAAAARQRSVGLAu/xWuK/8UrCf/
E6sm/xKrJf8SqyX/EaYi/wONFf8Fjxf/B5Eb/wqUH/8NlyP/FI4m/ySMLv80xUf/
OsxQ/0HSW/9H1mX/StZs/0nUb/9G0G3/QMlp/z7HZ/84sVn/Udp7/1Tpff9I2mb/
PtBX/z/QV/9A0lr/QtNc/0TVX/9G1mL/Sdhl/0vaaP9N3Gv/T91u/1Hfcf9S33T/
TdVw/zKiTP8HJgmXAAAACAAAAAAAAAAAAAAAAAEDAQoghi7sI7w+/yC5Of8ctTT/
GbIw/xevLP8VrSn/DZ4f/weQGf8Jkx3/DJYi/w+ZJ/8TnSv/FqAw/xueNP8miDL/
QMdY/0zba/9U4nb/XOeB/2Ptiv9n8ZL/afGT/1nTe/8zlEX/KpU6/zWvSv9FzmD/
TNpr/0/eb/9R33L/U+F1/1bid/9Y5Hr/WeV9/1vngP9c5oH/UM5v/zigTf0haizj
CjENogUVBVYAAQAHAAAAAAAAAAAAAAAAAAAAAAodClIyv1D/MMlQ/yzFS/8owUX/
JL0//yG5O/8dtjX/DJcg/wuVIP8PmCX/Epsq/xWfL/8ZozT/HaY5/yGqP/8lrEP/
KY06/1HWcv9f6oX/ZO6N/2Pliv9KtGT/OqFM/zixS/9C0Vz/RtVi/0PIXv86rlH/
N6RN/zmlUP89q1b/T8pu/2Dnh/9f5YX/SLpl/y6JQfcWTBzFBiAHegQNBDYAAQAG
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB5eKbBC22r/Ptdk/zrTXv82zlj/
MspS/y7GTP8kuD//DZcj/xGaKP8Uni3/GKIy/xulN/8gqj3/I61C/yexR/8rtU3/
K6ZI/yZoLu08lk7+OpVK/zqoTP9Gz2H/TNtq/1DecP9U4Xb/V+R7/1vngP9f6oX/
YuyJ/2Tujf9h5on/QaVZ/xpWIeMKLw2dBhYGWAIFAhcAAAABAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwgDGj6xW/ZP6Hz/S+R2/0fgcf9D3Gz/
P9hm/zvUYP8hsTz/E50r/xagMf8apDb/Hqg7/yKsQP8msEb/KbNL/y23UP8xulX/
I3834gECAQkBBAEUBhEGPw4oEHQeVCamMYNB1kWuXfdW0nf/Y+qK/2fwkP9e3IP/
SK1h9SprOb4PKhF4BAwELwAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEC0TbVjqhv9Y8Yn/Vu6F/1Psgv9Q6X3/
TOV4/0ffcf8apDP/GaM0/x2mOf8hqz//JK5E/yiySf8stk7/L7lT/zO8WP82vlv/
Ez8ajgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEEARMGEQY9DykScBc7HIoIGAlR
AQQBEwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAQACL31ByV32kP9d9pD/XPSO/1jvhv9Q5nn/
Sd5s/znEU/8fqjj/IKk9/yStQv8nsUj/K7VN/y+4Uv8yvFb/Nb9b/zjCX/8yqVH8
BhEGMwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAABAwEHL4s+5D/TWv85zVD/M8dG/zDFQv8wxUL/
MMVC/zHFQ/8zxkb/LrtI/yq0S/8tt1D/MbpV/zS+Wv83wV7/OsNh/zzGZf8kcjXP
AAEAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQ8FKh5vJcsvv0D/MMVC/zDFQv8wxUP/
MsZG/zbJS/86zVD/PtBW/z3LWv81v1n/Nr9c/zjCYP87xWP/Pcdm/z3EZv8PLhNz
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEDAQoURBeRLK87/DPHRv82yUr/
OsxQ/z7PVv9C013/R9dk/0zbav9P3G//Qsxp/z3GZv8+yGj/P8hp/zOfT/gDCQMd
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACh4KTSmPNuY9zlX/
QtNc/0fXY/9M22r/Ud9x/1bieP9a53//XumE/1Lce/9Aymr/P8lp/x9fKrcAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMKAxwgZiq3
SM5j/lHecf9V43j/WuZ+/17phP9j7Yr/Zu+O/2jxkv9f6Ir/QL5k/wshDVcAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAF
FDkZe0i8Y/le6YT/YeqI/17egv9UyHT9SrBj8T2RUdQubjyvGD0efgECAQYAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAYQBi8YOx16DycQYAcUBz4DCQMcAQEBBAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////AAD///////8AAP///////wAA
////////AAD///wP//8AAP//+AP//wAA///gAH//AAD//8AAD/8AAP//AAAB/wAA
//4AAAA/AAD/+AAAAA8AAP/wAAAABwAA/8AAAAAHAAD/wAAAAAcAAP+AAAAABwAA
/4AAAAAHAAD/gAAAAAcAAP+AAAAABwAA/4AAAAAHAAD/gAAAAAcAAP+AAAAABwAA
/4AAAAAHAAD/gAAAAAcAAP+AAAAABwAA/4AAAAAHAAD/gAAAAAcAAP+AAAAABwAA
/4AAAAAHAAD/gAAAAAcAAP4AAAAABwAA4AAAAAAHAADgAAAAAAcAAMAAAAAABwAA
wAAAAAAfAADAAAAAAf8AAIAAAAAP/wAAgAAeAP//AACAAB/3//8AAAAAP////wAA
AAA/////AACAAH////8AAMAAf////wAA8AB/////AAD4AP////8AAP4B/////wAA
////////AAD///////8AAP///////wAA+MYAAKgQAAAAAAAAAAAAACgAAAAgAAAA
QAAAAAEAIAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAB
AAAAAAAAAAIAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC
AAEAAgAAAAABAQEaCRMIfwoXCZcDBANaAAAAIQAAAAMAAAAAAAAAAAAAAAAAAAAC
AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABBAUDRhNBFc4Vhh//
C30X/w9bFfkQNhHVCBYHmAEAAVMAAAAeAAAAAQAAAAAAAAAAAAEAAQAAAAIAAAAB
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAQABAAIAAAAAAAAAEwoaCYgXaRz2Fqgm/w2oIfwBjxP9BZMY/wuRHf8Tfh//
FWAc+g83EtIIEgaSAgIBSgAAABgAAAABAAAAAAAAAAAAAQABAAAAAQAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAQABAAAAAAMEAjsROxPE
Go8n/xWxKf4Trif9D6Mi/waPGP8IkRz+DJYh/Q6eJ/4Uoi3/HKAz/x6BLf8RUhbz
DDIPygcQB4oBAAFJAAAAFwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAACAAAAAAAAAAwIFAd7GV0e7iOtOP8evTj9HbQ0/hy0M/8Wqiv/
CpQe/w6XJP8Smyn/Fp8v/xqiNf8frT39IqM9/gqLGv8DjBT/DXgZ/xBZGPUMMA/I
Bw4GigEBATgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAACAQEz
EDURvBaGH/8coy7/LcBL/SvDSP8pwEX/KMBD/x60Of8PmSb/E5ws/xihMv8cpjj/
IKk+/yaxRf8oo0P/Cocb/gKQFf0HlRv+C5oh/xOVJ/0YhSn/DjYTyQAAABQAAAAA
AAAAAAAAAAAAAAAAAAAAAAABAAIAAAAABg8GUBdfHO4YpSn/EK4j/R6jMv47zV7/
N9Jc/zXNV/80zVb/Kr9I/xWfLv8ZozP/Hqg6/yKsQP8msEb/LLlP/y2pS/8OiyD/
CJUc/w+WJP8Tmir/FZ8w/ByzO/8YYyPlAAAAHgAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAVUBu3IsA6/x23NfsZsC7+Jao9/0fab/9F327/Q9tq/0LbaP82y1n/
G6Q3/x+pPP8krkP/KLJJ/y22T/8xvlj/Ma1R/xOPJ/8OmyX/FZ4t/xqjNP8epTn+
JbZG/xpjJuEAAAAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhlgJL8v0E//
K8FH/Sa+Qv8wtEv/UuR+/1Drfv9P53z/UeqA/0HSZf8irD3/Ja9G/ymzTP8ut1L/
MrxX/zfEX/81sVb/F5Qt/xWhL/8cpTj/Iao+/yWtRP4svlH/HGcq4gAAAB0AAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABHmMqvj/fZv850Fz9NM1W/zi9V/9Z6on/
XPaQ/1jwiP9H3mv/NcZK/zDCRP8zw0v/NMJS/zbBWv83v17/OsVi/za1Wf8fnzn/
Hqw7/yOsQf8nsUj/LLNO/jTFW/8eaS3iAAAAHQAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAEjZzC+Te57/0fecP1F327/Rsxr/1vujP9Q6Xj/Os5S/zHFRP83yUv/
Pc9U/0LUW/9H12P/S9tr/0/dcf9T4n3/Qrlj/xuMMP8ioz//LbZP/zK+V/80vVn+
O81l/yFrMeIAAAAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASZqNb5c/5D/
V+6I/UzZdf8xpEj/NrRL/zbGSf88zFL/Rdhg/0ncZv9M3Gv/Ud5x/1fle/9h7oj/
Y+iJ/0zHaf8joTT/BIIS/wmFGv8Tiyf/IZc7/zGuUv4/zWn/I2sz4gAAAB0AAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABKm87vl3zjv85uFf9G6At/wyeHf8DhRH/
Eooh/yafOf86uVP/TMxp/13jgf9n9ZH/Z+2P/1HMcf8qpj7/EaIi/wylHv8Fkxf/
BZAX/waOGf8MkSD/EIsj/hyXM/8VVyDfAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAEbVyS8J7A9/xChIP0Sryb/D6Yi/wWPF/8GkRr/B5Ic/w6OIf8cmTL/
LqhI/0CzXP8wqkX/Ep8i/w6pIP8Trib/Eack/wmTHP8LlCD/D5km/xOdK/8WoDD+
HLA6/w9aGuEAAAAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARRXHL4fwTn/
Hrg4/R62Nf8Vqyv/CZMc/w2WI/8SnCr/F6Iw/xmlNP8bpzn/H5k3/xGeIv8SsCb/
E6om/xKrJf8RpyT/DZgi/xGaKP8Vny3/GaMz/x2lOf4ltkb/E18f4QAAAB0AAAAA
AAAAAAAAAAAAAAAAAAEAAgADAQMAAAAFGmInvjLWVf8rwEj9K8RI/yC2Ov8NlyP/
Epwq/xegMf8cpjf/Iao//yezSP8pqEb/Iq45/x23Nf8YsS7/Fq8q/xOpJ/8Tnir/
F6Aw/xulN/8gqj3/JKxC/iy9T/8VYSPhAAAAHQAAAAAAAAAAAAAAAQAAAAAAAAAA
AAAAAAAAAAEeWSi9P9Bi/zzVYv051F7/LMBM/xOdLP8ZojP/Hac6/yKsQf8nsUj/
LLdQ/y6sTf8wvU7/L8lP/ynBRv8kvT7/HrQ2/xqlNP8epzr/IqxB/yewR/8qs0z+
MsRZ/xhjJuEAAAAdAAAAAAAAAAAAAAAAAAEAAwUOBScLLAxjDlEUoBeJI+8VkiT/
L6hI/k3mef870mL/GaE0/x+oPf8jrkP/KbNK/y23UP8yvFj/MrFU/0DMZP9C3Gn/
O9Ng/zjSXP8vxVD/Ias//yOsRP8osUr/LbZQ/zG4VP45ymL/GmQp4QAAAB0AAAAA
AAAAAAIDAQwSYxi+FJsj/ROpJf4Usif/EKwj/wKQEv8CgBD/LaZH/0HNYv8irz3/
Ja5E/ymyS/8tt1H/MbpW/zbBXf83tln/T916/1Xxhv9O5Hn/Qttn/zfJUf8tuUT/
LblK/y+6T/4yvFX9NLxa+z3Rav8cai3lAAAAHgAAAAAAAAAACicMWhewLP8TsCf/
Eask/hKrJfwNnh7+BIwV/waTGv8JjRv/HZAr/y+1QP84zFL/Pcpb/kHLZf9D0Gz/
Q9Bv/zq1Xv9P13j/Uul5/0fcZf9B1Vr/Ps9V/0DRWf1H12H7TeBr/k7hcP9M2m79
Q81o/xVQIL0AAAAJAAAAAAAAAAAZaCatKMdE/x+2OPsaszL/GK8t/wuZHf8Kkh3/
D5gl/xSfLf8XoTP/IpY2/0DBWP5b8ID/ZfSO/2HiiP5UzXX7Oq1R/DKpRf07uVH8
QMBZ+0bJY/9X5Hr/YfWJ/1fie/9Kwmf9NpJK2B5ZJ6YJIgtmAQQBFQAAAAAAAAAB
BQ0FKzOuT+g822L/MslT/S7GTP8kuj//Dpgj/xKbKv8YoTH/Hac5/yOtQv8ntUn/
K5NB90GdVfBHtGD+Rr9e/0bLX/9S53L/W/F//1njff9W2Hn/U851/z6gVfYobTbD
F0AffgMSBUQAAAAUAAAAAAAAAAEAAAAAAAAAAAAAAAAZRSNwU+qA/07mevxI4HP/
RuBw/ym6R/8TnCz/G6Y3/yCrPv8msEb/K7VO/DTAWP8XUSSSAAAAAwQPBD4SNhds
KGo2mzqPUMBMtWnfSq1m1jF0QqMUMxpiAgcDHgAAAAAAAAAAAAAAAAAAAAABAgED
AAEAAwAAAAAAAAAAAAAAADufVtVg/pT/V+yG/lLpfP9J3W3/J7NB/xylOf8lr0X/
KrRN/y+5U/82wVz/NLJW/QgWCTgAAAAAAAEAAgAAAAAAAAAAAAAAAgACAB4AAgAU
AAAAAAAAAAAAAAAAAAAAAAECAQIAAQADAAEAAgAAAAAAAAAAAAAAAAAAAAABAQED
K4M5yjvTUv8zykj9MMNC/THEQ/8zxkb/Mb9M/y63UP8yu1j/N8Be/T/Paf8nfj7J
AAAAAwAAAAAAAQACAQIBAwEDAQQBAgIBAAAAAAAAAAABAwIDAAEBAwABAAEAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAwANFVIZky+9QP81zkr+
N8lN/D/QV/9G12H/R9Ro/j3FZP45wWL5QMtp/xQ/HnEAAAAAAQIBAwAAAAAAAAAA
AAAAAAAAAAEAAQACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAACAQEAAAAADSoPVjGkQ+dK4Wf/Tt1t/lXjeP9f7oT/
YvCL/VXqhP83rFjuBQ4ELAAAAAAAAQEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAEAAgACAQIAAAAABA8FJS+AP7xZ4nz/XuSC/VjRevlQuWznRJ9c0RpHJHcAAAAA
AQEBAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAQMAAAAA
AQIACA8mE0sNIRBEBAwFIAECAQkAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQIBAQEBAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAQEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
/////////////3////wP///wAf//4AA//8AAB/8AAAP+AAAD/AAAA/wAAAP8AAAD
/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/gAAAPAAAADwAAAA4AAAA+AAAD/
gAcH/wAP//8AD///gB///+Af///wP/////////////+w1wAAaAQAAAAAAAAAAAAA
KAAAABAAAAAgAAAAAQAgAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAEAAwABAAEAAAAAAAAAAAAAAAAAAAAAAAIBAgABAAMAAAAC
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAIAAwAAAAACAAESCzgOmAlBDrgGEwVl
AQAAHwAAAAAAAAAAAAAAAAACAQEAAAAAAAAAAAAAAAAAAAAAAAIBAgAAAAAFEAVG
FHAd3xKtJf8GmBn9D48h/xVzI/INPBOxBBEFYAEAABsAAAAAAAAAAAAAAAAAAAAB
AAAAAAEAAAwJMQuQIJsy/SXJQv8bsTP8Dpck/BWhL/0jtEP/GJ4v/wWFFP8PbR3y
CzEPlwAAAAYAAAAAAAEAAQAAAAAUWx21F7Mr/y/ATftC2Wn9NctZ/xqkNv8iq0H/
L7ZS/h6cN/wKlB/8GbI3/xuHMOoBAAAZAAAAAQAAAAAAAAAGKJs/2zDQUf9H02/9
WfWL/z/UYP8ptkH/LrpQ/zrGY/8sqkr/HaU4/iy8T/8kiz3kAAAAFwAAAAEAAAAA
AAAABT6rXtdQ6X3/PsFe/UHSXf9A0lf/TN5p/1jle/9T2Hf/IJw2/xaULf4wulT/
K49G5gAAABYAAAABAAAAAAAAAAgukkXYJbs+/waPFf0QkSH/La9G/0zMbf9Awlz/
Gqot/wmaGv8HjBn+FJ8s/xd3KeUAAAAWAAEAAQAAAAAAAAAEHokx1iTKQf8SoSj9
Dpgm/xeiM/8goTv/FKUn/xGuJP8Roib/Fp4v/iGzQf8bgzHlAAAAFgAAAAACBgIO
BiEHSCCPMuhA1GX/KblJ/hmgNf4osUj+MLZT/zvNXv8yzVT/IK86/h6jPPouvVP/
Jo5A6AAAABgEDwQhEYke4BSxJ/8GlhX+EpEm/yywRP8zw1L/P81m/zu7YPxL13L7
R95q/T7UWf9B12H9Rtxt/yiIQdoAAAAPFlEieTDSUf8ftjn7DZgj/hOdLP8gozn/
QbZa81PNcvtM0mr/Tttt/0zNav9EsV7oMH5BrRc/HmgEDQQhAAAAAES/Z9pV8oP/
M8RT/BmhNP4pskr9MrlW/wkeDkEEDAMjGkQiXilgOHwTLRtFAQIBDQAAAAAAAAAA
AAAAAAAAAAEhcC6hN85L/zrSUP88ylv8Qdht/y6US8oAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAABAwIDAQMBBAABAAIAAAAAAAAAAA81E1ZEwF7sWNl69EzCbuoVPyBi
AAAAAAEEAQUBAwEEAQMCBAECAQMAAAABAAAAAAAAAAAAAAAAAAAAAAECAgMAAAAA
BxEJHAoXDScCAwIJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAD//wAA/n8AAPwPAADwAQAA4AEAAOABAADgAQAA4AEAAOABAADgAQAA
gAEAAIAHAAAD/wAAA/8AAMf/AAD//wAAKNwAADAAAAAAAAAAAAAAAAAAAQADADAw
AAABACAAqCUAAAEAICAAAAEAIACoEAAAAgAQEAAAAQAgAGgEAAADAGjcAAAoBAAA
AAAAAAAAAAAoBDQAAABWAFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAA
vQTv/gAAAQAEAAEAAAAHAAQAAQAAAAcAPwAAAAAAAAAEAAAAAQAAAAAAAAAAAAAA
AAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEA
bgBzAGwAYQB0AGkAbwBuAAAAAAAAALAEiAMAAAEAUwB0AHIAaQBuAGcARgBpAGwA
ZQBJAG4AZgBvAAAAZAMAAAEAMAAwADAAMAAwADQAYgAwAAAAZAAmAAEAQwBvAG0A
bQBlAG4AdABzAAAAUwBoAG8AdwBzACAAYQBsAGwAIABwAGEAYwBrAGEAZwBlAHMA
IABpAG4AIABXAGkAbgBkAG8AdwBzACAAVgBpAHMAdABhAC8ANwAAAE4AFwABAEMA
bwBtAHAAYQBuAHkATgBhAG0AZQAAAAAATQBvAGQAaQBmAGkAZQBkACAAYgB5ACAA
TABlAGcAbwBsAGEAcwBoADIAbwAAAAAAVAAWAAEARgBpAGwAZQBEAGUAcwBjAHIA
aQBwAHQAaQBvAG4AAAAAAHcAaQBuADYALgB4AF8AcgBlAGcAaQBzAHQAcgB5AF8A
dAB3AGUAYQBrAAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAxAC4A
NAAuADcALgAwAAAATAAWAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABpAG4A
cwB0AGEAbABsAF8AdwBpAG0AXwB0AHcAZQBhAGsALgBlAHgAZQAAAHQAKAABAEwA
ZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAA
KABjACkAIAAyADAAMAA4AC0AMgAwADEAMQAgAE0AaQBjAGgAYQBCASAAVwBuAHUA
bwB3AHMAawBpAAAASAAQAAEATABlAGcAYQBsAFQAcgBhAGQAZQBtAGEAcgBrAHMA
AAAAAE0AaQBjAGgAYQBCASAAVwBuAHUAbwB3AHMAawBpAAAAVAAWAAEATwByAGkA
ZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAGkAbgBzAHQAYQBsAGwAXwB3AGkA
bQBfAHQAdwBlAGEAawAuAGUAeABlAAAATAAWAAEAUAByAG8AZAB1AGMAdABOAGEA
bQBlAAAAAAB3AGkAbgA2AC4AeABfAHIAZQBnAGkAcwB0AHIAeQBfAHQAdwBlAGEA
awAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADEALgA0AC4A
NwAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAA
MQAuADQALgA3AC4AMAAAAKDgAADqAQAAAAAAAAAAAADvu788P3htbCB2ZXJzaW9u
PSIxLjAiIGVuY29kaW5nPSJVVEYtOCIgc3RhbmRhbG9uZT0ieWVzIj8+DQoNCjxh
c3NlbWJseSB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjEi
IG1hbmlmZXN0VmVyc2lvbj0iMS4wIj4NCiAgPGFzc2VtYmx5SWRlbnRpdHkgdmVy
c2lvbj0iMS4wLjAuMCIgbmFtZT0iTXlBcHBsaWNhdGlvbi5hcHAiLz4NCiAgPHRy
dXN0SW5mbyB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjIi
Pg0KICAgIDxzZWN1cml0eT4NCiAgICAgIDxyZXF1ZXN0ZWRQcml2aWxlZ2VzIHht
bG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgICAg
IDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0iYXNJbnZva2VyIiB1aUFj
Y2Vzcz0iZmFsc2UiLz4NCiAgICAgIDwvcmVxdWVzdGVkUHJpdmlsZWdlcz4NCiAg
ICA8L3NlY3VyaXR5Pg0KICA8L3RydXN0SW5mbz4NCjwvYXNzZW1ibHk+AAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAADAAAAEA4AAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----
