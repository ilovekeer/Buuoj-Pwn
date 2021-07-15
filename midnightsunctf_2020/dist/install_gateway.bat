@echo off
:: Universal Battle.net Gateway Installer v1.0
:: https://github.com/HarpyWar/battle.net-gateway-installer
::
:: (c) 2012, HarpyWar (http://harpywar.com)


:: -- CONFIGURATION START --


	:: server connection
	::
	set title=Midnight Sun CTF
	set address=bnet.play.midnightsunctf.se
	set timezone=1
	

	:: games to setup in the registry (true or false)
	::
	set starcraft=true
	set warcraft3=false
	set diablo2=false
	
	
:: --  CONFIGURATION END  --

































set HKCU=HKEY_CURRENT_USER\Software

set starcraft_title=Starcraft
set starcraft_path=%HKCU%\Battle.net\Configuration
set starcraft_key=Battle.net Gateways

set warcraft3_title=Warcraft 3
set warcraft3_path=%HKCU%\Blizzard Entertainment\Warcraft III
set warcraft3_key=%starcraft_key%

set diablo2_title=Diablo 2
set diablo2_path=%starcraft_path%
set diablo2_key=Diablo II Battle.net Gateways
set diablo2_bnetip=%HKCU%\Blizzard Entertainment\Diablo II


TITLE Universal Battle.net Gateway Installer
color 9f
echo  - - - - - - - - - - - - - - - - - - - - -
echo.
echo   UNIVERSAL BATTLE.NET GATEWAY INSTALLER
echo.
echo  - - - - - - - - - - - - - - - - - - - - -
echo.
echo.
echo       Title: %title%
echo     Address: %address%
echo    Timezone: %timezone%
echo.

if %starcraft%==true call :addserver "starcraft_path" "starcraft_key" "starcraft_title"
if %warcraft3%==true call :addserver "warcraft3_path" "warcraft3_key" "warcraft3_title"
if %diablo2%==true (
	call :addserver "diablo2_path" "diablo2_key" "diablo2_title"
	call :updatebnetip "diablo2_bnetip" "diablo2_title"
)


echo.
echo.
echo.

pause
goto :eof




:: add server to registry in the game serverlist
:addserver <registryPath> <registryKey> <gameTitle>
    setlocal EnableDelayedExpansion
	
	set reg_path=!%~1!
	set reg_key=!%~2!
	set game_title=!%~3!

	echo.
	echo [%game_title%]
	
	:: -- STEP 1 -- (read parameter from registry)

	set /a line_count=0
	
	:: search parameter in the registry and get cmd output result with a line delimeter "*"
	set cmd=REG QUERY "%reg_path%" /v "%reg_key%"
	FOR /F "delims=" %%i IN ('%cmd%') DO if ("!out!"=="") (set out=%%i) else (set /a line_count+=1 & set out=!out!*%%i)

	:: if parameter found in the registry then append serverlist
	if %line_count% == 2 (
		for /F "tokens=1,2,3 delims=*" %%a in ("%out%") do set multistr=%%b
		rem echo !multistr!
		
		:: get start position
		call :strlen start "reg_key"
		:: spaces
		set /a start+=8
		
		:: get row type (REG_MULTI_SZ or REG_BINARY)
		call :substr _type !start! 10 "multistr"
		if "!_type!"=="REG_BINARY" (
			set /a start+=10
		) else (
			set /a start+=12
		)
			
		:: spaces
		set /a start+=4
		rem echo !start!
		
		:: get all result text length
		call :strlen len "multistr"
		set /a len-=!start!
		rem echo !len!
		
		:: get multistring data
		call :substr _substr !start! !len! "multistr"
		set serverlist=!_substr!
		
		
		:: if serverslist in binary format then convert it to ascii
		if "!_type!"=="REG_BINARY" (
			rem echo BINARY data detected!
			:: convert hex to string
			call :hex2ascii serverlist
			
			:: remove \0\0 at the end
			set serverlist=!serverlist:~0,-4!
			
			:: delete binary key from the registry
			rem set cmd=REG DELETE "%reg_path%" /v "%reg_key%" /f
			rem for /f "delims=" %%i in ('!cmd!') do set out=%%i
		)
	) else (
		set serverlist=1001\000
	)
	
	rem echo !serverlist!

	:: -- STEP 2 -- (add parameter into registry)

	set isfound=0
	:: find server in the serverlist
	for /f "delims=" %%i in ('echo "!serverlist!" ^| find "%address%"') do set isfound=%%i
	
	:: if server not found then add it
	if %isfound% equ 0 (
		set serverlist=!serverlist!\0%address%\0%timezone%\0%title%

		:: select this server
		rem echo !serverlist!
		call :servercount count "serverlist"
		call :selectserver !count! "serverlist"
		rem echo !serverlist!
		
		set cmd=REG ADD "%reg_path%" /v "%reg_key%" /f /t REG_MULTI_SZ /d "!serverlist!"
		for /f "delims=" %%i in ('!cmd!') do set out=%%i
		rem echo !out!
		echo   Server was added
	) else (
		echo   Server is already exists
	)

	endlocal
	exit /b

	
:: update bnetip key (needed for diablo 2)
:updatebnetip <registryPath>
    setlocal EnableDelayedExpansion
	
	set reg_path=!%~1!
	set reg_key=BNETIP
	set game_title=!%~2!

	set cmd=REG ADD "%reg_path%" /v "%reg_key%" /f /t REG_SZ /d "%address%"
	for /f "delims=" %%i in ('!cmd!') do set out=%%i
	rem echo %out%
	echo   Gateway selected
	
	endlocal
	exit /b

	
:: return length of string
:strlen <resultVar> <stringVar>
(   
    setlocal EnableDelayedExpansion
    set "s=!%~2!#"
    set "len=0"
    for %%P in (4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do (
        if "!s:~%%P,1!" NEQ "" ( 
            set /a "len+=%%P"
            set "s=!s:~%%P!"
        )
    )
)
(
    endlocal
    set "%~1=%len%"
    exit /b
)

:: return text substring from start to length
:substr <resultVar> <start> <length> <text>
(   
    setlocal EnableDelayedExpansion
	set _str=!%~4!
	set _substr=!_str:~%2,%3!
)
(
    endlocal
	set "%~1=%_substr%"
	exit /b 0
)

:: return servers count from the serverlist
:servercount <resultVar> <serverList>
(   
    setlocal EnableDelayedExpansion
	set _str=!%~2!
	
	set char=\0
	set count=0

	:loop
		if !_str:~0^,2! equ !char! (
			set /a count+=1
		)
		if "!_str:~1!" neq "" (
			set _str=!_str:~1!
			goto :loop
		)
	set /a count -= 1
	set /a count /= 3
)
(
    endlocal
	set "%~1=%count%"
	exit /b 0
)

:: update current server in the serverlist header
:selectserver <serverNum> <serverList>
(   
    setlocal EnableDelayedExpansion
	
	set servernum=%1
	set serverlist=!%~2!

	:: trim left
	set str=!serverlist!
	for /f "tokens=* delims= " %%a in ("!str!") do set str=%%a
	
	:: remove header
	set str=!str:~8!
	rem echo !str!

	:: add new header
	call :strlen len servernum
	:: add 0 before selected number if there is only one digit
	if !len! lss 2 set servernum=0!servernum!
	rem echo !len!
	
	set _serverlist=1001\0!servernum!!str!
)
(
    endlocal
	set "%~2=%_serverlist%"
	exit /b 0
)

:hex2ascii <serverList>
	set count=0
	set hex=!%~1!
	set newline=\0
	
	:_nextchar
	
	:: get 2 hex chars
	call :substr val !count! 2 hex

	if "!val!" neq "" (
		rem echo.
		rem echo %val%
		
		if "!val!" equ "00" (
			set char=%newline%
		) else (
			set /a decimal=0x!val!
			rem echo !decimal!
			
			cmd /c exit /b !decimal!
			set char=!=ExitCodeAscii!
		)
		
		
		set ascii=!ascii!!char!
		rem echo !ascii!
		
		set /a count+=2
		goto :_nextchar
	)

	rem echo !ascii!
	
	set "%~1=%ascii%"
	exit /b 0

