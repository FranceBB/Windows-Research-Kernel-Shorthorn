rem IF [%2] EQU [] goto setenv
set path=%2\tools\%1;%path%
set wrkarch=%1
call WRKEnv.bat %1
goto dothejob
rem :setenv
rem call WRKEnv.bat %1
:dothejob
cd base\ntos\
nmake %wrkarch%= clean
cd ..\..

