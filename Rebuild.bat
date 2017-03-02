@ECHO OFF
SET /P ARCH="Chose a architecture: "  
IF "%ARCH%"=="x86" (
	call cleanx86.bat %1 %2
	call buildx86.bat %1 %2
) ELSE IF "%ARCH%"=="x64" (
	call cleanx64.bat %1 %2
	call buildx64.bat %1 %2
)



