del ..\build\TheMatrix\Debug\x86\TheMatrix.dll

rem Create a binary to test DLL
..\build\TheMatrix\Debug\x86\TheMatrix.exe -add "..\ConsoleExe1_Test\bins\xapauthenticodesip.dll"
ren ..\build\TheMatrix\Debug\x86\TheMatrix.build.dll TheMatrix.dll

rem Create a binary to test EXE
..\build\TheMatrix\Debug\x86\TheMatrix.exe -add "..\build\ConsoleExe1_Test\Debug\x86\ConsoleExe1_Test.exe"
del ..\build\TheMatrix\Debug\x86\TheMatrix.exe
ren ..\build\TheMatrix\Debug\x86\TheMatrix.build.exe TheMatrix.exe