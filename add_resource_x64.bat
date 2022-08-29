del ..\build\TheMatrix\Debug\x64\TheMatrix.dll

rem Create a binary to test DLL
..\build\TheMatrix\Debug\x64\TheMatrix.exe -add "..\ConsoleExe1_Test\bins\adprovider.dll"
ren ..\build\TheMatrix\Debug\x64\TheMatrix.build.dll TheMatrix.dll

rem Create a binary to test EXE
..\build\TheMatrix\Debug\x64\TheMatrix.exe -add "..\ConsoleExe1_Test\Debug\x64\ConsoleExe1_Test.exe"
del ..\build\TheMatrix\Debug\x64\TheMatrix.exe
ren ..\build\TheMatrix\Debug\x64\TheMatrix.build.exe TheMatrix.exe