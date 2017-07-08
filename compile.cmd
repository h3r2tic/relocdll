call "%VS140COMNTOOLS%"\..\..\VC\bin\amd64\vcvars64

cl -Zi -nologo -c test.cpp -MDd -D_HAS_EXCEPTIONS=0 -Od -D "_DEBUG"
link -noentry -nodefaultlib -debug -dll -map -force test.obj

cl -I. relocdll.cpp -MDd -D_HAS_EXCEPTIONS=0 -link -map dbghelp.lib -debug
pause
