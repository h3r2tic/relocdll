#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C"
{
	__declspec(dllexport) int foo(int a, int b)
	{
		//__debugbreak();
		return a + b;
	}

	__declspec(dllexport) void bar()
	{
		std::cout << "bar called()" << std::endl;
	}

	__declspec(dllexport) int* baz()
	{
		return new int(666);
	}
}
