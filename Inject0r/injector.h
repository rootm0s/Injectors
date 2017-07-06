#pragma once

#include <string>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <io.h>

using namespace std;

namespace Injector
{
	extern bool Inject(string strProcessName, string strDLLPath);
}