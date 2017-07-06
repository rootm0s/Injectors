#include "injector.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR lpCmdLine, int nCmdShow) {
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	Injector::Inject("csgo.exe", "p4st3d.dll");

	return 0;
}