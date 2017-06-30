#include <windows.h>
#include <CommCtrl.h>

#include "resource.h"
#include "system.h"
#include "injector.h"

#pragma comment(lib, "comctl32.lib")






void HandleEvent(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	static CInjector injector;

	switch (wParam) {
		case IDC_BTN_INJECT:
			{
				wchar_t dllName[MAX_PATH] = {0}, exeName[MAX_PATH] = {0};
				
				// Get the path of the dll to inject and the mode of injection
				SendMessage(GetDlgItem(hWnd, IDC_EDIT_DLL), WM_GETTEXT, MAX_PATH, reinterpret_cast<LPARAM>(dllName));

				int bChecked = SendMessage(GetDlgItem(hWnd, IDC_CBX_AUTOINJECT), BM_GETCHECK, 0, 0);

				if (bChecked) {
					// Start the process and inject
					SendMessage(GetDlgItem(hWnd, IDC_EDIT_PROCESS), WM_GETTEXT, MAX_PATH, reinterpret_cast<LPARAM>(exeName));
					injector.InjectAuto(dllName, exeName);
				} else {
					// Get the name of the target process
					int exeIndex = SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_GETCURSEL, 0, 0);
					SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_GETTEXT, exeIndex, reinterpret_cast<LPARAM>(exeName));
					
					// Inject the dll normally
					if (!injector.Inject(dllName, exeName)) {
						std::wstringstream ss;
						ss << L"Could not inject " << dllName << L" into " << exeName;
						//MessageBoxW(hWnd, ss.str().c_str(), L"Injector", MB_ICONERROR);
					} else {
						//MessageBoxW(hWnd, L"Dll injected!", L"Injector", MB_ICONINFORMATION);
					}
				}
			}
			break;

		case IDC_BTN_REFRESH:
			{
				
				// Clear the process list
				SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_RESETCONTENT, 0, 0);

				// Get a new list of processes
				CInjector::ProcessList_t processes = injector.GetProcessList();
				CInjector::ProcessList_t::iterator i;
				// Iterate the process list and put it in the listbox
				for (i = processes.begin(); i != processes.end(); i++) {
					SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_ADDSTRING, 0, reinterpret_cast<LPARAM>((*i).c_str()));
				}
				
				// Select the 5 item by default
				 SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_SETCURSEL, 5, 0);
			}
			break;

		case IDC_BTN_DLL:
			{
				// Get the path that the user specifies
				OPENFILENAMEW ofn;
				memset((void*)&ofn, 0, sizeof(ofn));

				wchar_t fileName[MAX_PATH] = {0};

				ofn.hwndOwner = hWnd;
				ofn.lpstrFile = fileName;
				ofn.lpstrFilter = L"Supported Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
				ofn.nMaxCustFilter = 40;
				ofn.lStructSize = sizeof(ofn);
				ofn.nMaxFile = MAX_PATH;

				GetOpenFileNameW(&ofn);

				// Write it to the edit control
				SendMessage(GetDlgItem(hWnd, IDC_EDIT_DLL), WM_SETTEXT, 0, reinterpret_cast<LPARAM>(fileName));
			}
			break;

		case IDC_BTN_PROCESS:
			{
				// Get the path that the user specifies
				OPENFILENAMEW ofn;
				memset((void*)&ofn, 0, sizeof(ofn));

				wchar_t fileName[MAX_PATH] = {0};

				ofn.hwndOwner = hWnd;
				ofn.lpstrFile = fileName;
				ofn.lpstrFilter = L"Supported Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
				ofn.nMaxCustFilter = 40;
				ofn.lStructSize = sizeof(ofn);
				ofn.nMaxFile = MAX_PATH;

				GetOpenFileNameW(&ofn);

				// Write it to the edit control
				SendMessage(GetDlgItem(hWnd, IDC_EDIT_PROCESS), WM_SETTEXT, 0, reinterpret_cast<LPARAM>(fileName));
			}
			break;

		case IDC_BTN_UNLOAD:
			{
				wchar_t dllName[MAX_PATH] = {0}, exeName[MAX_PATH] = {0};
				
				// Get the path of the dll to unload
				SendMessage(GetDlgItem(hWnd, IDC_EDIT_DLL), WM_GETTEXT, MAX_PATH, reinterpret_cast<LPARAM>(dllName));

				// Get the name of the target process
				int exeIndex = SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_GETCURSEL, 0, 0);
				SendMessage(GetDlgItem(hWnd, IDC_LIST_PROCESSES), LB_GETTEXT, exeIndex, reinterpret_cast<LPARAM>(exeName));

				// Unload the dll
				if (!injector.Unload(dllName, exeName)) {
					//MessageBoxW(hWnd, L"Unloading failed", L"Injector", MB_ICONERROR);
				} else {
					//MessageBoxW(hWnd, L"Dll unloaded!", L"Injector", MB_ICONINFORMATION);
				}
			}
			break;

		case IDC_CBX_AUTOINJECT:
			{
				int bChecked = SendMessage(GetDlgItem(hWnd, IDC_CBX_AUTOINJECT), BM_GETCHECK, 0, 0);

				if (bChecked) {
					EnableWindow(GetDlgItem(hWnd, IDC_LIST_PROCESSES), 0);
					EnableWindow(GetDlgItem(hWnd, IDC_BTN_UNLOAD), 0);
					EnableWindow(GetDlgItem(hWnd, IDC_BTN_REFRESH), 0);
					EnableWindow(GetDlgItem(hWnd, IDC_BTN_PROCESS), 1);
					EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PROCESS), 1);
				} else {
					EnableWindow(GetDlgItem(hWnd, IDC_LIST_PROCESSES), 1);
					EnableWindow(GetDlgItem(hWnd, IDC_BTN_UNLOAD), 1);
					EnableWindow(GetDlgItem(hWnd, IDC_BTN_REFRESH), 1);
					EnableWindow(GetDlgItem(hWnd, IDC_BTN_PROCESS), 0);
					EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PROCESS), 0);
				}
			}
			break;
	}
}

BOOL CALLBACK DialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HICON   hIcon; 
	static HINSTANCE    hInstance   = GetModuleHandle (NULL);  
	try {
		switch (msg) {
			case WM_CLOSE:
				EndDialog(hWnd, 0);
				break;

			case WM_INITDIALOG:
 				hIcon  = LoadIcon (hInstance, MAKEINTRESOURCE(IDI_MAIN_ICON) );
				SendMessage(hWnd,WM_SETICON,ICON_BIG, (LPARAM)hIcon);
				HandleEvent(hWnd, IDC_BTN_REFRESH, 0);
				break;

			case WM_COMMAND:
				HandleEvent(hWnd, wParam, lParam);
				break;
		}
	}
	catch (std::exception e) {
		std::wstringstream ss;
		ss << e.what() << std::endl << System::GetSystemError();
		MessageBoxW(hWnd, ss.str().c_str(), L"Injector", MB_ICONERROR);
	}

	return FALSE;
}
 
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	
	

	InitCommonControls();
	System::SetDebugPrivilege();
	return DialogBoxW(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), 0, DialogProc);
}