#include <iostream>
#include <windows.h>

using namespace::std;

int Inject(HWND hwnd, char *name);

int main()
{
   char dll[]="c:/tt.dll";//change the name to your dll
   HWND hw=0;

 
      hw = FindWindow("Notepad",NULL);//change the "Notepad" to your window name

      if(!hw)
      {
         cout<<"Unable find window"<<endl;
         return 0;
      }

      if(Inject(hw,dll))
      {
         cout<<"DLL has injected into the process successfully"<<endl;
      }

      else
      {
         cout<<"Couldn't inject DLL into process"<<endl;
      }

   return 0;
}


int Inject(HWND hwnd,char *name)
{
   DWORD Pid;
   HANDLE    hProcess,hThread;
   DWORD   BytesWritten;
   LPVOID    mem;
 

   GetWindowThreadProcessId(hwnd, &Pid);


   hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

   if(!hProcess)
      return 0;


   mem = VirtualAllocEx(hProcess, NULL,  strlen(name), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

   if(mem==NULL)
   {
CloseHandle(hProcess);
return 0;
   }

   if(WriteProcessMemory(hProcess, mem, (LPVOID)name,  strlen(name), &BytesWritten))
   {
   
      hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA"), mem, 0, NULL);
   
      if(!hThread)
      {
          VirtualFreeEx(hProcess,NULL,strlen(name),MEM_RESERVE|MEM_COMMIT);
CloseHandle(hProcess);
         return 0;
      }
      VirtualFreeEx(hProcess,NULL,strlen(name),MEM_RESERVE|MEM_COMMIT);
          
            CloseHandle(hThread);
               CloseHandle(hProcess);

      return 1;
      

   }   
   VirtualFreeEx(hProcess,NULL,strlen(name),MEM_RESERVE|MEM_COMMIT);

               CloseHandle(hProcess);
             
   return 0;
} 
