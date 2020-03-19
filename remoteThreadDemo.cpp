

using namespace std;


#include <stdio.h>
#include<vector>
#include<iostream>
#include <fstream> 
#include <stdint.h>

#include <Winsock2.h>
#include<WS2tcpip.h>
#include<Windows.h>
#include<TlHelp32.h>
#include<direct.h>
#pragma comment(lib, "WS2_32")  // 链接到WS2_32.lib

std::string execute(string cmd);
bool enableDebugPriv();
wstring test(string str);
DWORD GetProcessIDByName(const char* pName);
int main1()
{
    if (!enableDebugPriv()) {
        cout << "failed to enable debug priv" << endl;
    }
    BOOL bFlag = FALSE;

    const char* szDllName = "C:/Windows/System32/DLL1.dll";
    //const char* szDllName = "D:\\vsrepos\\Dll1\\x64\\Debug\\DLL1.dll";
    const char* processName = "explorer.exe";
    DWORD hpid = GetProcessIDByName(processName);
    //bFlag = EnablePrivilege(SE_DEBUG_NAME);    //返回值为1时代表成功

    //得到目标进程句柄
    HANDLE hDestProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,hpid );

    LPTHREAD_START_ROUTINE dwAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");

    //在目标进程的地址空间内分配一个内存块
    LPVOID pRemoteSpace = VirtualAllocEx(hDestProcess, NULL, strlen(szDllName) +1 , MEM_COMMIT,
        PAGE_READWRITE);

    //向上一步的内存块中写入数据，就是要加载的DLL名字
    SIZE_T* numberOfBytesWrittern=nullptr;
    bFlag = WriteProcessMemory(hDestProcess, pRemoteSpace, szDllName, strlen(szDllName) +1 , numberOfBytesWrittern);
    LPDWORD tid=nullptr;
    //在目标进程内创建线程,线程的入口函数就是LoadLibraryA, 参数就是Dll名字
    HANDLE hThread = CreateRemoteThread(hDestProcess, NULL,0 , dwAddr, pRemoteSpace,
        NULL,tid
        );      //前面都是成功的，就到了这一步，返回的错误是5，Access denied,权限不够
                //本来以为我的VS是以管理员权限启动的，那么我这个进程应该权限就都够了，
                //看来不行，必须程序提权
                //我提权了之后，发现还是不行，之后上网查了
                //发现是32位注入到64位中会有问题，所以我换了个x64,然后显然线程运行成功了，
                //但是现在远程进程却崩溃了，估计是DLL是32的，我换个DLL编译方式再试试
                //我编译了64位的DLL，然后还是崩溃的，之后我发现了应该是我函数地址传的有问题
                //因为32位的LoadLibraryA地址是DWORD，但64位却是ULONGLONG，所以仅仅改变编译方式还不够
                //必须用一个足够容纳8个字节地址的类型来保存，这样就够了

                //另外一个需要注意的问题就是，为什么我在我这个进程中得到的LoadLibrary在远程进程中也可以用
                //答案就是,系统DLL在各个进程中的映射地址都是一样的，不过具体情况具体分析，至少这个函数看来是一样的。

                //在我完成了之后，我把EnablePrivileges这行注释掉了，但仍然注入成功，看来我用管理员权限运行VS2015之后就够了

                //然后我又发现了一个问题，就是对同一个进程，加载dll只能一次，第二次就不会弹了
                //原因，我目测是，DLL已经被加载了，所以第二次就不加载了，也就不执行DllMain那个函数了
                //除非我创建一个线程再UnLoad那个LIB，之后再LOAD，这样应该就可以了
                //也可以换个Dll名字，再LOAD， 反正方法很多。

    DWORD dwErr = GetLastError();
    
    DWORD dwThreadID = 0;
    //WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &dwThreadID);
    CloseHandle(hThread);
    /*//卸载dll
    cout << "start unload dll\n";
    PTHREAD_START_ROUTINE dwAddr1 = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "FreeLibrary");
    if (dwAddr1) {
        cout << "get free library ok\n";
    }
    else {
        cout << "get free library error\n";
    }
    
    HANDLE hThread1 = CreateRemoteThread(hDestProcess, NULL, 0, dwAddr1, pRemoteSpace, NULL, tid);
    if (hThread1){
        cout << "create remote thread ok\n";
    }
    else {
        cout << "create remote thread error" << GetLastError() << endl;
    }
    VirtualFreeEx(hDestProcess, pRemoteSpace, strlen(szDllName) + 1, MEM_DECOMMIT);
    CloseHandle(hThread1);*/
    CloseHandle(hDestProcess);
    
    return 0;
}



bool enableDebugPriv()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if ( !OpenProcessToken( GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,& hToken)
        )
    {
    return false;
    }
    if( !LookupPrivilegeValue(NULL, SE_DEBUG_NAME,& sedebugnameValue) )
    {
        CloseHandle(hToken);
    return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if( !AdjustTokenPrivileges(hToken, FALSE,& tkp, sizeof(tkp), NULL, NULL) )
    {
        CloseHandle(hToken);
    return false;
    }
    return true;
}
void main() {
    main1();
}
wstring test(string str) {
    
    LPCSTR src = str.c_str();
    int nLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
    if (nLen == 0)
        return L"";

    wchar_t* dst = new wchar_t[nLen];
    if (!dst)
        return L"";

    MultiByteToWideChar(CP_ACP, 0, src, -1, dst, nLen);
    std::wstring res(dst);
    delete[] dst;
    dst = NULL;
    return res;
}
DWORD GetProcessIDByName(const char* pName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        return NULL;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
        char szExeFileA[260] = { 0 };
        sprintf_s(szExeFileA, "%ws", pe.szExeFile);
        if (strcmp(szExeFileA, pName) == 0) {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
        //printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
    }
    CloseHandle(hSnapshot);
    return 0;
}
std::string execute(string cmd)
{
    // 创建匿名管道
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        return "";
    }

    LPCSTR pszSrc = cmd.c_str();
    int nLen = MultiByteToWideChar(CP_ACP, 0, cmd.c_str(), -1, NULL, 0);
    if (nLen == 0)
        return ("");

    wchar_t* pwszDst = new wchar_t[nLen];
    if (!pwszDst)
        return ("");

    MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, pwszDst, nLen);
    std::wstring pszCmd(pwszDst);
    delete[] pwszDst;
    pwszDst = NULL;


    // 设置命令行进程启动信息(以隐藏方式启动命令并定位其输出到hWrite
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;

    // 启动命令行
    PROCESS_INFORMATION pi;
    if (!CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
    {
        
        return ("Cannot create process");
    }

    // 立即关闭hWrite
    CloseHandle(hWrite);
    //wait for process to exit
    WaitForSingleObject(pi.hProcess, 5000);

    // 读取命令行返回值
    std::string strRetTmp;
    char buff[1024] = { 0 };
    DWORD dwRead = 0;
    //memset(buff, sizeof(buff), 0);
    strRetTmp = "";
    while (ReadFile(hRead, buff, 1023, &dwRead, NULL))
    {
        cout << "*" << buff << endl;
        strRetTmp.append(buff);
        if (strlen(buff) < 1000)break;
        memset(buff, 0, sizeof(buff));
    }
    //strRetTmp.append(buff);
    CloseHandle(hRead);
    cout << "result before trans to wide string*" << strRetTmp << "*\n";

    return strRetTmp;
}
