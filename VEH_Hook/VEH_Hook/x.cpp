#include <windows.h>
#include <iostream>
#include <list>

using namespace std;

struct EXCEPTION_HOOK
{
    ULONG_PTR ExceptionAddress;
    UCHAR OldCode;
};

list<EXCEPTION_HOOK> HookInfo;

LONG __stdcall MyVehHandle(EXCEPTION_POINTERS *ExceptionInfo)
{
    for (list<EXCEPTION_HOOK>::iterator i = HookInfo.begin(); i != HookInfo.end(); ++i)
    {
        if (i->ExceptionAddress == (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress && 
            ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            ULONG OldProtect;
            BOOL bProtect = VirtualProtect((PVOID)ExceptionInfo->ContextRecord->Eip, 1, PAGE_READWRITE, &OldProtect);
            if (bProtect == FALSE)
            {
                cout << "HOOKÊ§°Ü£¡´íÎóÂëÊÇ£º" << GetLastError() << endl;
                return FALSE;
            }

            *(UCHAR *)ExceptionInfo->ContextRecord->Eip = i->OldCode;
            VirtualProtect((PVOID)ExceptionInfo->ContextRecord->Eip, 1, OldProtect, &OldProtect);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL AddHook(ULONG_PTR Address)
{
    EXCEPTION_HOOK ExceptionInfo;
    ExceptionInfo.ExceptionAddress = Address;

    for (list<EXCEPTION_HOOK>::iterator i = HookInfo.begin(); i != HookInfo.end(); ++i)
    {
        if (i->ExceptionAddress == Address)
        {
            cout << "¸ÃµØÖ·ÒÑ¾­´æÔÚHOOKÖÐ£¡" << endl;
            return FALSE;
        }
    }

    ULONG OldProtect;
    BOOL bProtect = VirtualProtect((PVOID)Address, 1, PAGE_READWRITE, &OldProtect);
    if (bProtect == FALSE)
    {
        cout << "HOOKÊ§°Ü£¡´íÎóÂëÊÇ£º" << GetLastError() << endl;
        return FALSE;
    }

    ExceptionInfo.OldCode = *(UCHAR *)Address;
    *(UCHAR *)Address = 0xCC;

    HookInfo.push_back(ExceptionInfo);

    VirtualProtect((PVOID)Address, 1, OldProtect, &OldProtect);
    return TRUE;
}

BOOL DeleteHook(ULONG_PTR Address)
{
    BOOL bSearch = FALSE;
    UCHAR OldCode = 0;

    for (list<EXCEPTION_HOOK>::iterator i = HookInfo.begin(); i != HookInfo.end(); ++i)
    {
        if (i->ExceptionAddress == Address)
        {
            OldCode = i->OldCode;
            
            HookInfo.erase(i);
            bSearch = TRUE;
            break;
        }
    }

    if (bSearch == FALSE)
    {
        cout << "µ±Ç°µØÖ·Ã»ÓÐ±»HOOK£¡" << endl;
        return FALSE;
    }

    ULONG OldProtect;
    BOOL bProtect = VirtualProtect((PVOID)Address, 1, PAGE_READWRITE, &OldProtect);
    if (bProtect == FALSE)
    {
        cout << "HOOKÊ§°Ü£¡´íÎóÂëÊÇ£º" << GetLastError() << endl;
        return FALSE;
    }

    *(UCHAR *)Address = OldCode;

    VirtualProtect((PVOID)Address, 1, OldProtect, &OldProtect);
    return TRUE;
}

int main()
{
    PVOID hVEH = AddVectoredExceptionHandler(1, MyVehHandle);
    if (hVEH == NULL)
    {
        cout << "×¢²áÊ§°Ü£¡´íÎóÂëÊÇ£º" << GetLastError() << endl;
        system("pause");
        return -1;
    }

    AddHook((ULONG_PTR)MessageBoxA);
    MessageBoxA(NULL, "test", "test_caption", MB_OK);

    system("pause");
    return 0;
}