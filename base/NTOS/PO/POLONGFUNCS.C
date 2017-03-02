/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

   polongfuncs.c

Abstract:

    This module contains the routines which implement the
    transactions for files and registry.

--*/

#include <po.h>

PFAST_MUTEX mutex;

VOID PoSetDeviceBusyEx(
  IN  PULONG IdlePointer
)
{
	PoSetDeviceBusy(IdlePointer);
}


NTSTATUS PoUnregisterPowerSettingCallback(PVOID *handle)
{
  NTSTATUS result; // eax@2
  PVOID local; // eax@5
  NTSTATUS status; // esi@6
  PVOID other; // ecx@7

  if ( handle )
  {
    if ( handle[2] == (PVOID)0x74655350 )
    {
      local = *handle;
      if ( *handle == handle )
      {
        status = 0xC000000Du;
      }
      else
      {
        other = *(PVOID *)(*((DWORD64 *)local + 1) + 4);
        local = other;
        other = local;
        ExFreePoolWithTag(handle, 0x74655350u);
        status = 0;
      }
      result = status;
    }
    else
    {
      result = 0xC000000Du;
    }
  }
  else
  {
    result = 0xC000000Du;
  }
  return result;
}

typedef NTSTATUS
(NTAPI POWER_SETTING_CALLBACK)(
  IN LPCGUID SettingGuid,
  IN PVOID Value,
  IN ULONG ValueLength,
  IN PVOID Context);
typedef POWER_SETTING_CALLBACK *PPOWER_SETTING_CALLBACK;

//unimplemented
NTSTATUS PoRegisterPowerSettingCallback(
  IN  PDEVICE_OBJECT DeviceObject,
  IN  LPCGUID SettingGuid,
  IN  PPOWER_SETTING_CALLBACK Callback,
  IN  PVOID Context,
  IN  PVOID *Handle
)
{
	return 0x00000000;
}


void PoReenableSleepStates(PVOID P)
{
  PVOID localPOther; // ecx@1
  PVOID localP; // eax@1

  ExInitializeFastMutex(mutex);
  ExAcquireFastMutex(mutex);
#if defined(_i386_)
  localPOther = (PVOID)*((DWORD *)P + 1);
#else
  localPOther = (PVOID)(ULONGLONG)((DWORD *)P + 1);
#endif	  
  localP = P;
  localPOther = P;
  localP = localPOther;
  ExReleaseFastMutex(mutex);
  ExFreePoolWithTag(P, 0x64536F50u);
}

//unimplemented
NTSTATUS PoDisableSleepStates(PVOID a1, PVOID a2, PVOID a3)
{
	return 0x00000000;
}