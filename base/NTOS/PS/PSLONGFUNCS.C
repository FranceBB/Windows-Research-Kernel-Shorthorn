/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    pslongfuncs.c

Abstract:

    This module implements LONGHORN/VISTA functions

--*/

#include "psp.h"

PLEGO_NOTIFY_ROUTINE PspLegoNotifyRoutine;

ULONG PsGetCurrentProcessSessionIdEx()
{
	return PsGetCurrentProcessSessionId();
}

BOOLEAN PsIsProtectedProcess(PEPROCESS Process)
{
  return (BOOLEAN)(Process->Flags >> 11) & 1;
}

BOOLEAN PsIsSecureProcess(PEPROCESS Process)
{
  return (BOOLEAN)(Process->Flags >> 11) & 1;
}


NTSTATUS PfFileInfoNotify(int a1)
{
	return 0;
}

ULONG NTAPI PsSetLegoNotifyRoutine(PVOID LegoNotifyRoutine)	
{
    /* Set the System-Wide Lego Routine */
    PspLegoNotifyRoutine = LegoNotifyRoutine;

    /* Return the location to the Lego Data */
    return FIELD_OFFSET(KTHREAD, LegoData);
}