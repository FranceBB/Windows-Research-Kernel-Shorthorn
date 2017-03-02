/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    kelonghornfunctions.c

Abstract:

    This module implements the kernel event objects. Functions are
    provided to initialize, pulse, read, reset, and set event objects.

--*/

#include "ki.h"

#define THREAD_ALERT_INCREMENT   2
ULONG globalUserExceptionCOunt = 0;

FORCEINLINE VOID KiAcquireDispatcherLockAtDpcLevel 	( 	VOID  		) 	
{
    /* This is a no-op at DPC Level for UP systems */
    return;
}
FORCEINLINE VOID KiAcquireApcLock 	( 	IN PKTHREAD  	Thread,
		IN PKLOCK_QUEUE_HANDLE  	Handle 
	) 		
{
    /* Acquire the lock and raise to synchronization level */
    KeAcquireInStackQueuedSpinLockRaiseToSynch(&Thread->ApcQueueLock, Handle);
}

FORCEINLINE VOID KiReleaseDispatcherLockFromDpcLevel(VOID) 	
{
    /* This is a no-op at DPC Level for UP systems */
    return;
}

FORCEINLINE VOID KiReleaseApcLockFromDpcLevel(IN PKLOCK_QUEUE_HANDLE  Handle) 	
{
    /* Release the lock */
    KeReleaseInStackQueuedSpinLockFromDpcLevel(Handle);
}

ULONG KeQueryActiveProcessorCount(
  OUT  PKAFFINITY ActiveProcessors
)
{
	return (ULONG)KeQueryActiveProcessors();
}

ULONG KeQueryMaximumProcessorCount(void)
{
	return 256;
}

ULONGLONG KeQueryUnbiasedInterruptTime(void)
{
	return KeQueryInterruptTime();
}

//review - reimplement
int KeInvalidateRangeAllCaches(PVOID BaseAddress, ULONG Length)
{
  int address; // esi@1
  int result; // eax@1

  KeInvalidateAllCaches();
#if defined(_i386_)
  address = *(DWORD *)(__readfsdword(32) + 956);
  result = (int)((char *)BaseAddress + Length - 1);
  while ( BaseAddress <= (PVOID)result )
#else
  address = *(DWORD *)(__readgsqword(32) + 956);
  result = (int)(ULONGLONG)((char *)BaseAddress + Length - 1);
  while ( BaseAddress <= (PVOID)(ULONGLONG)result )
#endif	  
  {
    _mm_clflush(BaseAddress);
    BaseAddress = (char *)BaseAddress + address;
  }
  return result;
}

//Reimplement
BOOLEAN KeSetCoalescableTimer(
  IN OUT   PKTIMER Timer,
  IN      LARGE_INTEGER DueTime,
  IN      ULONG Period,
  IN      ULONG TolerableDelay,
  IN   PKDPC Dpc
)
{
	return TRUE;
}

BOOLEAN KeSetUserExceptionCallout(ULONG userExceptionCount)
{
  BOOLEAN result; // al@2

  if ( globalUserExceptionCOunt )
  {
    result = FALSE;
  }
  else
  {
    globalUserExceptionCOunt = userExceptionCount;
    result = TRUE;
  }
  return result;
}

VOID KeRevertToUserAffinityThreadEx(
  IN  KAFFINITY Affinity
)
{
	KeRevertToUserAffinityThread();
}

VOID NTAPI KeInitializeMutantEx(	
	IN PKMUTANT 	Mutant,
	IN BOOLEAN 	InitialOwner, 
	IN LONG numbers
)	
{
	KeInitializeMutant(Mutant, InitialOwner);
}