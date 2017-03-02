/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    lazyrite.c

Abstract:

    This module implements the longhorn functions for the Cache subsystem.

--*/

#include "cc.h"
typedef unsigned long DWORD;

NTKERNELAPI NTSTATUS NTAPI CcSetFileSizesEx(IN PFILE_OBJECT FileObject, IN PCC_FILE_SIZES FileSizes) 	
{
	CcSetFileSizes(FileObject, FileSizes);
	return 0x00000000;
}

NTSTATUS CcGetCacheMapDirtyPageCount(PFILE_OBJECT FileObject, CSHORT type)
{
  PDEVICE_OBJECT deviceObject; // eax@1
  NTSTATUS result; // eax@2

  type = 0;
  deviceObject = FileObject->DeviceObject;
  if ( deviceObject )
  {
    type = deviceObject->DeviceQueue.Type;
    result = 0;
  }
  else
  {
    result = 0xC000000Du;
  }
  return result;
 }
 
void CcSetParallelFlushFile(PFILE_OBJECT FileObject, BOOLEAN verification)
{
  PFILE_OBJECT localFileObject; // esi@1
  KIRQL irq; // al@1

  localFileObject = (PFILE_OBJECT)FileObject->SectionObjectPointer->SharedCacheMap;
  irq = KeRaiseIrqlToDpcLevel();
  if ( verification )
#if defined(_i386_)
    localFileObject->CompletionContext = (PIO_COMPLETION_CONTEXT)((ULONG)localFileObject->CompletionContext | 0x40000);
#else
    localFileObject->CompletionContext = (PIO_COMPLETION_CONTEXT)((ULONGLONG)localFileObject->CompletionContext | 0x40000);
#endif
  else
#if defined(_i386_)
    localFileObject->CompletionContext = (PIO_COMPLETION_CONTEXT)((unsigned int)localFileObject->CompletionContext & 0xFFFBFFFF);
#else
    localFileObject->CompletionContext = (PIO_COMPLETION_CONTEXT)((ULONGLONG)localFileObject->CompletionContext & 0xFFFBFFFF);
#endif

#if defined(_i386_)
  KfLowerIrql(irq);
#else
  KeLowerIrql(irq);
#endif
}

BOOLEAN CcNewSetFileSizes(
  IN  PFILE_OBJECT FileObject,
  IN  PCC_FILE_SIZES FileSizes
)
{
	CcSetFileSizes(FileObject, FileSizes);
	return TRUE;
}

BOOLEAN CcIsThereDirtyDataEx(
  IN      PVPB Vpb,
  IN  PULONG NumberOfDirtyPages
)
{
	return CcIsThereDirtyData(Vpb);
}