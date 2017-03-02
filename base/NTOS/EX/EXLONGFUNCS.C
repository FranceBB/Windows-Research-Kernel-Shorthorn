/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    exlongfuncs.c

Abstract:

    The module contains the the initialization code for the executive
    component. It also contains the display string and shutdown system
    services.

--*/

#include "exp.h"

KSPIN_LOCK ExNPagedLookasideLock;

KSPIN_LOCK ExPagedLookasideLock;

PSINGLE_LIST_ENTRY ExDeleteLookasideListEx(PSLIST_HEADER ListHead)
{
  KSPIN_LOCK *lock; // eax@1
  PSINGLE_LIST_ENTRY result; // eax@3
  struct _SINGLE_LIST_ENTRY *list; // edi@4

  lock = &ExNPagedLookasideLock;
  if ( ListHead[3].Alignment & 1 )
    lock = &ExPagedLookasideLock;
  //ExpRemoveGeneralLookaside((int)ListHead, lock);
  result = (PSINGLE_LIST_ENTRY)ExInterlockedFlushSList(ListHead);
  if ( result )
  {
    do
    {
      list = result->Next;
      ListHead[5].Alignment= (ULONGLONG)result;
      result = list;
    }
    while ( list );
  }
  return result;
}