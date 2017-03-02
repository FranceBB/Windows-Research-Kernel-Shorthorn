/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

   whealongfuncs.c

Abstract:

    This module contains the routines which implement the
    Event log for files and registry.

--*/

#include "whea.h"

static PVOID WheapErrorSourceInitializer[20];

PVOID NTAPI WheapDefaultErrSrcInitializer(PVOID a1, PVOID a2)
{
  return NULL;
}

NTSTATUS NTAPI WheaRegisterErrSrcInitializer(int Number, PVOID call)
{
  PVOID *procedure; // eax@3
  NTSTATUS result; // eax@4

  if ( Number > 7 )
  {
    result = STATUS_INVALID_PARAMETER_1;
  }
  else
  {
    if ( call )
    {
      procedure = &WheapErrorSourceInitializer[Number];
      if ( (PVOID (__stdcall *)(PVOID, PVOID))*procedure == WheapDefaultErrSrcInitializer )
      {
        *procedure = call;
        result = STATUS_SUCCESS;
      }
      else
      {
        result = STATUS_UNSUCCESSFUL;
      }
    }
    else
    {
      result = STATUS_INVALID_PARAMETER_2;
    }
  }
  return result;
}