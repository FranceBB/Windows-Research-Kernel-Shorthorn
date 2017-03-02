/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    lpclongfuncs.c

Abstract:

    Local Inter-Process Communication (LPC) request system services.

--*/

#include "lpcp.h"

//reimplement
NTSTATUS LpcReplyWaitReplyPortHelper(int a1, ULONG a2, int a3, int a4)
{
  ULONG other; // eax@2
  NTSTATUS result; // eax@8

  if ( (BYTE)a3 )
  {
    other = a2;
    if ( a2 & 3 )
      ExRaiseDatatypeMisalignment();
    if ( a2 >= MmUserProbeAddress )
      *(BYTE *)MmUserProbeAddress = 0;
  }
  else
  {
    other = a2;
  }
  result = 0x00000000;
  if ( result == 0xC0000703 )
    result = 0xC0000037u;
  if ( result == 0xC0000701 )
    result = 0xC0000253u;
  return result;
}

//UNKNOWN TYPES
NTSTATUS LpcReplyWaitReplyPort(int a1, int a2, int a3)
{
  return LpcReplyWaitReplyPortHelper(a1, a3, 0, a2);
}