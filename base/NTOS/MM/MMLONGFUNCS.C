#include "mi.h"

typedef MDL* PMDLX;
typedef NTSTATUS(NTAPI * PMM_ROTATE_COPY_CALLBACK_FUNCTION)(IN PMDL DestinationMdl, IN PMDL SourceMdl, IN PVOID Context);
typedef unsigned long DWORD; //Provisório, mover para algum header depois
typedef int NODE_REQUIREMENT;

typedef enum _MM_ROTATE_DIRECTION {
   MmToFrameBuffer,
   MmToFrameBufferNoCopy,
   MmToRegularMemory,
   MmToRegularMemoryNoCopy,
   MmMaximumRotateDirection
} MM_ROTATE_DIRECTION, *PMM_ROTATE_DIRECTION;

NTSTATUS
NTAPI
MmRotatePhysicalView(
   IN PVOID VirtualAddress,
   PSIZE_T NumberOfBytes,
   IN PMDLX NewMdl,
   IN MM_ROTATE_DIRECTION Direction,
   IN PMM_ROTATE_COPY_CALLBACK_FUNCTION CopyFunction,
   PVOID Context)
{
	return 0x0000000;
}
/*
PVOID NTAPI MmAllocateContiguousMemorySpecifyCacheNode(
	SIZE_T NumberOfBytes, 
	PHYSICAL_ADDRESS LowestAcceptableAddress, 
	PHYSICAL_ADDRESS HighestAcceptableAddress, 
	PHYSICAL_ADDRESS BoundaryAddressMultiple, 
	MEMORY_CACHING_TYPE CacheType, 
	NODE_REQUIREMENT PreferredNode)
{
  PHYSICAL_ADDRESS LocalLowestAddress; // edi@1
  PVOID result; // eax@4
  PHYSICAL_ADDRESS GlobalAddress; // qax@5

  LocalLowestAddress = LowestAcceptableAddress >> 12;
  if ( LowestAcceptableAddress & 0xFFF )
    ++LocalLowestAddress;
  if ( BoundaryAddressMultiple & 0xFFF )
  {
    result = 0;
  }
  else
  {
    GlobalAddress = HighestAcceptableAddress >> 12;
    if ( (HighestAcceptableAddress >> 12) > MmHighestPossiblePhysicalPage )
      GlobalAddress) = MmHighestPossiblePhysicalPage;
    if ( LocalLowestAddress <= GlobalAddress )
      result = MiAllocateContiguousMemory(NumberOfBytes, GlobalAddress);
    else
      result = 0;
  }
  return result;
}*/
