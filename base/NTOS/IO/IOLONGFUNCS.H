#include "./IOMGR/iomgr.h" //Novos tipos para as funções encontradas aqui estão nesse header
#include <setupblk.h>
#include <inbv.h>
#include <ntddstor.h>
#include <hdlsblk.h>
#include <hdlsterm.h>

typedef BOOLEAN
 (NTAPI KMESSAGE_SERVICE_ROUTINE)(
   IN struct _KINTERRUPT *Interrupt,
   IN PVOID ServiceContext,
   IN ULONG MessageID);

typedef KMESSAGE_SERVICE_ROUTINE *PKMESSAGE_SERVICE_ROUTINE;

// ENUMERATIONS
/*
typedef enum _KINTERRUPT_POLARITY { 
  InterruptPolarityUnknown,
  InterruptActiveHigh,
  InterruptRisingEdge             = InterruptActiveHigh,
  InterruptActiveLow,
  InterruptFallingEdge            = InterruptActiveLow,
  InterruptActiveBoth,
  InterruptActiveBothTriggerLow   = InterruptActiveBoth,
  InterruptActiveBothTriggerHigh
} KINTERRUPT_POLARITY, *PKINTERRUPT_POLARITY;

typedef enum _IO_PRIORITY_HINT { 
  IoPriorityVeryLow   = 0,
  IoPriorityLow       = 1,
  IoPriorityNormal    = 2,
  IoPriorityHigh      = 3,
  IoPriorityCritical  = 4,
  MaxIoPriorityTypes  = 5
} IO_PRIORITY_HINT;

//END ENUMERATIONS

typedef struct _IO_INTERRUPT_MESSAGE_INFO_ENTRY {
  PHYSICAL_ADDRESS    MessageAddress;
  KAFFINITY           TargetProcessorSet;
  PKINTERRUPT         InterruptObject;
  ULONG               MessageData;
  ULONG               Vector;
  KIRQL               Irql;
  KINTERRUPT_MODE     Mode;
  KINTERRUPT_POLARITY Polarity;
} IO_INTERRUPT_MESSAGE_INFO_ENTRY, *PIO_INTERRUPT_MESSAGE_INFO_ENTRY;

typedef struct _IO_INTERRUPT_MESSAGE_INFO {
  KIRQL                           UnifiedIrql;
  ULONG                           MessageCount;
  IO_INTERRUPT_MESSAGE_INFO_ENTRY MessageInfo[1];
} IO_INTERRUPT_MESSAGE_INFO, *PIO_INTERRUPT_MESSAGE_INFO;

typedef struct _IO_DISCONNECT_INTERRUPT_PARAMETERS {
  ULONG Version;
  union {
    PVOID                      Generic;
    PKINTERRUPT                InterruptObject;
    PIO_INTERRUPT_MESSAGE_INFO InterruptMessageTable;
  } ConnectionContext;
} IO_DISCONNECT_INTERRUPT_PARAMETERS, *PIO_DISCONNECT_INTERRUPT_PARAMETERS;

typedef struct _IO_CONNECT_INTERRUPT_PARAMETERS {
  ULONG Version;
  union {
    struct {
      PDEVICE_OBJECT    PhysicalDeviceObject;
      PKINTERRUPT       *InterruptObject;
      PKSERVICE_ROUTINE ServiceRoutine;
      PVOID             ServiceContext;
      PKSPIN_LOCK       SpinLock;
      KIRQL             SynchronizeIrql;
      BOOLEAN           FloatingSave;
      BOOLEAN           ShareVector;
      ULONG             Vector;
      KIRQL             Irql;
      KINTERRUPT_MODE   InterruptMode;
      KAFFINITY         ProcessorEnableMask;
      USHORT            Group;
    } FullySpecified;
    struct {
      PDEVICE_OBJECT    PhysicalDeviceObject;
      PKINTERRUPT       *InterruptObject;
      PKSERVICE_ROUTINE ServiceRoutine;
      PVOID             ServiceContext;
      PKSPIN_LOCK       SpinLock;
      KIRQL             SynchronizeIrql;
      BOOLEAN           FloatingSave;
    } LineBased;
    struct {
      PDEVICE_OBJECT            PhysicalDeviceObject;
      union {
        PVOID                      *Generic;
        PIO_INTERRUPT_MESSAGE_INFO *InterruptMessageTable;
        PKINTERRUPT                *InterruptObject;
      } ConnectionContext;
      PKMESSAGE_SERVICE_ROUTINE MessageServiceRoutine;
      PVOID                     ServiceContext;
      PKSPIN_LOCK               SpinLock;
      KIRQL                     SynchronizeIrql;
      BOOLEAN                   FloatingSave;
      PKSERVICE_ROUTINE         FallBackServiceRoutine;
    } MessageBased;
  };
} IO_CONNECT_INTERRUPT_PARAMETERS, *PIO_CONNECT_INTERRUPT_PARAMETERS;*/