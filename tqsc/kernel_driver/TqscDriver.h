#pragma once

#include <ntifs.h>
#include <ntddk.h>

#define TQSC_DEVICE_NAME L"\\Device\\TqscDriver"
#define TQSC_SYMLINK_NAME L"\\DosDevices\\TqscDriver"

// IOCTLs
#define IOCTL_TQSC_GET_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TQSC_ADD_BLOCK_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Event structure for queue
typedef struct _TQSC_PROCESS_EVENT {
    HANDLE ParentId;
    HANDLE ProcessId;
    BOOLEAN Create;
} TQSC_PROCESS_EVENT, *PTQSC_PROCESS_EVENT;

// Linked list node for event
typedef struct _TQSC_EVENT_NODE {
    LIST_ENTRY ListEntry;
    TQSC_PROCESS_EVENT Event;
} TQSC_EVENT_NODE, *PTQSC_EVENT_NODE;
