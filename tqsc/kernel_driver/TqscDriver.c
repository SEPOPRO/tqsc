#include "TqscDriver.h"

// Globals
PDEVICE_OBJECT g_DeviceObject = NULL;
LIST_ENTRY g_EventQueue;
KSPIN_LOCK g_EventQueueLock;

#define MAX_BLOCKED_PIDS 1024
HANDLE g_BlockedPids[MAX_BLOCKED_PIDS];
ULONG g_BlockedPidCount = 0;
KSPIN_LOCK g_BlockListLock;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD TqscUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH TqscCreateClose;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH TqscCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH TqscDeviceControl;
void TqscProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;

    RtlInitUnicodeString(&devName, TQSC_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, TQSC_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = TqscCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TqscCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TqscDeviceControl;
    DriverObject->DriverUnload = TqscUnload;

    InitializeListHead(&g_EventQueue);
    KeInitializeSpinLock(&g_EventQueueLock);
    KeInitializeSpinLock(&g_BlockListLock);
    g_BlockedPidCount = 0;

    status = PsSetCreateProcessNotifyRoutineEx(TqscProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}

void TqscUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, TQSC_SYMLINK_NAME);

    PsSetCreateProcessNotifyRoutineEx(TqscProcessNotifyRoutineEx, TRUE);

    IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    while (!IsListEmpty(&g_EventQueue)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueue);
        PTQSC_EVENT_NODE node = CONTAINING_RECORD(entry, TQSC_EVENT_NODE, ListEntry);
        ExFreePoolWithTag(node, 'csqT');
    }
    KeReleaseSpinLock(&g_EventQueueLock, irql);
}

NTSTATUS TqscCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS TqscDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (controlCode) {
    case IOCTL_TQSC_GET_EVENTS:
    {
        if (outLength < sizeof(TQSC_PROCESS_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KIRQL irql;
        KeAcquireSpinLock(&g_EventQueueLock, &irql);
        if (IsListEmpty(&g_EventQueue)) {
            KeReleaseSpinLock(&g_EventQueueLock, irql);
            status = STATUS_NO_MORE_ENTRIES;
            break;
        }

        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueue);
        KeReleaseSpinLock(&g_EventQueueLock, irql);

        PTQSC_EVENT_NODE node = CONTAINING_RECORD(entry, TQSC_EVENT_NODE, ListEntry);
        RtlCopyMemory(buffer, &node->Event, sizeof(TQSC_PROCESS_EVENT));
        ExFreePoolWithTag(node, 'csqT');

        info = sizeof(TQSC_PROCESS_EVENT);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_TQSC_ADD_BLOCK_PID:
    {
        if (inLength < sizeof(HANDLE)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        HANDLE pid = *(PHANDLE)buffer;
        
        KIRQL irql;
        KeAcquireSpinLock(&g_BlockListLock, &irql);
        if (g_BlockedPidCount < MAX_BLOCKED_PIDS) {
            g_BlockedPids[g_BlockedPidCount++] = pid;
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
        KeReleaseSpinLock(&g_BlockListLock, irql);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

void TqscProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        BOOLEAN block = FALSE;
        
        KIRQL irql;
        KeAcquireSpinLock(&g_BlockListLock, &irql);
        for (ULONG i = 0; i < g_BlockedPidCount; i++) {
            if (g_BlockedPids[i] == ProcessId || g_BlockedPids[i] == CreateInfo->ParentProcessId) {
                block = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_BlockListLock, irql);

        if (block) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }
    }

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64
#endif

    PTQSC_EVENT_NODE node = (PTQSC_EVENT_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TQSC_EVENT_NODE), 'csqT');
    if (!node) {
        node = (PTQSC_EVENT_NODE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TQSC_EVENT_NODE), 'csqT');
    }
    if (node) {
        node->Event.ProcessId = ProcessId;
        node->Event.ParentId = (CreateInfo != NULL) ? CreateInfo->ParentProcessId : NULL;
        node->Event.Create = (CreateInfo != NULL);
        
        ExInterlockedInsertTailList(&g_EventQueue, &node->ListEntry, &g_EventQueueLock);
    }
}
