// FFI for functions not yet implemented in the Rust Windows Driver project

use wdk_sys::PKTHREAD;
use core::{ffi::c_void, ptr::null_mut};

use wdk_sys::{_EVENT_TYPE::SynchronizationEvent, ACCESS_MASK, DISPATCH_LEVEL, FALSE, FAST_MUTEX, FM_LOCK_BIT, HANDLE, LIST_ENTRY, NTSTATUS, OBJECT_ATTRIBUTES, PHANDLE, PIO_STACK_LOCATION, PIRP, POBJECT_ATTRIBUTES, PSECURITY_DESCRIPTOR, PULONG, PUNICODE_STRING, ULONG, ntddk::{KeGetCurrentIrql, KeInitializeEvent}, UNICODE_STRING, BOOLEAN, KPROCESSOR_MODE, KAPC, PVOID, KPRIORITY};

pub unsafe fn IoGetCurrentIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION { unsafe {
    assert!((*irp).CurrentLocation <= (*irp).StackCount + 1); // todo maybe do error handling instead of an assert?
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
}}

#[allow(non_snake_case)]
pub unsafe fn ExInitializeFastMutex(kmutex: *mut FAST_MUTEX) { unsafe {
    // check IRQL
    let irql = unsafe { KeGetCurrentIrql() };
    assert!(irql as u32 <= DISPATCH_LEVEL);

    core::ptr::write_volatile(&mut (*kmutex).Count, FM_LOCK_BIT as i32);

    (*kmutex).Owner = core::ptr::null_mut();
    (*kmutex).Contention = 0;
    KeInitializeEvent(&mut (*kmutex).Event, SynchronizationEvent, FALSE as _)
}}

#[allow(non_snake_case)]
pub unsafe fn InitializeObjectAttributes(
    p: POBJECT_ATTRIBUTES,
    n: PUNICODE_STRING,
    a: ULONG,
    r: HANDLE,
    s: PSECURITY_DESCRIPTOR,
) -> Result<(), ()> { unsafe {

    if p.is_null() {
        return Err(());
    }

    (*p).Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    (*p).RootDirectory = r;
    (*p).Attributes = a;
    (*p).ObjectName = n;
    (*p).SecurityDescriptor = s;
    (*p).SecurityQualityOfService = null_mut();

    Ok(())
}}

unsafe extern "system" {
    pub unsafe fn PsGetProcessImageFileName(p_eprocess: *const c_void) -> *const c_void;
    pub unsafe fn NtQueryInformationProcess(
        handle: HANDLE,
        flags: i32,
        process_information: *mut c_void,
        len: ULONG,
        return_len: PULONG,
    ) -> NTSTATUS;
    
}


unsafe extern "system" {
    pub unsafe fn ZwGetNextProcess(
        handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_proc_handle: PHANDLE,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextThread(
        proc_handle: HANDLE,
        thread_handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_thread_handle: PHANDLE,
    ) -> NTSTATUS;

    pub unsafe fn KeInitializeApc(
        apc: *mut KAPC,
        thread: PKTHREAD,
        enviroment: KAPC_ENVIRONMENT,
        kernel_routine: PKKERNEL_ROUTINE,
        rundown_routine: PKRUNDOWN_ROUTINE,
        normal_routine: PKNORMAL_ROUTINE,
        processor_mode: KPROCESSOR_MODE,
        normal_context: *mut c_void
    );
    pub unsafe fn ZwAllocateVirtualMemory(
            ProcessHandle: HANDLE,
            BaseAddress: *mut PVOID,
            ZeroBits: usize,
            RegionSize: *mut usize,
            AllocationType: u32,
            Protect: u32,
        ) -> NTSTATUS;

    pub unsafe fn ExAllocatePool2(
    flags: u64, size: usize, tag: u32) -> PVOID;

    pub unsafe fn KeInsertQueueApc(
        Apc: *mut KAPC,
        sys_arg1: *mut c_void,
        sys_arg2: *mut c_void,
        increment: KPRIORITY,
    ) -> BOOLEAN;


}

unsafe extern "system" {
    pub static PsProcessType: *mut *mut c_void;
    pub static PsThreadType: *mut *mut c_void;
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum KAPC_ENVIRONMENT {
    OriginalApcEnvironment = 0,
    AttachedApcEnvironment = 1,
    CurrentApcEnvironment = 2,
    InsertApcEnvironment = 3,
}
pub type PKAPC_ENVIRONMENT = *mut KAPC_ENVIRONMENT;

pub type PKRUNDOWN_ROUTINE = Option<
    unsafe extern "system" fn(
        Apc: *mut KAPC,
    ),
>;

pub type PKNORMAL_ROUTINE = Option<
    unsafe extern "system" fn(
        NormalContext: *mut c_void,
        SystemArgument1: *mut c_void,
        SystemArgument2: *mut c_void,
    ),
>;

pub type PKKERNEL_ROUTINE = Option<
    unsafe extern "system" fn(
        Apc: *mut KAPC,
        NormalRoutine: *mut PKNORMAL_ROUTINE,
        NormalContext: *mut *mut c_void,
        SystemArgument1: *mut *mut c_void,
        SystemArgument2: *mut *mut c_void,
    ),
>;
#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*mut c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}