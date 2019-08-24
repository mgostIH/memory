//! Mod that defines every basic winapi function we'll have to call

use std::io::Error;
use std::io::Result;
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::um::winnt::HANDLE;

pub use winapi::um::winnt::{
    PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
    PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, SYNCHRONIZE,
};

pub use winapi::um::winnt::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_TARGETS_INVALID,
    PAGE_TARGETS_NO_UPDATE, PAGE_WRITECOMBINE, PAGE_WRITECOPY,
};

pub use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RESET, MEM_RESET_UNDO};

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
/// `lpNumberOfBytesWritten` is ignored
pub unsafe fn write_process_memory(
    proc_handle: HANDLE,
    address: LPVOID,
    buffer: &[u8],
) -> Result<()> {
    use winapi::um::memoryapi::WriteProcessMemory;
    if WriteProcessMemory(
        proc_handle,
        address,
        buffer.as_ptr() as LPVOID,
        buffer.len(),
        std::ptr::null_mut(),
    ) != 0
    {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
/// `lpNumberOfBytesRead` is ignored
pub unsafe fn read_process_memory(
    proc_handle: HANDLE,
    address: LPCVOID,
    buffer: &mut [u8],
) -> Result<()> {
    use winapi::um::memoryapi::ReadProcessMemory;
    if ReadProcessMemory(
        proc_handle,
        address,
        buffer.as_mut_ptr() as LPVOID,
        buffer.len(),
        std::ptr::null_mut(),
    ) != 0
    {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
/// In case of success, the value of the old page protection is returned
pub unsafe fn virtual_protect_ex(
    proc_handle: HANDLE,
    address: LPVOID,
    size: usize,
    protection_flags: u32,
) -> Result<u32> {
    use winapi::um::memoryapi::VirtualProtectEx;
    let mut old_protect: u32 = 0;
    if VirtualProtectEx(
        proc_handle,
        address,
        size,
        protection_flags,
        &mut old_protect,
    ) != 0
    {
        Ok(old_protect)
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
/// In case of success, the value of the old page protection is returned
pub unsafe fn virtual_protect(address: LPVOID, size: usize, protection_flags: u32) -> Result<u32> {
    use winapi::um::memoryapi::VirtualProtect;

    let mut old_protect: u32 = 0;
    if VirtualProtect(address, size, protection_flags, &mut old_protect) != 0 {
        Ok(old_protect)
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
/// In case of success, the pointer to the allocated page is returned
/// No specific address is requested
pub unsafe fn virtual_alloc_ex(
    proc_handle: HANDLE,
    size: usize,
    allocation_flags: u32,
    protection_flags: u32,
) -> Result<LPVOID> {
    use winapi::um::memoryapi::VirtualAllocEx;

    let memory = VirtualAllocEx(
        proc_handle,
        std::ptr::null_mut(),
        size,
        allocation_flags,
        protection_flags,
    );

    if !memory.is_null() {
        Ok(memory)
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
/// In case of success, the pointer to the allocated page is returned
/// No specific address is requested
pub unsafe fn virtual_alloc(
    size: usize,
    allocation_flags: u32,
    protection_flags: u32,
) -> Result<LPVOID> {
    use winapi::um::memoryapi::VirtualAlloc;

    let memory = VirtualAlloc(
        std::ptr::null_mut(),
        size,
        allocation_flags,
        protection_flags,
    );

    if !memory.is_null() {
        Ok(memory)
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
/// In case of success, a handle to the process is returned
/// Handle inheritance is not supported (not cared for)
pub unsafe fn open_process(desired_access: u32, process_id: u32) -> Result<HANDLE> {
    use winapi::um::processthreadsapi::OpenProcess;

    let process_handle = OpenProcess(desired_access, 0, process_id);
    if !process_handle.is_null() {
        Ok(process_handle)
    } else {
        Err(Error::last_os_error())
    }
}

#[inline]
/// API equivalent to https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
/// The pseudohandle is -1 in value, thus there's no need to call the actual API
/// The value returned is a valid handle to the calling process
pub const fn get_current_process() -> HANDLE {
    -1 as isize as HANDLE
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
/// The value returned is the process identifier of the calling process
pub fn get_current_process_id() -> u32 {
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    unsafe { GetCurrentProcessId() }
}

#[inline]
/// API extracted from https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
/// This function is unsafe because closing a handle twice will trigger an exception when debugged
pub unsafe fn close_handle(handle: HANDLE) {
    use winapi::um::handleapi::CloseHandle;
    CloseHandle(handle);
}
