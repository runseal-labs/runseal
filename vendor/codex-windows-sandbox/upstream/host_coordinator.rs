use anyhow::{Result, anyhow};
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SetKernelObjectSecurity,
};
use windows_sys::Win32::System::Threading::CreateEventW;

struct SecurityDescriptor(*mut c_void);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0 as _);
        }
    }
}

/// Host coordination only. The event is non-inheritable, has a protected DACL,
/// and an existing object must belong to the current host principal.
pub fn create_host_coordinator_event(name: &str) -> Result<OwnedHandle> {
    let token = unsafe { crate::token::get_current_token_for_restriction()? };
    let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
    let sid = unsafe { crate::token::get_user_sid_bytes(token.as_raw_handle() as HANDLE)? };
    let user = crate::winutil::string_from_sid_bytes(&sid).map_err(anyhow::Error::msg)?;
    let descriptor = crate::winutil::to_wide(format!("O:{user}D:P(A;;GA;;;SY)(A;;GA;;;{user})"));
    let mut pointer = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            1,
            &mut pointer,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let descriptor = SecurityDescriptor(pointer);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name = crate::winutil::to_wide(name);
    let event = unsafe { CreateEventW(&attributes, 1, 0, name.as_ptr()) };
    if event == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let event = unsafe { OwnedHandle::from_raw_handle(event as _) };
    let mut owner = std::ptr::null_mut();
    let mut existing = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            event.as_raw_handle() as HANDLE,
            6,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut existing,
        )
    };
    let existing = SecurityDescriptor(existing);
    if status != 0 || owner.is_null() || unsafe { EqualSid(owner, sid.as_ptr() as _) } == 0 {
        return Err(anyhow!("host coordination object owner unavailable"));
    }
    // Creation attributes do not replace an existing object's security. Harden
    // it only after ownership has been verified; never mutate a foreign object.
    if unsafe {
        SetKernelObjectSecurity(
            event.as_raw_handle() as HANDLE,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    drop(existing);
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    };
    use windows_sys::Win32::System::Threading::{CreateMutexW, SetEvent, WaitForSingleObject};

    #[test]
    fn host_event_is_protected_noninheritable_and_reopen_does_not_clear_signal() -> Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let name = format!(
            "Global\\RunSealCoordinatorFixture-{}",
            tmp.path()
                .file_name()
                .ok_or_else(|| anyhow!("fixture name"))?
                .to_string_lossy()
        );
        let event = create_host_coordinator_event(&name)?;
        assert_ne!(unsafe { SetEvent(event.as_raw_handle() as HANDLE) }, 0);
        let reopened = create_host_coordinator_event(&name)?;
        assert_eq!(
            unsafe { WaitForSingleObject(reopened.as_raw_handle() as HANDLE, 0) },
            0
        );
        assert_eq!(
            unsafe { WaitForSingleObject(event.as_raw_handle() as HANDLE, 0) },
            0
        );
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(event.as_raw_handle() as HANDLE, &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let mut pointer = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    event.as_raw_handle() as HANDLE,
                    6,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut pointer,
                )
            },
            0
        );
        let descriptor = SecurityDescriptor(pointer);
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert_ne!(
            control & 0x1000,
            0,
            "DACL must be protected from inheritance"
        );
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert!(!acl.is_null(), "NULL DACL would grant unrestricted access");
        let token = unsafe { crate::token::get_current_token_for_restriction()? };
        let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
        let host = unsafe { crate::token::get_user_sid_bytes(token.as_raw_handle() as HANDLE)? };
        let system = crate::token::LocalSid::from_string("S-1-5-18")?;
        assert!(unsafe { (*acl).AceCount } > 0);
        for index in 0..unsafe { (*acl).AceCount } {
            let mut pointer = std::ptr::null_mut();
            assert_ne!(unsafe { GetAce(acl, u32::from(index), &mut pointer) }, 0);
            let ace = pointer as *const ACCESS_ALLOWED_ACE;
            assert_eq!(
                unsafe { (*ace).Header.AceType },
                0,
                "only allow ACEs are expected"
            );
            let sid = unsafe { &(*ace).SidStart as *const u32 as *mut c_void };
            assert!(
                unsafe { EqualSid(sid, host.as_ptr() as _) } != 0
                    || unsafe { EqualSid(sid, system.as_ptr()) } != 0,
                "no other principal may change the signal"
            );
        }
        Ok(())
    }

    #[test]
    fn conflicting_native_object_type_refuses_event_creation_without_mutation() -> Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let name = format!(
            "Global\\RunSealCoordinatorCollision-{}",
            tmp.path()
                .file_name()
                .ok_or_else(|| anyhow!("fixture name"))?
                .to_string_lossy()
        );
        let wide = crate::winutil::to_wide(&name);
        let mutex = unsafe { CreateMutexW(std::ptr::null_mut(), 0, wide.as_ptr()) };
        if mutex == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mutex = unsafe { OwnedHandle::from_raw_handle(mutex as _) };
        assert!(create_host_coordinator_event(&name).is_err());
        assert_eq!(
            unsafe { WaitForSingleObject(mutex.as_raw_handle() as HANDLE, 0) },
            0
        );
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::Threading::ReleaseMutex(mutex.as_raw_handle() as HANDLE)
            },
            0
        );
        Ok(())
    }
}
