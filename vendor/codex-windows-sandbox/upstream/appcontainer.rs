use crate::cap::workspace_read_cap_sid_for_workspace;
use crate::cap::workspace_write_cap_sid_for_root;
use crate::token::LocalSid;
use crate::winutil::to_wide;
use anyhow::Context;
use anyhow::Result;
use std::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationGetAppContainerConfig;
use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationSetAppContainerConfig;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::DeriveCapabilitySidsFromName;
use windows_sys::Win32::Security::EqualSid;
use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::System::Memory::GetProcessHeap;
use windows_sys::Win32::System::Memory::HeapFree;

pub const WINDOWS_WORKSPACE_CONTAINED_APPCONTAINER_NAME: &str = "RunSeal.WorkspaceContained";
const APPCONTAINER_DISPLAY_NAME: &str = "RunSeal workspace-contained";
const APPCONTAINER_DESCRIPTION: &str = "RunSeal LowBox for workspace-contained tools";
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

fn hresult_from_win32(code: u32) -> i32 {
    (0x8007_0000u32 | (code & 0xffff)) as i32
}

unsafe fn sid_to_string(sid: *mut c_void) -> Result<String> {
    let mut string_sid = std::ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut string_sid) == 0 || string_sid.is_null() {
        anyhow::bail!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut len = 0usize;
    while *string_sid.add(len) != 0 {
        len += 1;
    }
    let value = String::from_utf16_lossy(std::slice::from_raw_parts(string_sid, len));
    LocalFree(string_sid as HLOCAL);
    Ok(value)
}

pub fn ensure_appcontainer_profile_sid() -> Result<String> {
    let name = to_wide(WINDOWS_WORKSPACE_CONTAINED_APPCONTAINER_NAME);
    let display_name = to_wide(APPCONTAINER_DISPLAY_NAME);
    let description = to_wide(APPCONTAINER_DESCRIPTION);
    let mut sid = std::ptr::null_mut();
    let create_result = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display_name.as_ptr(),
            description.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if create_result < 0 && create_result != hresult_from_win32(ERROR_ALREADY_EXISTS) {
        anyhow::bail!(
            "CreateAppContainerProfile failed: HRESULT 0x{:08X}",
            create_result as u32
        );
    }
    if sid.is_null() {
        let derive_result =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if derive_result < 0 || sid.is_null() {
            anyhow::bail!(
                "DeriveAppContainerSidFromAppContainerName failed after profile creation: HRESULT 0x{:08X}",
                derive_result as u32
            );
        }
    }
    let result = unsafe { sid_to_string(sid) };
    unsafe { windows_sys::Win32::Security::FreeSid(sid) };
    result
}

pub fn ensure_appcontainer_loopback_exemption(appcontainer_sid: &str) -> Result<()> {
    let appcontainer_sid = LocalSid::from_string(appcontainer_sid)?;
    let mut existing_count = 0u32;
    let mut existing_entries: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
    let get_result = unsafe {
        NetworkIsolationGetAppContainerConfig(&mut existing_count, &mut existing_entries)
    };
    if get_result != 0 {
        anyhow::bail!("NetworkIsolationGetAppContainerConfig failed: win32 error {get_result}");
    }

    let existing = if existing_entries.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(existing_entries, existing_count as usize) }
    };
    let already_present = existing
        .iter()
        .any(|entry| unsafe { EqualSid(entry.Sid, appcontainer_sid.as_ptr()) } != 0);
    let result = if already_present {
        Ok(())
    } else {
        let mut combined = existing.to_vec();
        combined.push(SID_AND_ATTRIBUTES {
            Sid: appcontainer_sid.as_ptr(),
            Attributes: 0,
        });
        let set_result = unsafe {
            NetworkIsolationSetAppContainerConfig(combined.len() as u32, combined.as_ptr())
        };
        if set_result == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "NetworkIsolationSetAppContainerConfig failed: win32 error {set_result}"
            ))
        }
    };

    if !existing_entries.is_null() {
        unsafe {
            for entry in existing {
                if !entry.Sid.is_null() {
                    HeapFree(GetProcessHeap(), 0, entry.Sid);
                }
            }
            HeapFree(GetProcessHeap(), 0, existing_entries.cast::<c_void>());
        }
    }
    result
}

pub fn appcontainer_capability_sid(capability_name: &str) -> Result<String> {
    let capability_name = to_wide(capability_name);
    let mut group_sids = std::ptr::null_mut();
    let mut group_sid_count = 0u32;
    let mut capability_sids = std::ptr::null_mut();
    let mut capability_sid_count = 0u32;
    let ok = unsafe {
        DeriveCapabilitySidsFromName(
            capability_name.as_ptr(),
            &mut group_sids,
            &mut group_sid_count,
            &mut capability_sids,
            &mut capability_sid_count,
        )
    };
    if ok == 0 || capability_sids.is_null() || capability_sid_count == 0 {
        anyhow::bail!(
            "DeriveCapabilitySidsFromName failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let sid = unsafe { *capability_sids };
    let result = unsafe { sid_to_string(sid) };
    unsafe {
        for index in 0..group_sid_count as usize {
            let value = *group_sids.add(index);
            if !value.is_null() {
                LocalFree(value as HLOCAL);
            }
        }
        for index in 0..capability_sid_count as usize {
            let value = *capability_sids.add(index);
            if !value.is_null() {
                LocalFree(value as HLOCAL);
            }
        }
        LocalFree(group_sids as HLOCAL);
        LocalFree(capability_sids as HLOCAL);
    }
    result
}

pub fn appcontainer_capability_sid_from_seed(kind: &str, seed_sid: &str) -> Result<String> {
    appcontainer_capability_sid(&format!("runseal.workspace-contained.{kind}.{seed_sid}"))
}

pub fn appcontainer_write_capability_sid(seed_sid: &str) -> Result<String> {
    appcontainer_capability_sid_from_seed("write", seed_sid)
}

pub fn appcontainer_read_capability_sid(seed_sid: &str) -> Result<String> {
    appcontainer_capability_sid_from_seed("read", seed_sid)
}

pub fn workspace_appcontainer_read_capability_sid(
    codex_home: &Path,
    workspace_root: &Path,
) -> Result<String> {
    let seed = workspace_read_cap_sid_for_workspace(codex_home, workspace_root)?;
    appcontainer_read_capability_sid(&seed)
}

pub fn workspace_appcontainer_write_capability_sid(
    codex_home: &Path,
    workspace_root: &Path,
    writable_root: &Path,
) -> Result<String> {
    let seed = workspace_write_cap_sid_for_root(codex_home, workspace_root, writable_root)?;
    appcontainer_write_capability_sid(&seed)
}

pub struct AppContainerSecurityCapabilities {
    appcontainer_sid: LocalSid,
    capability_sids: Vec<LocalSid>,
    sid_and_attributes: Vec<SID_AND_ATTRIBUTES>,
    value: SECURITY_CAPABILITIES,
}

impl AppContainerSecurityCapabilities {
    pub fn new(capability_sid_strings: &[String]) -> Result<Self> {
        let appcontainer_sid = LocalSid::from_string(&ensure_appcontainer_profile_sid()?)?;
        let capability_sids = capability_sid_strings
            .iter()
            .map(|sid| {
                LocalSid::from_string(sid)
                    .with_context(|| format!("invalid AppContainer capability SID: {sid}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let sid_and_attributes = capability_sids
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_ptr(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect::<Vec<_>>();
        let value = SECURITY_CAPABILITIES {
            AppContainerSid: appcontainer_sid.as_ptr(),
            Capabilities: sid_and_attributes.as_ptr() as *mut SID_AND_ATTRIBUTES,
            CapabilityCount: sid_and_attributes.len() as u32,
            Reserved: 0,
        };
        Ok(Self {
            appcontainer_sid,
            capability_sids,
            sid_and_attributes,
            value,
        })
    }

    pub fn as_mut_ptr(&mut self) -> *mut SECURITY_CAPABILITIES {
        let _ = (
            &self.appcontainer_sid,
            &self.capability_sids,
            &self.sid_and_attributes,
        );
        &mut self.value
    }
}

#[cfg(test)]
mod tests {
    use super::appcontainer_read_capability_sid;
    use super::appcontainer_write_capability_sid;

    #[test]
    fn derived_capabilities_are_stable_and_separate_by_access_kind() {
        let seed = "S-1-5-21-100-200-300-400";
        let read = appcontainer_read_capability_sid(seed).expect("derive read capability SID");
        let repeated_read =
            appcontainer_read_capability_sid(seed).expect("derive repeated read capability SID");
        let write = appcontainer_write_capability_sid(seed).expect("derive write capability SID");

        assert_eq!(read, repeated_read);
        assert_ne!(read, write);
        assert!(read.starts_with("S-1-15-3-"));
        assert!(write.starts_with("S-1-15-3-"));
    }
}
