use crate::logging;
use crate::token::get_current_token_for_restriction;
use crate::token::get_user_sid_bytes;
use crate::winutil::format_last_error;
use crate::winutil::string_from_sid_bytes;
use crate::winutil::to_wide;
use anyhow::Result;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use std::ffi::c_void;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::Authorization::SE_WINDOW_OBJECT;
use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_UNKNOWN;
use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::StationsAndDesktops::CloseDesktop;
use windows_sys::Win32::System::StationsAndDesktops::CloseWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::CreateDesktopW;
use windows_sys::Win32::System::StationsAndDesktops::CreateWindowStationW;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_CREATEMENU;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_CREATEWINDOW;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_DELETE;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_ENUMERATE;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_HOOKCONTROL;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_JOURNALPLAYBACK;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_JOURNALRECORD;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_READ_CONTROL;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_READOBJECTS;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_SWITCHDESKTOP;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_WRITE_DAC;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_WRITE_OWNER;
use windows_sys::Win32::System::StationsAndDesktops::DESKTOP_WRITEOBJECTS;
use windows_sys::Win32::System::StationsAndDesktops::GetProcessWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::GetUserObjectInformationW;
use windows_sys::Win32::System::StationsAndDesktops::SetProcessWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::UOI_NAME;
use windows_sys::Win32::UI::WindowsAndMessaging::CWF_CREATE_ONLY;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_ACCESSCLIPBOARD;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_ACCESSGLOBALATOMS;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_CREATEDESKTOP;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_ENUMDESKTOPS;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_ENUMERATE;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_EXITWINDOWS;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_READATTRIBUTES;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_READSCREEN;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_WRITEATTRIBUTES;

const DESKTOP_ALL_ACCESS: u32 = DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_CREATEMENU
    | DESKTOP_HOOKCONTROL
    | DESKTOP_JOURNALRECORD
    | DESKTOP_JOURNALPLAYBACK
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP
    | DESKTOP_DELETE
    | DESKTOP_READ_CONTROL
    | DESKTOP_WRITE_DAC
    | DESKTOP_WRITE_OWNER;
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000f_0000;
const WINDOW_STATION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED
    | WINSTA_ENUMDESKTOPS as u32
    | WINSTA_READATTRIBUTES as u32
    | WINSTA_ACCESSCLIPBOARD as u32
    | WINSTA_CREATEDESKTOP as u32
    | WINSTA_WRITEATTRIBUTES as u32
    | WINSTA_ACCESSGLOBALATOMS as u32
    | WINSTA_EXITWINDOWS as u32
    | WINSTA_ENUMERATE as u32
    | WINSTA_READSCREEN as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchDesktopMode {
    Default,
    PrivateDesktop,
    PrivateWindowStation,
}

impl LaunchDesktopMode {
    pub fn from_private_desktop(enabled: bool) -> Self {
        if enabled {
            Self::PrivateDesktop
        } else {
            Self::Default
        }
    }
}

pub struct LaunchDesktop {
    _private_desktop: Option<PrivateDesktop>,
    _private_window_station: Option<PrivateWindowStation>,
    startup_name: Vec<u16>,
}

impl LaunchDesktop {
    pub fn prepare(
        mode: LaunchDesktopMode,
        logs_base_dir: Option<&Path>,
        restricting_sids: &[*mut c_void],
    ) -> Result<Self> {
        match mode {
            LaunchDesktopMode::Default => Ok(Self {
                _private_desktop: None,
                _private_window_station: None,
                startup_name: to_wide("Winsta0\\Default"),
            }),
            LaunchDesktopMode::PrivateDesktop => {
                let private_desktop = PrivateDesktop::create(logs_base_dir, restricting_sids)?;
                let startup_name = to_wide(format!("Winsta0\\{}", private_desktop.name));
                Ok(Self {
                    _private_desktop: Some(private_desktop),
                    _private_window_station: None,
                    startup_name,
                })
            }
            LaunchDesktopMode::PrivateWindowStation => {
                let boundary = PrivateWindowStation::create(logs_base_dir, restricting_sids)?;
                let startup_name = to_wide(format!(
                    "{}\\{}",
                    boundary.station_name, boundary.desktop_name
                ));
                Ok(Self {
                    _private_desktop: None,
                    _private_window_station: Some(boundary),
                    startup_name,
                })
            }
        }
    }

    pub fn startup_info_desktop(&self) -> *mut u16 {
        self.startup_name.as_ptr() as *mut u16
    }
}

struct PrivateDesktop {
    handle: isize,
    name: String,
}

impl PrivateDesktop {
    fn create(logs_base_dir: Option<&Path>, restricting_sids: &[*mut c_void]) -> Result<Self> {
        let mut rng = SmallRng::from_entropy();
        let name = format!("RunSealSandboxDesktop-{:x}", rng.r#gen::<u128>());
        let name_wide = to_wide(&name);
        let handle = unsafe {
            CreateDesktopW(
                name_wide.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                0,
                DESKTOP_ALL_ACCESS,
                ptr::null_mut(),
            )
        };
        if handle == 0 {
            let err = unsafe { GetLastError() } as i32;
            logging::debug_log(
                &format!(
                    "CreateDesktopW failed for {name}: {} ({})",
                    err,
                    format_last_error(err),
                ),
                logs_base_dir,
            );
            return Err(anyhow::anyhow!("CreateDesktopW failed: {err}"));
        }

        unsafe {
            if let Err(err) = grant_window_object_access(
                handle,
                DESKTOP_ALL_ACCESS,
                "private desktop",
                logs_base_dir,
                restricting_sids,
            ) {
                let _ = CloseDesktop(handle);
                return Err(err);
            }
        }

        Ok(Self { handle, name })
    }
}

struct PrivateWindowStation {
    station_handle: isize,
    desktop_handle: isize,
    station_name: String,
    desktop_name: String,
}

impl PrivateWindowStation {
    fn create(logs_base_dir: Option<&Path>, restricting_sids: &[*mut c_void]) -> Result<Self> {
        unsafe {
            let previous_station = GetProcessWindowStation();
            if previous_station == 0 {
                return Err(anyhow::anyhow!("GetProcessWindowStation failed"));
            }

            let token = get_current_token_for_restriction()?;
            let user_sid = get_user_sid_bytes(token);
            CloseHandle(token);
            let mut user_sid = user_sid?;
            let user_sid_string = string_from_sid_bytes(&user_sid).map_err(anyhow::Error::msg)?;
            let station_sddl = to_wide(format!("D:P(A;;GA;;;{user_sid_string})"));
            let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                station_sddl.as_ptr(),
                1,
                &mut security_descriptor,
                ptr::null_mut(),
            ) == 0
            {
                let error = GetLastError() as i32;
                return Err(anyhow::anyhow!(
                    "Create private window station security descriptor failed: {error} ({})",
                    format_last_error(error)
                ));
            }
            let security_attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: security_descriptor,
                bInheritHandle: 0,
            };
            let station_handle = CreateWindowStationW(
                ptr::null(),
                CWF_CREATE_ONLY,
                WINDOW_STATION_ALL_ACCESS,
                &security_attributes,
            );
            let station_error = GetLastError() as i32;
            let _ = LocalFree(security_descriptor as HLOCAL);
            if station_handle == 0 {
                return Err(anyhow::anyhow!(
                    "CreateWindowStationW failed: {station_error} ({})",
                    format_last_error(station_error)
                ));
            }
            let mut access_sids = Vec::with_capacity(restricting_sids.len() + 1);
            access_sids.push(user_sid.as_mut_ptr().cast());
            access_sids.extend_from_slice(restricting_sids);
            if let Err(error) = grant_window_object_access_to_sids(
                station_handle,
                WINDOW_STATION_ALL_ACCESS,
                "private window station",
                logs_base_dir,
                &access_sids,
            ) {
                let _ = CloseWindowStation(station_handle);
                return Err(error);
            }
            if SetProcessWindowStation(station_handle) == 0 {
                let error = GetLastError() as i32;
                let _ = SetProcessWindowStation(previous_station);
                let _ = CloseWindowStation(station_handle);
                return Err(anyhow::anyhow!(
                    "SetProcessWindowStation failed: {error} ({})",
                    format_last_error(error)
                ));
            }

            let setup_result = (|| -> Result<(String, String, isize)> {
                let station_name = window_object_name(station_handle)?;
                let mut rng = SmallRng::from_entropy();
                let desktop_name = format!("RunSealSandboxDesktop-{:x}", rng.r#gen::<u128>());
                let desktop_name_wide = to_wide(&desktop_name);
                let desktop_handle = CreateDesktopW(
                    desktop_name_wide.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    DESKTOP_ALL_ACCESS,
                    ptr::null_mut(),
                );
                if desktop_handle == 0 {
                    let error = GetLastError() as i32;
                    return Err(anyhow::anyhow!(
                        "CreateDesktopW failed in private window station: {error} ({})",
                        format_last_error(error)
                    ));
                }
                if let Err(error) = grant_window_object_access_to_sids(
                    desktop_handle,
                    DESKTOP_ALL_ACCESS,
                    "private window station desktop",
                    logs_base_dir,
                    &access_sids,
                ) {
                    let _ = CloseDesktop(desktop_handle);
                    return Err(error);
                }
                Ok((station_name, desktop_name, desktop_handle))
            })();

            if SetProcessWindowStation(previous_station) == 0 {
                let error = GetLastError() as i32;
                if let Ok((_, _, desktop_handle)) = setup_result {
                    let _ = CloseDesktop(desktop_handle);
                }
                return Err(anyhow::anyhow!(
                    "SetProcessWindowStation restore failed: {error} ({})",
                    format_last_error(error)
                ));
            }

            match setup_result {
                Ok((station_name, desktop_name, desktop_handle)) => Ok(Self {
                    station_handle,
                    desktop_handle,
                    station_name,
                    desktop_name,
                }),
                Err(error) => {
                    let _ = CloseWindowStation(station_handle);
                    Err(error)
                }
            }
        }
    }
}

unsafe fn window_object_name(handle: isize) -> Result<String> {
    let mut required_bytes = 0;
    let _ = GetUserObjectInformationW(handle, UOI_NAME, ptr::null_mut(), 0, &mut required_bytes);
    if required_bytes < 2 {
        return Err(anyhow::anyhow!("window object name is unavailable"));
    }
    let mut buffer = vec![0u16; required_bytes.div_ceil(2) as usize];
    if GetUserObjectInformationW(
        handle,
        UOI_NAME,
        buffer.as_mut_ptr().cast(),
        required_bytes,
        &mut required_bytes,
    ) == 0
    {
        let error = GetLastError() as i32;
        return Err(anyhow::anyhow!(
            "GetUserObjectInformationW failed: {error} ({})",
            format_last_error(error)
        ));
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

unsafe fn grant_window_object_access(
    handle: isize,
    access_permissions: u32,
    object_label: &str,
    logs_base_dir: Option<&Path>,
    restricting_sids: &[*mut c_void],
) -> Result<()> {
    let token = get_current_token_for_restriction()?;
    let mut user_sid = get_user_sid_bytes(token)?;
    CloseHandle(token);

    let mut access_sids = Vec::with_capacity(restricting_sids.len() + 1);
    access_sids.push(user_sid.as_mut_ptr().cast());
    access_sids.extend_from_slice(restricting_sids);
    grant_window_object_access_to_sids(
        handle,
        access_permissions,
        object_label,
        logs_base_dir,
        &access_sids,
    )
}

unsafe fn grant_window_object_access_to_sids(
    handle: isize,
    access_permissions: u32,
    object_label: &str,
    logs_base_dir: Option<&Path>,
    sids: &[*mut c_void],
) -> Result<()> {
    let entries = sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: access_permissions,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: (*sid).cast(),
            },
        })
        .collect::<Vec<_>>();

    let mut updated_dacl = ptr::null_mut();
    let set_entries_code = SetEntriesInAclW(
        entries.len() as u32,
        entries.as_ptr(),
        ptr::null_mut(),
        &mut updated_dacl,
    );
    if set_entries_code != ERROR_SUCCESS {
        logging::debug_log(
            &format!("SetEntriesInAclW failed for {object_label}: {set_entries_code}"),
            logs_base_dir,
        );
        return Err(anyhow::anyhow!(
            "SetEntriesInAclW failed for {object_label}: {set_entries_code}"
        ));
    }

    let set_security_code = SetSecurityInfo(
        handle,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        ptr::null_mut(),
        ptr::null_mut(),
        updated_dacl,
        ptr::null_mut(),
    );
    if !updated_dacl.is_null() {
        LocalFree(updated_dacl as HLOCAL);
    }
    if set_security_code != ERROR_SUCCESS {
        logging::debug_log(
            &format!("SetSecurityInfo failed for {object_label}: {set_security_code}"),
            logs_base_dir,
        );
        return Err(anyhow::anyhow!(
            "SetSecurityInfo failed for {object_label}: {set_security_code}"
        ));
    }

    Ok(())
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        unsafe {
            if self.handle != 0 {
                let _ = CloseDesktop(self.handle);
            }
        }
    }
}

impl Drop for PrivateWindowStation {
    fn drop(&mut self) {
        unsafe {
            if self.desktop_handle != 0 {
                let _ = CloseDesktop(self.desktop_handle);
            }
            if self.station_handle != 0 {
                let _ = CloseWindowStation(self.station_handle);
            }
        }
    }
}
