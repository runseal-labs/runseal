mod filter_specs;

use crate::LocalSid;
use crate::to_wide;
use anyhow::Result;
use std::ffi::OsStr;
use std::mem::zeroed;
use std::ptr::null;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::FWP_E_ALREADY_EXISTS;
use windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_NOT_FOUND;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTRL_MATCH_FILTER;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_LOOPBACK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_EMPTY;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_EQUAL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_FLAGS_ALL_SET;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_FLAGS_NONE_SET;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_RANGE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_RANGE_TYPE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_RANGE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_SECURITY_DESCRIPTOR_TYPE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_SID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT32;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_PACKAGE_ID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_USER_ID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_FLAGS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_PROTOCOL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionAbort0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionBegin0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionCommit0;
use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
use windows_sys::Win32::Security::Authorization::BuildExplicitAccessWithNameW;
use windows_sys::Win32::Security::Authorization::BuildSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use filter_specs::ConditionSpec;
use filter_specs::FILTER_SPECS;
use filter_specs::FilterSpec;

const SESSION_NAME: &str = "RunSeal Windows Sandbox WFP";
const PROVIDER_NAME: &str = "RunSeal Windows Sandbox WFP";
const PROVIDER_DESCRIPTION: &str = "Persistent WFP provider for RunSeal Windows sandbox filters";
const SUBLAYER_NAME: &str = "RunSeal Windows Sandbox WFP";
const SUBLAYER_DESCRIPTION: &str = "Persistent WFP sublayer for RunSeal Windows sandbox filters";

// WFP identifies persistent providers, sublayers, and filters by stable GUIDs.
// These values are RunSeal-owned identities; do not regenerate them unless we
// intentionally want to orphan old objects and create a new WFP namespace.
const PROVIDER_KEY: GUID = GUID::from_u128(0x524bbcd9_3c6a_4b8f_8ce0_53aa6ae27f2c);
const SUBLAYER_KEY: GUID = GUID::from_u128(0xccd151ec_1095_4f7c_b795_b55aefdcd10d);
const LOOPBACK_TCP_V4_FILTER_KEY_BASE: u128 = 0xb9572700_1f5e_4fa1_9100_000000000000;
const LOOPBACK_TCP_V6_FILTER_KEY_BASE: u128 = 0x87a34600_4d4d_42d8_a200_000000000000;
const LOOPBACK_PACKAGE_TCP_V4_FILTER_KEY_BASE: u128 = 0x70ef6100_b637_4512_b300_000000000000;
const LOOPBACK_PACKAGE_TCP_V6_FILTER_KEY_BASE: u128 = 0x9e782b00_84b1_4caf_b400_000000000000;
const LOOPBACK_USER_UDP_V4_FILTER_KEY: GUID =
    GUID::from_u128(0x488f4e56_b540_4ba9_a9bb_6ad3a9317d7a);
const LOOPBACK_USER_UDP_V6_FILTER_KEY: GUID =
    GUID::from_u128(0xcac28f66_b5a8_41f2_b794_beb113052efb);
const LOOPBACK_PACKAGE_UDP_V4_FILTER_KEY: GUID =
    GUID::from_u128(0xb5b9785e_0c95_4e23_8d8c_f96c3607ae90);
const LOOPBACK_PACKAGE_UDP_V6_FILTER_KEY: GUID =
    GUID::from_u128(0xaf3ac7e4_36a2_40db_bf66_8dcaa0df21d8);
const MAX_PROXY_PORTS: usize = 32;

/// Installs persistent RunSeal WFP filters for the sandbox account.
///
/// This is intended to run from the already-elevated setup helper. Callers
/// must fail setup if any returned error prevents these filters from being
/// installed.
pub fn install_wfp_filters_for_account(
    account: &str,
    appcontainer_sid: Option<&str>,
    proxy_ports: &[u16],
) -> Result<usize> {
    let engine = Engine::open()?;
    let mut transaction = engine.begin_transaction()?;
    ensure_provider(engine.handle)?;
    ensure_sublayer(engine.handle)?;

    let user_condition = UserMatchCondition::for_accounts(&[account])?;
    let mut installed_filter_count = 0;
    for spec in FILTER_SPECS {
        delete_filter_if_present(engine.handle, &spec.key)?;
        add_filter(engine.handle, spec, &user_condition)?;
        installed_filter_count += 1;
    }
    let appcontainer_sid = appcontainer_sid.map(LocalSid::from_string).transpose()?;
    installed_filter_count += install_loopback_filters(
        engine.handle,
        &user_condition,
        appcontainer_sid.as_ref(),
        proxy_ports,
    )?;

    transaction.commit()?;
    Ok(installed_filter_count)
}

fn blocked_port_ranges(proxy_ports: &[u16]) -> Result<Vec<(u16, u16)>> {
    let mut allowed = proxy_ports
        .iter()
        .copied()
        .filter(|port| *port != 0)
        .collect::<Vec<_>>();
    allowed.sort_unstable();
    allowed.dedup();
    if allowed.len() > MAX_PROXY_PORTS {
        anyhow::bail!(
            "sandbox proxy config has {} ports; at most {MAX_PROXY_PORTS} are supported",
            allowed.len()
        );
    }

    let mut ranges = Vec::with_capacity(allowed.len() + 1);
    let mut start = 1u32;
    for port in allowed {
        let port = u32::from(port);
        if start < port {
            ranges.push((start as u16, (port - 1) as u16));
        }
        start = port + 1;
    }
    if start <= u32::from(u16::MAX) {
        ranges.push((start as u16, u16::MAX));
    }
    Ok(ranges)
}

fn loopback_tcp_filter_key(ipv6: bool, package: bool, slot: usize) -> GUID {
    let base = if package && ipv6 {
        LOOPBACK_PACKAGE_TCP_V6_FILTER_KEY_BASE
    } else if package {
        LOOPBACK_PACKAGE_TCP_V4_FILTER_KEY_BASE
    } else if ipv6 {
        LOOPBACK_TCP_V6_FILTER_KEY_BASE
    } else {
        LOOPBACK_TCP_V4_FILTER_KEY_BASE
    };
    GUID::from_u128(base + slot as u128)
}

fn install_loopback_filters(
    engine: HANDLE,
    user_condition: &UserMatchCondition,
    appcontainer_sid: Option<&LocalSid>,
    proxy_ports: &[u16],
) -> Result<usize> {
    let ranges = blocked_port_ranges(proxy_ports)?;
    for package in [false, true] {
        for ipv6 in [false, true] {
            for slot in 0..=MAX_PROXY_PORTS {
                delete_filter_if_present(engine, &loopback_tcp_filter_key(ipv6, package, slot))?;
            }
        }
    }
    for key in [
        LOOPBACK_USER_UDP_V4_FILTER_KEY,
        LOOPBACK_USER_UDP_V6_FILTER_KEY,
        LOOPBACK_PACKAGE_UDP_V4_FILTER_KEY,
        LOOPBACK_PACKAGE_UDP_V6_FILTER_KEY,
    ] {
        delete_filter_if_present(engine, &key)?;
    }

    let mut installed = 0;
    for ipv6 in [false, true] {
        add_loopback_filter(
            engine,
            loopback_udp_filter_key(ipv6, false),
            ipv6,
            IPPROTO_UDP as u8,
            None,
            user_condition,
            None,
        )?;
        installed += 1;
        for (slot, range) in ranges.iter().copied().enumerate() {
            add_loopback_filter(
                engine,
                loopback_tcp_filter_key(ipv6, false, slot),
                ipv6,
                IPPROTO_TCP as u8,
                Some(range),
                user_condition,
                None,
            )?;
            installed += 1;
        }
    }
    if let Some(appcontainer_sid) = appcontainer_sid {
        for ipv6 in [false, true] {
            add_loopback_filter(
                engine,
                loopback_udp_filter_key(ipv6, true),
                ipv6,
                IPPROTO_UDP as u8,
                None,
                user_condition,
                Some(appcontainer_sid),
            )?;
            installed += 1;
            for (slot, range) in ranges.iter().copied().enumerate() {
                add_loopback_filter(
                    engine,
                    loopback_tcp_filter_key(ipv6, true, slot),
                    ipv6,
                    IPPROTO_TCP as u8,
                    Some(range),
                    user_condition,
                    Some(appcontainer_sid),
                )?;
                installed += 1;
            }
        }
    }
    Ok(installed)
}

fn loopback_udp_filter_key(ipv6: bool, package: bool) -> GUID {
    match (ipv6, package) {
        (false, false) => LOOPBACK_USER_UDP_V4_FILTER_KEY,
        (true, false) => LOOPBACK_USER_UDP_V6_FILTER_KEY,
        (false, true) => LOOPBACK_PACKAGE_UDP_V4_FILTER_KEY,
        (true, true) => LOOPBACK_PACKAGE_UDP_V6_FILTER_KEY,
    }
}

fn add_loopback_filter(
    engine: HANDLE,
    filter_key: GUID,
    ipv6: bool,
    protocol: u8,
    port_range: Option<(u16, u16)>,
    user_condition: &UserMatchCondition,
    appcontainer_sid: Option<&LocalSid>,
) -> Result<()> {
    let port_description = port_range
        .map(|(low, high)| format!(" ports {low}-{high}"))
        .unwrap_or_default();
    let name_text = format!(
        "runseal_wfp_block_loopback_{}_{}{}",
        if protocol == IPPROTO_TCP as u8 {
            "tcp"
        } else {
            "udp"
        },
        if ipv6 { "v6" } else { "v4" },
        if appcontainer_sid.is_some() {
            "_package"
        } else {
            "_user"
        }
    );
    let description_text = format!(
        "Block sandbox loopback {}{port_description} {}",
        if protocol == IPPROTO_TCP as u8 {
            "TCP"
        } else {
            "UDP"
        },
        if ipv6 { "v6" } else { "v4" }
    );
    let name = to_wide(OsStr::new(&name_text));
    let description = to_wide(OsStr::new(&description_text));
    let principal = if appcontainer_sid.is_some() {
        &[][..]
    } else {
        &[ConditionSpec::User][..]
    };
    let mut specs = principal.to_vec();
    specs.extend([ConditionSpec::Loopback, ConditionSpec::Protocol(protocol)]);
    let mut conditions = build_conditions(&specs, user_condition);
    if let Some(appcontainer_sid) = appcontainer_sid {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: appcontainer_sid.as_ptr().cast(),
                },
            },
        });
    }
    let mut port_range_value = port_range.map(|(low_port, high_port)| FWP_RANGE0 {
        valueLow: FWP_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_VALUE0_0 { uint16: low_port },
        },
        valueHigh: FWP_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_VALUE0_0 { uint16: high_port },
        },
    });
    if let Some(port_range) = port_range_value.as_mut() {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    rangeValue: port_range,
                },
            },
        });
    }
    let provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: filter_key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr() as *mut _,
            description: description.as_ptr() as *mut _,
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        layerKey: if ipv6 {
            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6
        } else {
            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4
        },
        subLayerKey: SUBLAYER_KEY,
        weight: empty_value(),
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: zero_guid(),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };
    let mut filter_id = 0;
    let result = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id) };
    ensure_success(result, &format!("FwpmFilterAdd0({name_text})"))
}

/// Owns an open WFP engine handle and closes it on drop.
struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open() -> Result<Self> {
        let session_name = to_wide(OsStr::new(SESSION_NAME));
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.displayData = FWPM_DISPLAY_DATA0 {
            name: session_name.as_ptr() as *mut _,
            description: null_mut(),
        };
        session.txnWaitTimeoutInMSec = INFINITE;

        let mut handle = HANDLE::default();
        let result = unsafe {
            FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_DEFAULT as u32,
                null(),
                &session,
                &mut handle,
            )
        };
        ensure_success(result, "FwpmEngineOpen0")?;
        Ok(Self { handle })
    }

    fn begin_transaction(&self) -> Result<Transaction<'_>> {
        let result = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        ensure_success(result, "FwpmTransactionBegin0")?;
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.handle);
        }
    }
}

/// Aborts an open WFP transaction unless it was explicitly committed.
struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl Transaction<'_> {
    fn commit(&mut self) -> Result<()> {
        let result = unsafe { FwpmTransactionCommit0(self.engine.handle) };
        ensure_success(result, "FwpmTransactionCommit0")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.handle);
            }
        }
    }
}

/// Builds the ALE_USER_ID condition blob used for normal and restricted token access checks.
struct UserMatchCondition {
    security_descriptor: PSECURITY_DESCRIPTOR,
    blob: FWP_BYTE_BLOB,
}

impl UserMatchCondition {
    fn for_accounts(accounts: &[&str]) -> Result<Self> {
        let account_names = accounts
            .iter()
            .map(|account| to_wide(OsStr::new(account)))
            .collect::<Vec<_>>();
        let mut access_entries = vec![unsafe { zeroed() }; account_names.len()];
        for (access, account_w) in access_entries.iter_mut().zip(&account_names) {
            unsafe {
                BuildExplicitAccessWithNameW(
                    access,
                    account_w.as_ptr(),
                    FWP_ACTRL_MATCH_FILTER,
                    GRANT_ACCESS,
                    0,
                );
            }
        }

        let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let mut security_descriptor_len = 0;
        let result = unsafe {
            BuildSecurityDescriptorW(
                null(),
                null(),
                access_entries.len() as u32,
                access_entries.as_mut_ptr(),
                0,
                null(),
                null_mut(),
                &mut security_descriptor_len,
                &mut security_descriptor,
            )
        };
        ensure_success(result, "BuildSecurityDescriptorW")?;

        Ok(Self {
            security_descriptor,
            blob: FWP_BYTE_BLOB {
                size: security_descriptor_len,
                data: security_descriptor as *mut u8,
            },
        })
    }
}

impl Drop for UserMatchCondition {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor as HLOCAL);
            }
        }
    }
}

/// Ensures the persistent Codex WFP provider exists.
fn ensure_provider(engine: HANDLE) -> Result<()> {
    let provider_name = to_wide(OsStr::new(PROVIDER_NAME));
    let provider_description = to_wide(OsStr::new(PROVIDER_DESCRIPTION));
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: provider_name.as_ptr() as *mut _,
            description: provider_description.as_ptr() as *mut _,
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: null_mut(),
    };

    let result = unsafe { FwpmProviderAdd0(engine, &provider, null_mut()) };
    ensure_success_or(result, "FwpmProviderAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Ensures the persistent Codex sublayer exists under the Codex provider.
fn ensure_sublayer(engine: HANDLE) -> Result<()> {
    let sublayer_name = to_wide(OsStr::new(SUBLAYER_NAME));
    let sublayer_description = to_wide(OsStr::new(SUBLAYER_DESCRIPTION));
    let provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: sublayer_name.as_ptr() as *mut _,
            description: sublayer_description.as_ptr() as *mut _,
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        weight: 0x8000,
    };

    let result = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    ensure_success_or(result, "FwpmSubLayerAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Adds one blocking WFP filter from the static filter spec list.
fn add_filter(
    engine: HANDLE,
    spec: &FilterSpec,
    user_condition: &UserMatchCondition,
) -> Result<()> {
    let filter_name = to_wide(OsStr::new(spec.name));
    let filter_description = to_wide(OsStr::new(spec.description));
    let mut filter_conditions = build_conditions(spec.conditions, user_condition);
    let provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: spec.key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: filter_name.as_ptr() as *mut _,
            description: filter_description.as_ptr() as *mut _,
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        layerKey: spec.layer_key,
        subLayerKey: SUBLAYER_KEY,
        weight: empty_value(),
        numFilterConditions: filter_conditions.len() as u32,
        filterCondition: filter_conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: zero_guid(),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };

    let mut filter_id = 0_u64;
    let result = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id) };
    ensure_success(result, &format!("FwpmFilterAdd0({})", spec.name))
}

/// Converts our compact condition specs into WFP filter conditions.
fn build_conditions(
    specs: &[ConditionSpec],
    user_condition: &UserMatchCondition,
) -> Vec<FWPM_FILTER_CONDITION0> {
    specs
        .iter()
        .map(|spec| match spec {
            ConditionSpec::User => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_USER_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sd: &user_condition.blob as *const _ as *mut _,
                    },
                },
            },
            ConditionSpec::NonLoopback => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_NONE_SET,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                },
            },
            ConditionSpec::Loopback => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_ALL_SET,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                },
            },
            ConditionSpec::Protocol(protocol) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *protocol },
                },
            },
            ConditionSpec::RemotePort(port) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            },
        })
        .collect()
}

/// Deletes an old copy of a filter before re-adding it.
fn delete_filter_if_present(engine: HANDLE, key: &GUID) -> Result<()> {
    let result = unsafe { FwpmFilterDeleteByKey0(engine, key) };
    ensure_success_or(
        result,
        "FwpmFilterDeleteByKey0",
        &[FWP_E_FILTER_NOT_FOUND as u32, FWP_E_NOT_FOUND as u32],
    )
}

fn ensure_success(result: u32, operation: &str) -> Result<()> {
    ensure_success_or(result, operation, &[])
}

fn ensure_success_or(result: u32, operation: &str, allowed: &[u32]) -> Result<()> {
    if result == 0 || allowed.contains(&result) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{operation} failed: {}",
            format_error_code(result)
        ))
    }
}

fn format_error_code(result: u32) -> String {
    format!("0x{result:08X}")
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: null_mut(),
    }
}

fn empty_value() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: unsafe { zeroed() },
    }
}

fn zero_guid() -> GUID {
    GUID::from_u128(0)
}

#[cfg(test)]
mod tests {
    use super::FILTER_SPECS;
    use super::blocked_port_ranges;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeSet;

    #[test]
    fn filter_keys_are_unique() {
        let keys = FILTER_SPECS
            .iter()
            .map(|spec| {
                (
                    spec.key.data1,
                    spec.key.data2,
                    spec.key.data3,
                    spec.key.data4,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), FILTER_SPECS.len());
    }

    #[test]
    fn filter_names_are_unique() {
        let names = FILTER_SPECS
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), FILTER_SPECS.len());
    }

    #[test]
    fn blocked_port_ranges_exclude_only_proxy_ports() {
        assert_eq!(
            blocked_port_ranges(&[]).expect("disabled ranges"),
            vec![(1, 65535)]
        );
        assert_eq!(
            blocked_port_ranges(&[43128]).expect("single proxy ranges"),
            vec![(1, 43127), (43129, 65535)]
        );
        assert_eq!(
            blocked_port_ranges(&[65535, 1, 8080, 8080]).expect("multiple proxy ranges"),
            vec![(2, 8079), (8081, 65534)]
        );
    }
}
