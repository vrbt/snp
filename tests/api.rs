// SPDX-License-Identifier: Apache-2.0

use snp::firmware::host::{
    types::{CertTableEntry, SnpCertType, SnpConfig, SnpExtConfig, SnpPlatformStatus, TcbVersion},
    Firmware,
};

use serial_test::serial;

#[cfg_attr(not(has_sev), ignore)]
#[test]
fn get_identifier() {
    let mut fw = Firmware::open().unwrap();
    let id = fw.get_identifier().unwrap();
    assert_ne!(Vec::from(id), vec![0u8; 64]);
}

#[cfg_attr(not(has_sev), ignore)]
#[test]
fn platform_status() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let status: SnpPlatformStatus = fw.snp_platform_status().unwrap();

    println!(
        "Platform status ioctl results:
              version (major, minor): {}.{}
              build id: {}
              guests: {}
              platform tcb microcode version: {}
              platform tcb snp version: {}
              platform tcb tee version: {}
              platform tcb bootloader version: {}
              reported tcb microcode version: {}
              reported tcb snp version: {}
              reported tcb tee version: {}
              reported tcb bootloader version: {}
              state: {}",
        status.version.major,
        status.version.minor,
        status.build_id,
        status.guest_count,
        status.platform_tcb_version.microcode,
        status.platform_tcb_version.snp,
        status.platform_tcb_version.tee,
        status.platform_tcb_version.bootloader,
        status.reported_tcb_version.microcode,
        status.reported_tcb_version.snp,
        status.reported_tcb_version.tee,
        status.reported_tcb_version.bootloader,
        status.state
    );
}

fn build_ext_config(cert: bool, cfg: bool) -> SnpExtConfig {
    let test_cfg: SnpConfig = SnpConfig::new(TcbVersion::new(2, 0, 6, 39), 31);

    let cert_table: Vec<CertTableEntry> = vec![
        CertTableEntry::new(SnpCertType::ARK, vec![1; 28]),
        CertTableEntry::new(SnpCertType::ASK, vec![1; 28]),
    ];

    match (cert, cfg) {
        (true, true) => SnpExtConfig::new(test_cfg, cert_table),
        (true, false) => SnpExtConfig::update_certs_only(cert_table),
        (false, true) => SnpExtConfig::update_config_only(test_cfg),
        (false, false) => SnpExtConfig::default(),
    }
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_set_ext_config_std() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(true, true);
    fw.snp_set_ext_config(new_config).unwrap();
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_get_ext_config_std() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(true, true);
    fw.snp_set_ext_config(new_config.clone()).unwrap();
    let hw_config: SnpExtConfig = fw.snp_get_ext_config().unwrap();
    assert_eq!(new_config, hw_config);
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_get_ext_config_cert_only() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(true, false);
    fw.snp_set_ext_config(new_config.clone()).unwrap();
    let hw_config: SnpExtConfig = fw.snp_get_ext_config().unwrap();
    assert_eq!(new_config, hw_config);
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_get_ext_config_cfg_only() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(false, true);
    fw.snp_set_ext_config(new_config.clone()).unwrap();
    let hw_config: SnpExtConfig = fw.snp_get_ext_config().unwrap();
    assert_eq!(new_config, hw_config);
}
