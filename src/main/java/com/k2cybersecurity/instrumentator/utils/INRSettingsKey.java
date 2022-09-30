package com.k2cybersecurity.instrumentator.utils;

public class INRSettingsKey {
    public static final String SECURITY_POLICY_VULNERABILITY_SCAN_ENABLE = "security.policy.vulnerabilityScan.enabled";
    public static final String SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_ENABLE = "security.policy.vulnerabilityScan.iastScan.enabled";
    public static final String SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_INTERVAL = "security.policy.vulnerabilityScan.iastScan.probing.interval";
    public static final String SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_BATCH_SIZE = "security.policy.vulnerabilityScan.iastScan.probing.batchSize";
    public static final String SECURITY_POLICY_PROTECTION_MODE_ENABLE = "security.policy.protectionMode.enabled";
    public static final String SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ENABLE = "security.policy.protectionMode.ipBlocking.enabled";
    public static final String SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ATTACKER_IP_BLOCKING = "security.policy.protectionMode.ipBlocking.attackerIpBlocking";
    public static final String SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_IP_DETECT_VIA_XFF = "security.policy.protectionMode.ipBlocking.ipDetectViaXFF";
    public static final String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_ENABLE = "security.policy.protectionMode.apiBlocking.enabled";
    public static final String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ALL_APIS = "security.policy.protectionMode.apiBlocking.protectAllApis";
    public static final String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_KNOWN_VULNERABLE_APIS = "security.policy.protectionMode.apiBlocking.protectKnownVulnerableApis";
    public static final String SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ATTACKED_APIS = "security.policy.protectionMode.apiBlocking.protectAttackedApis";
}
