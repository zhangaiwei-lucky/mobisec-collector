package com.ucas.infocollect.collector.security;

/**
 * 安全发现的严重性等级。
 *
 * <p>等级语义参考 CVSS v3 风险划分：</p>
 * <ul>
 *   <li>{@link #INFO}     — 信息类，无直接风险，供审计参考。</li>
 *   <li>{@link #LOW}      — 低风险，需要额外条件才能被利用。</li>
 *   <li>{@link #MEDIUM}   — 中风险，攻击路径存在但需要交互。</li>
 *   <li>{@link #HIGH}     — 高风险，可被直接利用或扩大攻击面。</li>
 *   <li>{@link #CRITICAL} — 严重，已知可利用漏洞或直接数据泄露。</li>
 * </ul>
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
