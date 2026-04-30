package com.ucas.infocollect.collector.security;

import androidx.annotation.NonNull;

/**
 * 安全子扫描器策略接口（Strategy Pattern）。
 *
 * <p>每个实现类封装一个独立的、职责单一的安全检测维度。
 * {@link SecurityCollectorV2}（尚未实现）作为编排者（Orchestrator），
 * 持有一个 {@code List<SecurityScanner>} 并依次调用，将各子结果聚合
 * 为最终的 {@link com.ucas.infocollect.collector.CollectionResult}。</p>
 *
 * <h3>实现约定</h3>
 * <ol>
 *   <li>{@link #scan} 方法不得抛出任何受检或非受检异常；
 *       所有异常均在实现内部捕获，并通过
 *       {@link ScanResult#failed} 或 {@link ScanResult#partial} 返回。</li>
 *   <li>实现类必须是无状态的（Stateless）——{@code scan} 可被多线程并发调用。</li>
 *   <li>实现类内部禁止出现 {@code android.content.Context} 引用；
 *       所有 Android 资源访问通过 {@link SecurityScanContext} 进行。</li>
 *   <li>{@link #getId} 应返回稳定的常量字符串，用于日志、指标和测试断言，
 *       格式建议：大写下划线，例如 {@code "SELINUX_KERNEL_SECURITY"}。</li>
 * </ol>
 *
 * <h3>子扫描器矩阵（待实现，见 {@code scanner/} 子包）</h3>
 * <pre>
 *  ┌──────────────────────────────┬──────────────────────────────────────┐
 *  │ 实现类                        │ 职责范围                               │
 *  ├──────────────────────────────┼──────────────────────────────────────┤
 *  │ KernelSecurityScanner        │ SELinux 模式 / ASLR / perf_event 偏执级别 │
 *  │ SensitiveFileScanner         │ 系统敏感文件可读性检测                   │
 *  │ ExportedComponentScanner     │ 无权限保护的导出 Activity/Service/Receiver │
 *  │ DangerousProviderScanner     │ ContentProvider 路径遍历风险            │
 *  │ ApkSignatureScanner          │ APK V1/V2/V3 签名方案 / Janus 风险      │
 *  │ OverPrivilegeScanner         │ 应用过权限声明统计与 Top-N 排行         │
 *  │ CleartextTrafficScanner      │ 允许明文 HTTP 的应用（MITM 攻击面）     │
 *  │ SuspiciousProcessScanner     │ /proc 进程枚举 / 挖矿木马关键词匹配     │
 *  └──────────────────────────────┴──────────────────────────────────────┘
 * </pre>
 */
public interface SecurityScanner {

    /**
     * 返回本扫描器的唯一标识符。
     *
     * <p>标识符在系统生命周期内必须稳定，可被序列化存储和日志检索。
     * 命名约定：{@code SCREAMING_SNAKE_CASE}，例如 {@code "APK_SIGNATURE"}。</p>
     */
    @NonNull
    String getId();

    /**
     * 返回本扫描器的人类可读描述，用于 UI 调试信息和报告标题。
     */
    @NonNull
    String getDescription();

    /**
     * 执行安全扫描，返回结构化结果。
     *
     * <p>本方法保证不抛出任何异常。扫描过程中的所有错误通过
     * {@link ScanResult#errors} 或 {@link ScanResult#partial} 返回。</p>
     *
     * @param ctx 安全扫描上下文，提供系统服务和包管理器访问能力
     * @return 本扫描器的完整或部分结果
     */
    @NonNull
    ScanResult scan(@NonNull SecurityScanContext ctx);
}
