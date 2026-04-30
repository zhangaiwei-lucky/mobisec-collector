package com.ucas.infocollect.collector;

import android.content.pm.PackageManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ucas.infocollect.collector.security.Finding;
import com.ucas.infocollect.collector.security.ScanResult;
import com.ucas.infocollect.collector.security.SecurityScanContext;
import com.ucas.infocollect.collector.security.SecurityScanner;
import com.ucas.infocollect.collector.security.Severity;
import com.ucas.infocollect.collector.security.scanner.ApkSignatureScanner;
import com.ucas.infocollect.collector.security.scanner.KernelSecurityScanner;
import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 安全分析编排器（Orchestrator）——{@link com.ucas.infocollect.collector.security.SecurityScanner}
 * 策略群的协调者，{@link InfoCollectorV2} 的安全分析实现。
 *
 * <h2>职责划分</h2>
 * <p>本类是一个纯粹的<b>调度者</b>，内部不包含任何检测逻辑：</p>
 * <ul>
 *   <li>持有不可变的 {@link SecurityScanner} 注册表。</li>
 *   <li>构建 {@link SecurityScanContext} 桥接层，将 {@link SystemEnvironment}
 *       提升为扫描器所需的上下文接口。</li>
 *   <li>顺序执行所有扫描器，捕获所有非受检异常（保证单个扫描器崩溃不影响其余）。</li>
 *   <li>将策略层领域对象（{@link Finding} / {@link ScanResult}）翻译为
 *       UI 层可渲染的 {@link InfoRow} 和 {@link DegradeEntry}。</li>
 * </ul>
 *
 * <h2>扩展方式（Phase 2+）</h2>
 * <p>新的扫描策略类只需实现 {@link SecurityScanner} 接口，然后追加到
 * {@link #buildScannerRegistry()} 的列表中。编排器本身无需改动。</p>
 *
 * <h2>领域对象降维规则</h2>
 * <pre>
 *  Finding.Severity        →  InfoRow.RiskLevel
 *  ─────────────────────── ─  ─────────────────
 *  CRITICAL                →  HIGH
 *  HIGH                    →  HIGH
 *  MEDIUM                  →  NORMAL
 *  LOW                     →  NORMAL
 *  INFO                    →  NORMAL
 * </pre>
 */
public final class SecurityCollectorV2 implements InfoCollectorV2 {

    /** 本 Collector 的机器可读标识符，用于日志、指标和测试断言。 */
    public static final String COLLECTOR_ID = "SECURITY_V2";

    /**
     * 已注册扫描器的不可变有序列表。
     * 执行顺序即注册顺序；每个扫描器的输出在 UI 中保持独立分段。
     */
    @NonNull
    private final List<SecurityScanner> scanners;

    // ─────────────────────────────────────────────────────────────────────────
    // 构造
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 生产环境构造器，使用默认扫描器注册表。
     *
     * <p>当前注册（按执行顺序）：</p>
     * <ol>
     *   <li>{@link KernelSecurityScanner} — SELinux / ASLR / perf_event</li>
     *   <li>{@link ApkSignatureScanner}   — APK 签名方案 / Janus CVE-2017-13156</li>
     * </ol>
     */
    public SecurityCollectorV2() {
        this(buildScannerRegistry());
    }

    /**
     * 测试 / 扩展构造器，允许注入自定义扫描器列表。
     *
     * @param scanners 非空的扫描器列表，内部自动创建不可变副本
     */
    public SecurityCollectorV2(@NonNull final List<SecurityScanner> scanners) {
        this.scanners = Collections.unmodifiableList(new ArrayList<>(scanners));
    }

    /** 构建默认扫描器注册表。Phase 2 新扫描器在此追加，编排器逻辑不变。 */
    @NonNull
    private static List<SecurityScanner> buildScannerRegistry() {
        return Arrays.asList(
                new KernelSecurityScanner(),
                new ApkSignatureScanner()
                // Phase 2 占位：
                // new SensitiveFileScanner(),
                // new ExportedComponentScanner(),
                // new DangerousProviderScanner(),
                // new OverPrivilegeScanner(),
                // new CleartextTrafficScanner(),
                // new SuspiciousProcessScanner()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // InfoCollectorV2 契约
    // ─────────────────────────────────────────────────────────────────────────

    /** 本 Collector 的机器可读标识符。 */
    @NonNull
    public String getCollectorId() {
        return COLLECTOR_ID;
    }

    /**
     * {@inheritDoc}
     *
     * <p>遍历所有已注册扫描器，取权限集合的并集。
     * 保持顺序确定性（{@link LinkedHashSet} 保持插入顺序）。</p>
     */
    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        final Set<String> union = new LinkedHashSet<>();
        for (final SecurityScanner scanner : scanners) {
            union.addAll(scanner.getRequiredPermissions());
        }
        return Collections.unmodifiableList(new ArrayList<>(union));
    }

    /**
     * {@inheritDoc}
     *
     * <p>执行流程：</p>
     * <ol>
     *   <li>构建 {@link SecurityScanContextBridge}，将 {@code env} 提升为
     *       {@link SecurityScanContext}。</li>
     *   <li>顺序执行每个扫描器的 {@code scan()} 方法。</li>
     *   <li>对每个扫描器的 {@link ScanResult}，将 {@link Finding} 翻译为
     *       {@link InfoRow}，将 {@code errors} 翻译为 {@link DegradeEntry}。</li>
     *   <li>若扫描器抛出任何非受检异常，捕获并记录为降级事件，继续执行下一个扫描器。</li>
     * </ol>
     */
    @NonNull
    @Override
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder builder = CollectionResult.builder();
        final SecurityScanContext ctx = new SecurityScanContextBridge(env);

        for (final SecurityScanner scanner : scanners) {
            try {
                final ScanResult scanResult = scanner.scan(ctx);
                translateScanResult(scanner, scanResult, builder);
            } catch (final Exception e) {
                // 单个扫描器的意外崩溃不得中断整个安全扫描流程。
                builder.addDegrade(
                        scanner.getId(),
                        CollectorUtils.DegradeReason.READ_FAILED,
                        "Unhandled exception in scanner ["
                        + scanner.getId() + "]: "
                        + e.getClass().getSimpleName() + " — " + e.getMessage());
            }
        }

        return builder.build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 领域对象降维翻译（Finding → InfoRow）
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 将单个扫描器的 {@link ScanResult} 翻译并写入 {@link CollectionResult.Builder}。
     *
     * <p>每个扫描器的输出以其描述字符串作为 {@link InfoRow} 分区标题。</p>
     */
    private static void translateScanResult(
            @NonNull final SecurityScanner         scanner,
            @NonNull final ScanResult              scanResult,
            @NonNull final CollectionResult.Builder builder) {

        // 分区标题
        builder.addHeader(scanner.getDescription());

        // Finding → InfoRow
        for (final Finding finding : scanResult.findings) {
            final RiskLevel riskLevel = toRiskLevel(finding.severity);
            final String    key       = buildFindingKey(finding);
            final String    value     = buildFindingValue(finding);

            if (riskLevel == RiskLevel.HIGH) {
                builder.addHighRisk(key, value);
            } else {
                builder.add(key, value);
            }
        }

        // ScanResult.errors → DegradeEntry（不混入数据行）
        for (final String error : scanResult.errors) {
            builder.addDegrade(
                    scanner.getDescription(),
                    CollectorUtils.DegradeReason.READ_FAILED,
                    error);
        }

        // partial 状态：额外追加一条摘要降级
        if (scanResult.partial && !scanResult.hasErrors()) {
            builder.addDegrade(
                    scanner.getDescription(),
                    CollectorUtils.DegradeReason.NO_DATA,
                    "Scanner reported partial results with no explicit error message.");
        }
    }

    /**
     * 构建 InfoRow 的 key 字段。
     *
     * <p>格式：{@code "[FINDING_TYPE] title}，使 Finding 类型机器可读、
     * 标题人类可读，两者均在列表视图中可见。</p>
     */
    @NonNull
    private static String buildFindingKey(@NonNull final Finding finding) {
        return "[" + finding.findingType + "]\n" + finding.title;
    }

    /**
     * 构建 InfoRow 的 value 字段。
     *
     * <p>由两部分拼接而成：</p>
     * <ol>
     *   <li>描述文本（最多 {@link #DESC_MAX_CHARS} 字符，超出截断并追加省略号）。</li>
     *   <li>精选 attribute 以 {@code "标签: 值"} 格式逐行追加，
     *       仅输出 {@link #DISPLAY_ATTRS} 中明确声明的属性。</li>
     * </ol>
     */
    @NonNull
    private static String buildFindingValue(@NonNull final Finding finding) {
        final StringBuilder sb = new StringBuilder();

        // 描述文本（截断保护）
        final String desc = finding.description;
        if (!desc.isEmpty()) {
            sb.append(desc.length() > DESC_MAX_CHARS
                    ? desc.substring(0, DESC_MAX_CHARS) + "…"
                    : desc);
        }

        // 精选 attribute 追加
        for (final String[] entry : DISPLAY_ATTRS) {
            final String attrKey   = entry[0];
            final String attrLabel = entry[1];
            final String attrVal   = finding.getAttribute(attrKey);
            if (attrVal != null) {
                sb.append('\n').append(attrLabel).append(": ").append(attrVal);
            }
        }

        return sb.length() > 0 ? sb.toString() : "(无详细信息)";
    }

    /**
     * 描述文本截断长度。Android RecyclerView 中的 TextView 显示过长文本会
     * 影响滚动性能，此处保留足够的安全分析语境同时避免单条 Item 过高。
     */
    private static final int DESC_MAX_CHARS = 220;

    /**
     * 用于 UI 展示的 attribute 白名单（有序）。
     * 每条为 {@code {attrKey, displayLabel}}。
     * 未在此列表中的 attribute 仅供机器处理，不在 UI 中显示。
     */
    private static final String[][] DISPLAY_ATTRS = {
            // 通用
            {"package",                "包名"},
            {"cve",                    "CVE"},
            {"confidence",             "置信度"},
            {"detection_confidence",   "置信度"},
            // APK 签名相关
            {"has_v1",                 "V1 签名迹象"},
            {"has_v2",                 "V2 Block"},
            {"has_v3",                 "V3 Block"},
            {"device_api",             "设备 API"},
            {"janus_vulnerable_os",    "Janus 受影响设备"},
            // 扫描摘要
            {"total_user_apps",        "扫描应用总数"},
            {"modern_signed_count",    "现代签名数量"},
            {"v1_only_count",          "V1-only 数量"},
            {"malformed_count",        "结构损坏数量"},
            // 内核安全
            {"enforce_value",          "内核值"},
            {"randomize_va_space",     "内核值"},
            {"perf_event_paranoid",    "内核值"},
            {"recommended_value",      "建议值"},
            {"source",                 "检测来源"},
            {"prop_value",             "属性值"},
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Severity → RiskLevel 映射
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 将安全领域的 {@link Severity} 降维为 UI 层的 {@link RiskLevel}。
     *
     * <ul>
     *   <li>{@code CRITICAL / HIGH} → {@link RiskLevel#HIGH}（UI 高亮显示）</li>
     *   <li>{@code MEDIUM / LOW / INFO} → {@link RiskLevel#NORMAL}</li>
     * </ul>
     */
    @NonNull
    private static RiskLevel toRiskLevel(@NonNull final Severity severity) {
        switch (severity) {
            case CRITICAL:
            case HIGH:
                return RiskLevel.HIGH;
            default:
                return RiskLevel.NORMAL;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SystemEnv → SecurityScanContext 桥接层（内部静态类）
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 将 {@link SystemEnvironment} 提升为 {@link SecurityScanContext} 的内部桥接适配器。
     *
     * <h3>实现说明</h3>
     * <ul>
     *   <li>{@link SystemEnvironment} 的四个方法直接委托给传入的 {@code delegate}。</li>
     *   <li>{@link SecurityScanContext#getPackageManager()} 委托给
     *       {@code delegate.getPackageManager()}，无 Context 穿透。</li>
     *   <li>{@link SecurityScanContext#readSystemFile(String)} 使用纯 Java I/O
     *       ({@link BufferedReader} + {@link FileReader}) 实现，
     *       不依赖任何 Android 框架类，可在 JVM 测试环境中直接运行。</li>
     * </ul>
     *
     * <p>本类是 {@code SecurityCollectorV2} 的内部实现细节，不对外暴露。</p>
     */
    private static final class SecurityScanContextBridge implements SecurityScanContext {

        @NonNull
        private final SystemEnvironment delegate;

        private SecurityScanContextBridge(@NonNull final SystemEnvironment delegate) {
            this.delegate = delegate;
        }

        // ── SystemEnvironment 委托 ────────────────────────────────────────────

        @Nullable
        @Override
        public <T> T getSystemService(@NonNull final Class<T> serviceClass) {
            return delegate.getSystemService(serviceClass);
        }

        @Nullable
        @Override
        public String getSecureStringSetting(@NonNull final String key) {
            return delegate.getSecureStringSetting(key);
        }

        @Override
        public int getSecureIntSetting(@NonNull final String key, final int defValue) {
            return delegate.getSecureIntSetting(key, defValue);
        }

        @Override
        public int getGlobalIntSetting(@NonNull final String key, final int defValue) {
            return delegate.getGlobalIntSetting(key, defValue);
        }

        @NonNull
        @Override
        public PackageManager getPackageManager() {
            return delegate.getPackageManager();
        }

        // ── SecurityScanContext 扩展 ──────────────────────────────────────────

        /**
         * 读取 Linux 伪文件系统中的文本文件。
         *
         * <p>使用标准 Java I/O 实现，无任何 Android 依赖，
         * 可在 JUnit 4 环境中以真实 {@code /proc} 路径测试。</p>
         *
         * @return 文件全文（已 trim）；不存在、不可读或 I/O 异常时返回 {@code null}
         */
        @Nullable
        @Override
        public String readSystemFile(@NonNull final String path) {
            try (final BufferedReader br = new BufferedReader(new FileReader(path))) {
                final StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString().trim();
            } catch (final IOException ignored) {
                return null;
            }
        }
    }
}
