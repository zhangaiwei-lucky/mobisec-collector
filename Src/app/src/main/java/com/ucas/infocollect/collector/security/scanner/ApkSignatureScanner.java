package com.ucas.infocollect.collector.security.scanner;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import com.ucas.infocollect.collector.security.Finding;
import com.ucas.infocollect.collector.security.ScanResult;
import com.ucas.infocollect.collector.security.SecurityScanContext;
import com.ucas.infocollect.collector.security.SecurityScanner;
import com.ucas.infocollect.collector.security.Severity;
import com.ucas.infocollect.collector.security.binary.ApkParseException;
import com.ucas.infocollect.collector.security.binary.ApkSignatureInfo;
import com.ucas.infocollect.collector.security.binary.ApkSignatureParser;
import com.ucas.infocollect.collector.security.binary.DefaultApkSignatureParser;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * APK 签名方案分析扫描器。
 *
 * <h2>威胁模型</h2>
 * <p><b>CVE-2017-13156（Janus）</b>：Android 的 V1（JAR）签名方案仅对 ZIP 条目内容
 * 进行签名，不覆盖 ZIP 文件头之前的字节区域。攻击者可在合法 APK 文件头前附加任意
 * DEX 字节码，Android 5.1–8.0（API 22–26）的 {@code PackageInstaller} 在安装/更新时
 * 会优先执行该 DEX，同时认为签名仍然有效——这使得攻击者可以在不破坏签名的前提下
 * 实现静默恶意代码注入。</p>
 *
 * <p>V2 / V3 签名方案通过 APK Signing Block 对整个 ZIP 结构（包含文件头至 EOCD
 * 之间的所有字节）进行覆盖式哈希，从根本上消除了 Janus 攻击面。</p>
 *
 * <h2>检测逻辑</h2>
 * <ol>
 *   <li>枚举所有用户安装应用，跳过系统应用（噪音过高）。</li>
 *   <li>对每个 APK 调用 {@link ApkSignatureParser#parse}（低拷贝 FileChannel 路径）。</li>
 *   <li>按下表生成 {@link Finding}：</li>
 * </ol>
 * <pre>
 *  ┌───────────────────────────────┬────────────┬───────────────────────────────┐
 *  │ 条件                           │ Severity   │ Finding Type                  │
 *  ├───────────────────────────────┼────────────┼───────────────────────────────┤
 *  │ APK 文件结构违规（不合规 ZIP）  │ CRITICAL   │ APK_MALFORMED_STRUCTURE        │
 *  │ 纯 V1 签名 + 设备 API ≤ 26    │ HIGH       │ APK_V1_ONLY_JANUS_RISK         │
 *  │ 纯 V1 签名 + 设备 API > 26    │ MEDIUM     │ APK_V1_ONLY_JANUS_RISK         │
 *  │ 存在 V2 或 V3 现代签名方案     │ INFO       │ （仅计入聚合摘要，不单独成条）  │
 *  │ APK 不可读（I/O 权限）         │ （errors） │ （记录为 error，标记 partial）  │
 *  └───────────────────────────────┴────────────┴───────────────────────────────┘
 * </pre>
 *
 * <h2>依赖注入</h2>
 * <p>底层解析器通过构造函数注入，生产代码使用无参构造器（默认 {@link DefaultApkSignatureParser}），
 * 单元测试可注入 mock 实现，无需真实 APK 文件。</p>
 */
public final class ApkSignatureScanner implements SecurityScanner {

    public static final String SCANNER_ID = "APK_SIGNATURE";

    // ── Finding Type 常量 ──────────────────────────────────────────────────────
    private static final String FT_V1_ONLY_JANUS         = "APK_V1_ONLY_JANUS_RISK";
    private static final String FT_MALFORMED_STRUCTURE    = "APK_MALFORMED_STRUCTURE";
    private static final String FT_SIGNATURE_SCAN_SUMMARY = "APK_SIGNATURE_SCAN_SUMMARY";

    // ── 输出截断保护 ───────────────────────────────────────────────────────────
    /** 最多输出多少条 V1-only 独立 Finding（超出时聚合为"还有 N 个"）。 */
    private static final int MAX_V1_FINDINGS       = 10;
    /** 最多记录多少条 APK 结构损坏 Finding。 */
    private static final int MAX_MALFORMED_FINDINGS = 5;

    @NonNull
    private final ApkSignatureParser parser;

    /** 生产环境构造器，使用 {@link DefaultApkSignatureParser}。 */
    public ApkSignatureScanner() {
        this(new DefaultApkSignatureParser());
    }

    /** 测试/扩展构造器，允许注入自定义解析器实现。 */
    @VisibleForTesting
    public ApkSignatureScanner(@NonNull final ApkSignatureParser parser) {
        this.parser = parser;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecurityScanner 契约
    // ─────────────────────────────────────────────────────────────────────────

    @NonNull
    @Override
    public String getId() {
        return SCANNER_ID;
    }

    @NonNull
    @Override
    public String getDescription() {
        return "APK 签名方案分析 — Janus CVE-2017-13156 风险检测";
    }

    /**
     * {@inheritDoc}
     *
     * <p>本方法保证不抛出任何异常。所有解析错误通过 {@link ScanResult#errors} 或
     * {@link ScanResult#partial} 返回。</p>
     */
    @NonNull
    @Override
    public ScanResult scan(@NonNull final SecurityScanContext ctx) {
        final PackageManager pm = ctx.getPackageManager();
        final List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(0);
        } catch (final Exception e) {
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() failed: " + e.getMessage());
        }

        final List<Finding> findings  = new ArrayList<>();
        final List<String>  errors    = new ArrayList<>();

        final int apiLevel            = Build.VERSION.SDK_INT;
        // Janus 的经典受影响范围：Android 5.1（API 22）至 Android 8.0（API 26）。
        final boolean onVulnerableOs  = apiLevel <= Build.VERSION_CODES.O;

        // 统计数据，用于生成聚合摘要 Finding
        int totalUserApps    = 0;
        int modernSignedCount = 0;
        int v1OnlyCount      = 0;
        int malformedCount   = 0;
        int undeterminedCount = 0;
        int v1FindingsEmitted = 0;
        int malformedFindingsEmitted = 0;

        for (final PackageInfo pkg : packages) {
            if (pkg.applicationInfo == null) continue;
            final boolean isSys =
                    (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue; // 系统应用签名状态属于 ROM 厂商职责，排除
            totalUserApps++;

            final String apkPath = pkg.applicationInfo.sourceDir;
            if (apkPath == null || apkPath.isEmpty()) {
                errors.add("[" + pkg.packageName + "] applicationInfo.sourceDir is null or empty");
                continue;
            }

            final ApkSignatureInfo info;
            try {
                info = parser.parse(new File(apkPath));
            } catch (final ApkParseException e) {
                if (e.reason == ApkParseException.Reason.IO_ERROR) {
                    // 权限不足属于正常环境限制，记录为错误但不产生安全 Finding
                    errors.add("[" + pkg.packageName + "] APK unreadable: " + e.getMessage());
                } else {
                    // MALFORMED_STRUCTURE：APK 二进制结构违规——潜在恶意构造，提升为 CRITICAL
                    malformedCount++;
                    if (malformedFindingsEmitted < MAX_MALFORMED_FINDINGS) {
                        malformedFindingsEmitted++;
                        findings.add(buildMalformedFinding(pkg.packageName, apkPath, e));
                    }
                }
                continue;
            }

            if (info.isModernSigned()) {
                modernSignedCount++;
                // 现代签名不单独出 Finding，只计入摘要——避免输出洪泛

            } else if (info.isPossiblyV1Only()) {
                v1OnlyCount++;
                if (v1FindingsEmitted < MAX_V1_FINDINGS) {
                    v1FindingsEmitted++;
                    findings.add(buildV1OnlyFinding(pkg.packageName, info, apiLevel, onVulnerableOs));
                }

            } else {
                undeterminedCount++;
                // 无法判断签名状态（通常因 APK 路径不可读），静默忽略
            }
        }

        // 截断提示：超出 MAX_V1_FINDINGS 的部分汇总为一条 Finding
        final int v1Overflow = v1OnlyCount - v1FindingsEmitted;
        if (v1Overflow > 0) {
            findings.add(Finding.of(FT_V1_ONLY_JANUS, onVulnerableOs ? Severity.HIGH : Severity.MEDIUM)
                    .title("更多 V1-only 签名应用（已截断）")
                    .description("还有 " + v1Overflow + " 个用户应用疑似仅使用 V1 签名。"
                            + "当前设备 API=" + apiLevel
                            + (onVulnerableOs ? "，处于 Janus 受影响范围（API ≤ 26）。" : "。"))
                    .attribute("overflow_count", String.valueOf(v1Overflow))
                    .attribute("device_api",     String.valueOf(apiLevel))
                    .build());
        }

        // 聚合摘要 Finding（始终输出，作为本次扫描的机读快照）
        findings.add(buildSummaryFinding(
                totalUserApps, modernSignedCount, v1OnlyCount,
                malformedCount, undeterminedCount, apiLevel, onVulnerableOs));

        return errors.isEmpty()
                ? ScanResult.success(SCANNER_ID, findings)
                : ScanResult.partial(SCANNER_ID, findings, errors);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Finding 构建辅助
    // ─────────────────────────────────────────────────────────────────────────

    @NonNull
    private static Finding buildV1OnlyFinding(
            @NonNull final String packageName,
            @NonNull final ApkSignatureInfo info,
            final int apiLevel,
            final boolean onVulnerableOs) {

        final Severity severity = onVulnerableOs ? Severity.HIGH : Severity.MEDIUM;

        final String deviceRisk = onVulnerableOs
                ? "⚠ 当前设备 API=" + apiLevel + " 处于受影响范围（API 22–26），攻击可立即实施。"
                : "当前设备 API=" + apiLevel + " 已超出典型受影响范围，但该应用若被部署到旧设备，"
                + "攻击面依然存在。";

        return Finding.of(FT_V1_ONLY_JANUS, severity)
                .title("APK 疑似纯 V1 签名 — Janus 漏洞风险")
                .description(
                        "CVE-2017-13156（Janus）：V1（JAR Signature）方案对 APK 字节流的覆盖范围"
                        + "不包含 ZIP Local File Header 之前的任意前缀字节。"
                        + "攻击者可将恶意 DEX 字节码附加在合法 APK 之前，"
                        + "Android PackageInstaller（API 22–26）在安装/更新时会以该 DEX 执行，"
                        + "而签名验证结果仍为「通过」。"
                        + "此类攻击已被用于 OTA 更新劫持和恶意插件注入场景。"
                        + deviceRisk)
                .attribute("package",              packageName)
                .attribute("has_v1",               String.valueOf(info.hasV1Signature))
                .attribute("has_v2",               String.valueOf(info.hasV2Block))
                .attribute("has_v3",               String.valueOf(info.hasV3Block))
                .attribute("detection_confidence", info.confidence.name())
                .attribute("device_api",           String.valueOf(apiLevel))
                .attribute("janus_vulnerable_os",  String.valueOf(onVulnerableOs))
                .attribute("cve",                  "CVE-2017-13156")
                .build();
    }

    @NonNull
    private static Finding buildMalformedFinding(
            @NonNull final String packageName,
            @NonNull final String apkPath,
            @NonNull final ApkParseException e) {
        return Finding.of(FT_MALFORMED_STRUCTURE, Severity.CRITICAL)
                .title("APK 二进制结构违规")
                .description(
                        "目标 APK 的 ZIP/Signing Block 结构不符合 Google APK Specification 规范，"
                        + "可能为以下情况之一：① 手工篡改的 APK（用于绕过解析器的边界检查）；"
                        + "② 工具链 Bug 导致的损坏文件；③ 针对 PackageParser 的模糊测试载荷。"
                        + "建议对该应用进行人工二进制审计。解析错误：" + e.getMessage())
                .attribute("package",      packageName)
                .attribute("apk_path",     apkPath)
                .attribute("error_reason", e.reason.name())
                .attribute("error_detail", e.getMessage())
                .build();
    }

    @NonNull
    private static Finding buildSummaryFinding(
            final int totalUserApps,
            final int modernSigned,
            final int v1Only,
            final int malformed,
            final int undetermined,
            final int apiLevel,
            final boolean onVulnerableOs) {

        final String riskSummary = v1Only > 0
                ? (onVulnerableOs
                        ? v1Only + " 个应用在当前受影响设备上存在 Janus 利用窗口"
                        : v1Only + " 个应用采用纯 V1 签名，部署到旧设备后存在风险")
                : "未发现 V1-only 签名应用";

        return Finding.of(FT_SIGNATURE_SCAN_SUMMARY, Severity.INFO)
                .title("APK 签名方案扫描摘要")
                .description("共扫描 " + totalUserApps + " 个用户应用。"
                        + "现代签名（V2/V3）：" + modernSigned + " 个；"
                        + "疑似 V1-only：" + v1Only + " 个；"
                        + "结构损坏：" + malformed + " 个；"
                        + "无法判断：" + undetermined + " 个。"
                        + riskSummary + "。")
                .attribute("total_user_apps",        String.valueOf(totalUserApps))
                .attribute("modern_signed_count",    String.valueOf(modernSigned))
                .attribute("v1_only_count",          String.valueOf(v1Only))
                .attribute("malformed_count",        String.valueOf(malformed))
                .attribute("undetermined_count",     String.valueOf(undetermined))
                .attribute("device_api",             String.valueOf(apiLevel))
                .attribute("janus_vulnerable_os",    String.valueOf(onVulnerableOs))
                .build();
    }
}
