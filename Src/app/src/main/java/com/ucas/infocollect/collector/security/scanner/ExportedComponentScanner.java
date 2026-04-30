package com.ucas.infocollect.collector.security.scanner;

import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ucas.infocollect.collector.security.Finding;
import com.ucas.infocollect.collector.security.ScanResult;
import com.ucas.infocollect.collector.security.SecurityScanContext;
import com.ucas.infocollect.collector.security.SecurityScanner;
import com.ucas.infocollect.collector.security.Severity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 无权限保护的导出组件扫描器（Exported Component Scanner）。
 *
 * <h2>威胁模型</h2>
 * <p>Android 四大组件中，{@code android:exported="true"} 表示任意第三方应用均可
 * 显式触发该组件。若组件同时未声明 {@code android:permission} 属性，则触发不需要
 * 任何权限——攻击面对设备上所有安装的应用无条件开放。</p>
 *
 * <h3>按组件类型分析攻击路径</h3>
 * <dl>
 *   <dt>Activity</dt>
 *   <dd>任意应用可通过 {@code startActivity()} 将用户界面偷换为恶意界面
 *       （UI Spoofing / Tapjacking），或直接绕过认证逻辑进入受限界面。
 *       部分 deeplink 处理 Activity 会将 URI 参数不加校验地传递给 WebView，
 *       可引发 Open Redirect 或 XSS 攻击。</dd>
 *
 *   <dt>Service</dt>
 *   <dd>恶意应用可通过 {@code bindService()} 绑定并调用 AIDL/Messenger 接口，
 *       执行后台任务、提取敏感数据或利用 Service 中的特权操作进行本地提权
 *       （Local Privilege Escalation）。无绑定权限约束的 Service 是
 *       Android 应用最常见的越权漏洞来源之一。</dd>
 *
 *   <dt>BroadcastReceiver</dt>
 *   <dd>任意应用可向导出的 Receiver 发送 Intent，可能触发：
 *       ① 重置认证状态（如 Session 失效）；
 *       ② 触发高权限操作（如向通讯录写入数据）；
 *       ③ 拒绝服务（发送大量 Intent 消耗 Receiver 处理线程）。
 *       即使 Receiver 内部仅做日志记录，过度暴露也为信息泄露创造了攻击面。</dd>
 * </dl>
 *
 * <h2>扫描逻辑</h2>
 * <ol>
 *   <li>通过 {@link PackageManager#getInstalledPackages} 枚举所有已安装用户 App，
 *       过滤掉系统应用（{@link ApplicationInfo#FLAG_SYSTEM} 和
 *       {@link ApplicationInfo#FLAG_UPDATED_SYSTEM_APP}）以减少噪音。</li>
 *   <li>对每个包逐一检查 {@code activities}、{@code services}、{@code receivers}
 *       数组：
 *       <ul>
 *         <li>{@link ActivityInfo#exported} / {@link ServiceInfo#exported} == {@code true}</li>
 *         <li>{@code permission} 为 {@code null} 或空字符串</li>
 *       </ul>
 *   </li>
 *   <li>每条脆弱组件生成独立的 {@link Severity#HIGH} {@link Finding}（Attributes 包含
 *       {@code packageName}、{@code componentName}、{@code componentType}）。</li>
 *   <li>每类组件超过 {@link #MAX_FINDINGS_PER_TYPE} 条时截断，防止 UI 溢出；
 *       精确计数仍写入摘要 Finding 的 Attributes。</li>
 *   <li>最终追加一条 {@link Severity#INFO} 摘要 Finding，记录全局统计数字。</li>
 * </ol>
 *
 * <h2>权限与 API 说明</h2>
 * <p>本扫描器不需要任何运行时危险权限（无需重写 {@link #getRequiredPermissions()}）。
 * 底层依赖 {@code PackageManager.GET_ACTIVITIES | GET_SERVICES | GET_RECEIVERS}
 * flag 读取组件元数据，这些 flag 均为 Manifest 级别查询，不涉及 Manifest 危险权限。</p>
 *
 * <p><b>Android 11+（API 30）可见性限制：</b>当应用的 {@code targetSdkVersion ≥ 30} 时，
 * {@code getInstalledPackages()} 仅返回本应用、系统应用以及在 {@code <queries>} 中
 * 声明了意图匹配的应用。若需扫描所有应用，清单中须声明
 * {@code <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>}。</p>
 */
public final class ExportedComponentScanner implements SecurityScanner {

    public static final String SCANNER_ID = "EXPORTED_COMPONENT";

    // ── Finding Type 常量 ──────────────────────────────────────────────────────
    private static final String FT_EXPORTED_ACTIVITY = "EXPORTED_ACTIVITY_NO_PERMISSION";
    private static final String FT_EXPORTED_SERVICE  = "EXPORTED_SERVICE_NO_PERMISSION";
    private static final String FT_EXPORTED_RECEIVER = "EXPORTED_RECEIVER_NO_PERMISSION";
    private static final String FT_SCAN_SUMMARY      = "EXPORTED_COMPONENT_SCAN_SUMMARY";

    /**
     * 每类组件的 Finding 输出上限，防止数百条 Finding 撑爆 RecyclerView 列表。
     * 超过上限的组件仍被计入统计，并在摘要中注明截断。
     */
    private static final int MAX_FINDINGS_PER_TYPE = 20;

    /**
     * PackageManager 查询标记。
     *
     * <ul>
     *   <li>{@code GET_ACTIVITIES}  (1) — 填充 {@code PackageInfo.activities}
     *       数组，用于检测 Activity 导出状态。</li>
     *   <li>{@code GET_SERVICES}   (4) — 填充 {@code PackageInfo.services}
     *       数组，用于检测 Service 导出状态。</li>
     *   <li>{@code GET_RECEIVERS}  (2) — 填充 {@code PackageInfo.receivers}
     *       数组，用于检测 BroadcastReceiver 导出状态。</li>
     * </ul>
     *
     * <p>这些 flag 均不属于运行时危险权限范畴。
     * {@code GET_PERMISSIONS} 未包含，因为本扫描器的判定依据是
     * 组件级别的 {@code permission} 字段，而非包级别的权限列表。</p>
     */
    @SuppressWarnings("deprecation")
    private static final int PM_FLAGS =
            PackageManager.GET_ACTIVITIES
            | PackageManager.GET_SERVICES
            | PackageManager.GET_RECEIVERS;

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
        return "无权限保护的导出组件扫描 — Activity / Service / BroadcastReceiver";
    }

    /**
     * {@inheritDoc}
     *
     * <p>本扫描器不需要任何 Android 运行时危险权限。
     * 底层依赖 {@code PackageManager.GET_ACTIVITIES | GET_SERVICES | GET_RECEIVERS}
     * flag 读取 Manifest 元数据，这些 flag 均无需 {@code uses-permission} 声明。</p>
     *
     * <p>若设备运行 Android 11+（API 30）且本应用 targetSdkVersion ≥ 30，
     * 则需在 AndroidManifest.xml 中声明
     * {@code <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>}
     * 以获取完整的包可见性——但该权限在 Play Store 审核政策中受到限制，
     * 部署前须评估合规风险。</p>
     *
     * @return 空列表（无需运行时危险权限）
     */
    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        return Collections.emptyList();
    }

    @NonNull
    @Override
    @SuppressWarnings("deprecation")
    public ScanResult scan(@NonNull final SecurityScanContext ctx) {
        final List<Finding> findings = new ArrayList<>();
        final List<String>  errors   = new ArrayList<>();

        final PackageManager pm = ctx.getPackageManager();

        // ── 1. 枚举已安装包（全量捕获异常，确保 Scanner 不崩溃）────────────────
        final List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PM_FLAGS);
        } catch (final SecurityException e) {
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() denied — SecurityException: "
                    + e.getMessage());
        } catch (final RuntimeException e) {
            // 覆盖 DeadObjectException（PackageManager 服务重启）、
            // TransactionTooLargeException（安装包数量极多）等
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() RuntimeException ["
                    + e.getClass().getSimpleName() + "]: " + e.getMessage());
        }

        if (packages == null) {
            // 正常情况下不应为 null，若发生则说明 PM 状态异常
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() returned null — "
                    + "possible Android 11+ visibility restriction: "
                    + "QUERY_ALL_PACKAGES permission may be missing");
        }

        // ── 2. 计数变量 ──────────────────────────────────────────────────────
        int userAppCount         = 0;
        int totalVulnActivities  = 0;
        int totalVulnServices    = 0;
        int totalVulnReceivers   = 0;
        int activityFindingCount = 0;
        int serviceFindingCount  = 0;
        int receiverFindingCount = 0;

        // ── 3. 遍历包信息 ────────────────────────────────────────────────────
        for (final PackageInfo pkgInfo : packages) {
            if (pkgInfo == null) continue;

            // ApplicationInfo 为 null 通常意味着包元数据损坏，静默跳过
            final ApplicationInfo appInfo = pkgInfo.applicationInfo;
            if (appInfo == null) continue;

            // 过滤系统应用（FLAG_SYSTEM = 原生系统包, FLAG_UPDATED_SYSTEM_APP = OTA 更新的系统包）
            if (isSystemApp(appInfo)) continue;

            // packageName 为 null 只见于严重损坏的包记录，防御性跳过
            final String packageName = pkgInfo.packageName;
            if (packageName == null || packageName.isEmpty()) continue;

            userAppCount++;

            // ── 3a. Activity 扫描 ────────────────────────────────────────────
            if (pkgInfo.activities != null) {
                for (final ActivityInfo ai : pkgInfo.activities) {
                    if (ai == null) continue;
                    // exported=true 且 permission 为 null 或空 → 无权限保护
                    if (ai.exported && isNullOrEmpty(ai.permission)) {
                        totalVulnActivities++;
                        if (activityFindingCount < MAX_FINDINGS_PER_TYPE) {
                            findings.add(buildComponentFinding(
                                    FT_EXPORTED_ACTIVITY, "Activity", packageName, ai.name));
                            activityFindingCount++;
                        }
                    }
                }
            }

            // ── 3b. Service 扫描 ─────────────────────────────────────────────
            if (pkgInfo.services != null) {
                for (final ServiceInfo si : pkgInfo.services) {
                    if (si == null) continue;
                    if (si.exported && isNullOrEmpty(si.permission)) {
                        totalVulnServices++;
                        if (serviceFindingCount < MAX_FINDINGS_PER_TYPE) {
                            findings.add(buildComponentFinding(
                                    FT_EXPORTED_SERVICE, "Service", packageName, si.name));
                            serviceFindingCount++;
                        }
                    }
                }
            }

            // ── 3c. BroadcastReceiver 扫描 ───────────────────────────────────
            // PackageInfo.receivers 的元素类型为 ActivityInfo（Receiver 与 Activity
            // 共用同一 ComponentInfo 子类型，区别仅在于注册方式）
            if (pkgInfo.receivers != null) {
                for (final ActivityInfo ri : pkgInfo.receivers) {
                    if (ri == null) continue;
                    if (ri.exported && isNullOrEmpty(ri.permission)) {
                        totalVulnReceivers++;
                        if (receiverFindingCount < MAX_FINDINGS_PER_TYPE) {
                            findings.add(buildComponentFinding(
                                    FT_EXPORTED_RECEIVER, "BroadcastReceiver",
                                    packageName, ri.name));
                            receiverFindingCount++;
                        }
                    }
                }
            }
        }

        // ── 4. 摘要 Finding ──────────────────────────────────────────────────
        final int     totalVuln  = totalVulnActivities + totalVulnServices + totalVulnReceivers;
        final boolean truncated  = activityFindingCount >= MAX_FINDINGS_PER_TYPE
                || serviceFindingCount >= MAX_FINDINGS_PER_TYPE
                || receiverFindingCount >= MAX_FINDINGS_PER_TYPE;

        final StringBuilder summaryDesc = new StringBuilder();
        summaryDesc.append("共扫描 ").append(userAppCount)
                   .append(" 个用户应用（已过滤系统应用），发现 ")
                   .append(totalVuln).append(" 个无权限保护的导出组件：")
                   .append(totalVulnActivities).append(" Activity, ")
                   .append(totalVulnServices).append(" Service, ")
                   .append(totalVulnReceivers).append(" BroadcastReceiver。");
        if (truncated) {
            summaryDesc.append(" [注意：每类 Finding 上限 ")
                       .append(MAX_FINDINGS_PER_TYPE)
                       .append(" 条，实际数量以 Attribute 中的计数为准]");
        }

        findings.add(Finding.of(FT_SCAN_SUMMARY, Severity.INFO)
                .title("导出组件扫描摘要")
                .description(summaryDesc.toString())
                .attribute("total_user_apps",       String.valueOf(userAppCount))
                .attribute("vulnerable_activities", String.valueOf(totalVulnActivities))
                .attribute("vulnerable_services",   String.valueOf(totalVulnServices))
                .attribute("vulnerable_receivers",  String.valueOf(totalVulnReceivers))
                .attribute("total_vulnerable",      String.valueOf(totalVuln))
                .build());

        return errors.isEmpty()
                ? ScanResult.success(SCANNER_ID, findings)
                : ScanResult.partial(SCANNER_ID, findings, errors);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Finding 工厂方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 构建单条脆弱组件 Finding。
     *
     * <p>短名称（shortName）通过去掉 {@code packageName} 前缀获得，
     * 使 UI 列表标题更简洁，完整名称仍保留在 {@code componentName} Attribute 中。</p>
     */
    @NonNull
    private static Finding buildComponentFinding(
            @NonNull final String findingType,
            @NonNull final String componentType,
            @NonNull final String packageName,
            @Nullable final String componentName) {

        final String safeName   = componentName != null ? componentName : "(unknown)";
        final String shortName  = safeName.startsWith(packageName + ".")
                ? safeName.substring(packageName.length() + 1)
                : safeName;

        final String titlePrefix;
        final String riskDetail;

        switch (componentType) {
            case "Activity":
                titlePrefix = "无保护的导出 Activity";
                riskDetail  =
                        "任意第三方应用可无需权限直接 startActivity() 启动此界面，"
                        + "可能引发：① 界面欺骗（UI Spoofing），将合法界面替换为仿冒界面；"
                        + "② 跨应用越权访问，直接进入本应受认证保护的界面；"
                        + "③ WebView 中的 Open Redirect / XSS（如果该 Activity 处理 deeplink URI）。"
                        + "修复建议：声明 android:permission 属性，"
                        + "或将 android:exported 设为 false 并通过隐式 Intent 触发。";
                break;
            case "Service":
                titlePrefix = "无保护的导出 Service";
                riskDetail  =
                        "任意应用可无需权限通过 bindService() / startService() 访问此 Service，"
                        + "可能导致：① AIDL/Messenger 接口越权调用，执行敏感后台逻辑；"
                        + "② Service 持有的系统权限被间接利用（Permission Re-Delegation）；"
                        + "③ 长期绑定耗尽 Service 进程资源（DoS 攻击）。"
                        + "修复建议：在 <service> 标签中声明 android:permission，"
                        + "或改用 LocalBroadcastManager 等仅应用内可访问的通信机制。";
                break;
            default: // BroadcastReceiver
                titlePrefix = "无保护的导出 Receiver";
                riskDetail  =
                        "任意应用可无需权限向此 Receiver 发送任意 Intent，"
                        + "可能导致：① 触发安全敏感操作（如注销 Session、重置数据）；"
                        + "② 通过精心构造的 Intent Extra 注入恶意数据；"
                        + "③ 向 Receiver 发送大量 Intent 实施本地拒绝服务（DoS）攻击。"
                        + "修复建议：在 <receiver> 标签声明 android:permission，"
                        + "或改用 LocalBroadcastManager；若仅响应系统广播，"
                        + "将 android:exported 设为 false 可完全封闭第三方触发路径。";
                break;
        }

        return Finding.of(findingType, Severity.HIGH)
                .title(titlePrefix + ": " + shortName)
                .description(riskDetail)
                .attribute("packageName",   packageName)
                .attribute("componentName", safeName)
                .attribute("componentType", componentType)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 内部工具方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 判断给定 ApplicationInfo 是否为系统应用。
     *
     * <p>{@code FLAG_SYSTEM} 标记原生内置系统包，{@code FLAG_UPDATED_SYSTEM_APP}
     * 标记通过 OTA 升级覆盖的系统包（如 Google Play Services）。
     * 两者均排除在外，避免将正常 Android 框架组件误报为漏洞。</p>
     */
    private static boolean isSystemApp(@NonNull final ApplicationInfo ai) {
        return (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                || (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
    }

    /**
     * 检查权限字符串是否为 null 或空。
     *
     * <p>Android 解析 Manifest 时，未声明 {@code android:permission} 的组件
     * 其 {@code permission} 字段为 {@code null}；极少数情况下（如混淆后的
     * AAR 依赖）可能出现空字符串，一并视为"无权限"处理。</p>
     */
    private static boolean isNullOrEmpty(@Nullable final String s) {
        return s == null || s.isEmpty();
    }
}
