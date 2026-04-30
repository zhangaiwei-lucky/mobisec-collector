package com.ucas.infocollect.collector.security.scanner;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;

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
 * 高危 ContentProvider 扫描器（Dangerous ContentProvider Scanner）。
 *
 * <h2>威胁模型</h2>
 * <p>Android ContentProvider 是应用间数据共享的核心机制。当一个 Provider 被导出
 * （{@code android:exported="true"}）且未声明任何读写权限时，设备上的所有应用均可
 * 通过 {@code ContentResolver} 无限制地访问其暴露的数据——这等价于将内部数据库、
 * 文件系统路径或业务接口向所有第三方完全公开。</p>
 *
 * <h3>主要攻击路径</h3>
 * <dl>
 *   <dt>路径遍历（Directory Traversal）</dt>
 *   <dd>FileProvider 配置不当或未正确限制 {@code res/xml/file_paths.xml} 时，
 *       攻击者可通过构造 {@code content://authority/../../../data/data/target.app/databases/}
 *       路径绕过根目录限制，读取目标应用的内部数据库、SharedPreferences 或私钥文件。
 *       典型案例：CVE-2018-9474（Samsung Gallery Provider）。</dd>
 *
 *   <dt>越权数据读写</dt>
 *   <dd>调用 {@code ContentResolver.query()} 可枚举内部数据库全表；
 *       {@code insert()} / {@code update()} / {@code delete()} 可直接修改敏感数据。
 *       即使 Provider 看似只提供只读 API，无权限约束也会为后续的逻辑漏洞放大提供基础。</dd>
 *
 *   <dt>URI 授权委托滥用（grantUriPermissions）</dt>
 *   <dd>当 {@code android:grantUriPermissions="true"} 时，Provider 可将对特定 URI
 *       的临时访问权限授予其他应用。攻击者可利用开放 Provider 作为"权限代理"，
 *       诱使目标应用调用 {@code grantUriPermission()} 并将权限委托给攻击者控制的组件。
 *       CVE-2014-8609、CVE-2021-0306、CVE-2022-20347 均属此类攻击模式。</dd>
 *
 *   <dt>SQL 注入（通过 selection 参数）</dt>
 *   <dd>Provider 未做参数化查询且对外开放时，{@code query()} 的 {@code selection}
 *       参数可直接拼入 SQL WHERE 子句，攻击者可执行任意 SQL 语句读取或删除数据库内容。</dd>
 * </dl>
 *
 * <h2>判定规则</h2>
 * <pre>
 *  条件                                        Severity   Finding Type
 *  ─────────────────────────────────────────── ────────── ────────────────────────────
 *  exported=true AND read+write 权限均为 null   CRITICAL   PROVIDER_FULLY_OPEN
 *  上述条件 + grantUriPermissions=true          CRITICAL   PROVIDER_OPEN_WITH_URI_GRANT
 *  （grantUriPermissions 额外标记，不改变 Severity，但 description 中追加攻击链说明）
 * </pre>
 *
 * <h2>权限说明</h2>
 * <p>本扫描器不需要任何 Android 运行时危险权限。
 * 底层依赖 {@code PackageManager.GET_PROVIDERS} flag 读取 Manifest 元数据，
 * 该 flag 无需 {@code uses-permission} 声明。</p>
 *
 * <p><b>Android 11+（API 30）可见性限制同 {@link ExportedComponentScanner}。</b></p>
 */
public final class DangerousProviderScanner implements SecurityScanner {

    public static final String SCANNER_ID = "DANGEROUS_PROVIDER";

    // ── Finding Type 常量 ──────────────────────────────────────────────────────
    private static final String FT_OPEN_PROVIDER           = "PROVIDER_FULLY_OPEN";
    private static final String FT_OPEN_PROVIDER_URI_GRANT = "PROVIDER_OPEN_WITH_URI_GRANT";
    private static final String FT_SCAN_SUMMARY            = "DANGEROUS_PROVIDER_SCAN_SUMMARY";

    /**
     * PackageManager 查询标记。
     *
     * <ul>
     *   <li>{@code GET_PROVIDERS} (8) — 填充 {@code PackageInfo.providers} 数组，
     *       包含 {@link ProviderInfo#readPermission}、{@link ProviderInfo#writePermission}、
     *       {@link ProviderInfo#grantUriPermissions} 等关键字段。</li>
     * </ul>
     *
     * <p>不包含 {@code GET_URI_PERMISSION_PATTERNS} 或 {@code GET_META_DATA}，
     * 避免返回数据体过大触发 {@code TransactionTooLargeException}。</p>
     */
    @SuppressWarnings("deprecation")
    private static final int PM_FLAGS = PackageManager.GET_PROVIDERS;

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
        return "高危 ContentProvider 扫描 — 开放读写 / URI 授权滥用攻击面";
    }

    /**
     * {@inheritDoc}
     *
     * <p>本扫描器不需要任何 Android 运行时危险权限。
     * 底层依赖 {@code PackageManager.GET_PROVIDERS} flag 读取组件元数据。</p>
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

        // ── 1. 枚举已安装包 ──────────────────────────────────────────────────
        final List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PM_FLAGS);
        } catch (final SecurityException e) {
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() denied — SecurityException: "
                    + e.getMessage());
        } catch (final RuntimeException e) {
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() RuntimeException ["
                    + e.getClass().getSimpleName() + "]: " + e.getMessage());
        }

        if (packages == null) {
            return ScanResult.failed(SCANNER_ID,
                    "PackageManager.getInstalledPackages() returned null — "
                    + "possible Android 11+ QUERY_ALL_PACKAGES permission missing");
        }

        // ── 2. 计数变量 ──────────────────────────────────────────────────────
        int userAppCount          = 0;
        int openProviderCount     = 0;
        int grantUriProviderCount = 0;

        // ── 3. 遍历包信息 ────────────────────────────────────────────────────
        for (final PackageInfo pkgInfo : packages) {
            if (pkgInfo == null) continue;

            final ApplicationInfo appInfo = pkgInfo.applicationInfo;
            if (appInfo == null) continue;
            if (isSystemApp(appInfo)) continue;

            final String packageName = pkgInfo.packageName;
            if (packageName == null || packageName.isEmpty()) continue;

            userAppCount++;

            // providers 字段在 GET_PROVIDERS flag 下填充，但包内无 Provider 时为 null
            if (pkgInfo.providers == null) continue;

            for (final ProviderInfo pi : pkgInfo.providers) {
                if (pi == null) continue;

                // 只处理导出的 Provider
                if (!pi.exported) continue;

                // readPermission 和 writePermission 均为 null 或空时，Provider 完全无保护。
                // 注意：android:permission 属性会同时设置两个字段；
                // android:readPermission / android:writePermission 可单独覆盖；
                // 只有当两者均未设置时才构成"完全开放"。
                final boolean noReadPerm  = isNullOrEmpty(pi.readPermission);
                final boolean noWritePerm = isNullOrEmpty(pi.writePermission);

                if (!noReadPerm || !noWritePerm) {
                    // 至少有一项权限保护，跳过（部分保护需进一步人工审查，不在本扫描范围内）
                    continue;
                }

                // Authority 为 null 的情况极为罕见（Manifest 验证应阻止），保留兜底
                final String authority = (pi.authority != null && !pi.authority.isEmpty())
                        ? pi.authority
                        : packageName + "/.UnknownProvider";

                if (pi.grantUriPermissions) {
                    grantUriProviderCount++;
                    findings.add(buildGrantUriProviderFinding(packageName, authority));
                } else {
                    openProviderCount++;
                    findings.add(buildOpenProviderFinding(packageName, authority));
                }
            }
        }

        // ── 4. 摘要 Finding ──────────────────────────────────────────────────
        final int totalDangerous = openProviderCount + grantUriProviderCount;

        final StringBuilder desc = new StringBuilder();
        desc.append("共扫描 ").append(userAppCount)
            .append(" 个用户应用（已过滤系统应用），发现 ")
            .append(totalDangerous).append(" 个高危 ContentProvider：")
            .append(openProviderCount).append(" 个完全开放（无读写权限），")
            .append(grantUriProviderCount).append(" 个开放且启用 grantUriPermissions。");

        if (totalDangerous == 0) {
            desc.append(" 未检测到明显的 ContentProvider 过度暴露问题。");
        }

        findings.add(Finding.of(FT_SCAN_SUMMARY, Severity.INFO)
                .title("高危 ContentProvider 扫描摘要")
                .description(desc.toString())
                .attribute("total_user_apps",     String.valueOf(userAppCount))
                .attribute("open_providers",      String.valueOf(openProviderCount))
                .attribute("grant_uri_providers", String.valueOf(grantUriProviderCount))
                .attribute("total_dangerous",     String.valueOf(totalDangerous))
                .build());

        return errors.isEmpty()
                ? ScanResult.success(SCANNER_ID, findings)
                : ScanResult.partial(SCANNER_ID, findings, errors);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Finding 工厂方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 构建"完全开放 Provider"Finding（无读写权限，但 grantUriPermissions 未启用）。
     *
     * <p>威胁等级 {@link Severity#CRITICAL}：数据泄露路径直接，攻击者无需任何前置权限。</p>
     */
    @NonNull
    private static Finding buildOpenProviderFinding(
            @NonNull final String packageName,
            @NonNull final String authority) {
        return Finding.of(FT_OPEN_PROVIDER, Severity.CRITICAL)
                .title("完全开放的 ContentProvider: " + authority)
                .description(
                        "ContentProvider（authority: " + authority + "）已导出且未声明任何读写权限"
                        + "（readPermission=null, writePermission=null）。"
                        + "设备上的任意第三方应用均可通过 ContentResolver 无需任何权限地访问该 Provider：\n"
                        + "① ContentResolver.query() — 枚举暴露的全部数据（可能含账户、密钥、消息）；\n"
                        + "② ContentResolver.insert/update/delete() — 直接篡改或删除业务数据；\n"
                        + "③ ContentResolver.openFile() — 若为 FileProvider，可能通过路径遍历"
                        + "（\"../\"）读取 /data/data/ 中的任意私有文件。\n"
                        + "修复建议：在 <provider> 标签上声明 android:readPermission 和"
                        + " android:writePermission（至少设置 signatureOrSystem 级别），"
                        + "或将 android:exported 设为 false 并通过 Intent 机制间接触发。")
                .attribute("authority",           authority)
                .attribute("packageName",         packageName)
                .attribute("grantUriPermissions", "false")
                .build();
    }

    /**
     * 构建"开放 Provider + URI 授权已启用"Finding（风险更高）。
     *
     * <p>在无权限保护的基础上额外启用了 {@code grantUriPermissions}，
     * 使该 Provider 可被用作"权限代理"进行 URI 授权委托攻击，威胁等级仍为
     * {@link Severity#CRITICAL}，但 {@code description} 包含额外的攻击链说明。</p>
     */
    @NonNull
    private static Finding buildGrantUriProviderFinding(
            @NonNull final String packageName,
            @NonNull final String authority) {
        return Finding.of(FT_OPEN_PROVIDER_URI_GRANT, Severity.CRITICAL)
                .title("开放 ContentProvider + URI 授权已启用: " + authority)
                .description(
                        "ContentProvider（authority: " + authority + "）已导出且无读写权限，"
                        + "同时 android:grantUriPermissions=\"true\"。\n"
                        + "攻击链风险极高：\n"
                        + "① 攻击者无需任何权限可直接访问 Provider 的所有 CRUD 接口；\n"
                        + "② 利用开放 Provider 作为"权限代理"——诱使目标应用调用"
                        + " Context.grantUriPermission() 并将临时 URI 访问权委托给攻击者控制的组件；\n"
                        + "③ 配合路径遍历（\"../\"）绕过 FileProvider xml 路径限制，"
                        + "读取 /data/data/ 任意私有文件；\n"
                        + "④ 若 <grant-uri-permission path=\"*\"/> 规则过宽，"
                        + "攻击者可枚举并读取所有授权路径下的文件，"
                        + "包括 SQLite 数据库（.db）、SharedPreferences（.xml）和私钥（.p12/.pem）。\n"
                        + "已知同类 CVE：CVE-2014-8609、CVE-2021-0306、CVE-2022-20347。\n"
                        + "修复建议：声明权限同时，审查所有 <grant-uri-permission> 规则，"
                        + "禁止使用 android:path=\"*\" / android:pathPattern=\".*\" 等过宽路径匹配；"
                        + "改用精确路径（android:path=\"/share/\"）限制 URI 授权范围。")
                .attribute("authority",           authority)
                .attribute("packageName",         packageName)
                .attribute("grantUriPermissions", "true")
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 内部工具方法
    // ─────────────────────────────────────────────────────────────────────────

    private static boolean isSystemApp(@NonNull final ApplicationInfo ai) {
        return (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                || (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
    }

    private static boolean isNullOrEmpty(@Nullable final String s) {
        return s == null || s.isEmpty();
    }
}
