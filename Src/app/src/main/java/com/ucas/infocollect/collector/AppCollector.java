package com.ucas.infocollect.collector;

import android.Manifest;
import android.app.AppOpsManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Process;

import androidx.annotation.NonNull;

import com.ucas.infocollect.model.RiskLevel;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 已安装应用与使用情况收集器（V2 无 Context 版）。
 *
 * <p>展示内容：</p>
 * <ul>
 *   <li>统计概览：用户/系统/高危权限应用数量</li>
 *   <li>用户应用列表（APP_ITEM 可点击 → 详情页）</li>
 *   <li>应用使用统计（需 PACKAGE_USAGE_STATS 特殊权限）</li>
 * </ul>
 */
public class AppCollector implements InfoCollectorV2 {

    private static final int MAX_USER_APP_DISPLAY    = 60;
    private static final int MAX_USAGE_STATS_DISPLAY = 20;

    private static final String[] SENSITIVE_PERMISSIONS = {
        "READ_CONTACTS", "READ_CALL_LOG", "READ_SMS", "SEND_SMS",
        "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "CAMERA",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS",
        "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
        "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_DEVICE_ADMIN"
    };

    private static final String[] SECURITY_KEYWORDS = {
        "antivirus", "360", "kaspersky", "avast", "mcafee",
        "supersu", "magisk", "xposed", "frida", "objection"
    };

    private static final String[] VPN_KEYWORDS = { "vpn" };

    private static final String[] SYSTEM_PKG_PREFIXES = {
        "com.android.", "android.", "com.google.", "com.coloros.",
        "com.oppo.", "com.realme.", "com.miui.", "com.xiaomi.",
        "com.huawei.", "com.samsung.", "com.oneplus.", "com.oplus."
    };

    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        // PACKAGE_USAGE_STATS 是 AppOps 特殊权限（非危险权限），由用户在设置中手动授权；
        // GET_TASKS 已在 Android 5.0 后废弃，无需声明。
        // 此处仅供文档说明，应用层调用前无需动态申请。
        return Collections.emptyList();
    }

    @NonNull
    @Override
    @SuppressWarnings("deprecation")
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder result = CollectionResult.builder();
        final PackageManager pm = env.getPackageManager();

        List<PackageInfo> packages = new ArrayList<>();
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        } catch (final Exception e) {
            try {
                packages = pm.getInstalledPackages(0);
            } catch (final Exception e2) {
                result.add("错误", "无法获取应用列表: " + e2.getMessage());
                return result.build();
            }
        }

        if (packages.isEmpty()) {
            result.add("提示",
                "未获取到应用列表。\nAndroid 11+ 需要 QUERY_ALL_PACKAGES 权限。");
            return result.build();
        }

        // ── 统计概览 ──────────────────────────────────────────────
        result.addHeader("应用统计概览");
        int userApps = 0, sysApps = 0, highPermApps = 0;
        final List<String> securityTools = new ArrayList<>();
        final List<String> vpnApps       = new ArrayList<>();

        for (final PackageInfo pkg : packages) {
            if (pkg == null || pkg.applicationInfo == null) continue;
            final boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) sysApps++; else userApps++;
            if (hasSensitivePerm(pkg)) highPermApps++;

            final boolean isSysPkg = isSystemPackageName(pkg.packageName);
            if (!isSys && !isSysPkg && pkg.packageName != null) {
                final String pkgLower = pkg.packageName.toLowerCase(Locale.ROOT);
                for (final String kw : SECURITY_KEYWORDS) {
                    if (pkgLower.contains(kw)) { securityTools.add(pkg.packageName); break; }
                }
                for (final String kw : VPN_KEYWORDS) {
                    if (pkgLower.contains(kw)) { vpnApps.add(pkg.packageName); break; }
                }
            }
        }

        result.add("用户应用数量",       String.valueOf(userApps));
        result.add("系统应用数量",       String.valueOf(sysApps));
        result.add("持有高危权限的应用", String.valueOf(highPermApps));

        if (securityTools.isEmpty()) {
            result.add("检测到的安全/分析工具（用户应用）", "无");
        } else {
            result.addHighRisk("检测到的安全/分析工具（用户应用）",
                String.join(", ", securityTools));
        }
        result.add("VPN 相关应用（用户应用）",
            vpnApps.isEmpty() ? "无" : String.join(", ", vpnApps));
        result.add("提示", "点击下方应用可查看完整权限详情 →");

        // ── 用户应用列表 ──────────────────────────────────────────
        result.addHeader("用户安装应用（点击查看权限详情）");
        int count = 0;
        for (final PackageInfo pkg : packages) {
            if (pkg == null || pkg.applicationInfo == null) continue;
            if ((pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            if (count++ >= MAX_USER_APP_DISPLAY) {
                result.add("更多", "还有更多应用（仅展示前 " + MAX_USER_APP_DISPLAY + " 条）");
                break;
            }

            String label = pkg.packageName;
            try { label = pm.getApplicationLabel(pkg.applicationInfo).toString(); }
            catch (final Exception ignored) {}

            final int       dangerousCount = countDangerousPerms(pkg);
            final RiskLevel risk           = dangerousCount > 0 ? RiskLevel.HIGH : RiskLevel.NORMAL;
            final String    permSummary    = dangerousCount > 0
                ? dangerousCount + " 项危险权限" : "无危险权限";

            result.addAppItem(label, permSummary, risk, pkg.packageName);
        }

        // ── 应用使用统计 ──────────────────────────────────────────
        result.addHeader("应用使用统计（过去7天）");
        if (hasUsageStatsPerm(env)) {
            collectUsageStats(env, result);
        } else {
            result.add("未授权",
                "请在「设置→隐私→使用情况访问权限」中开启本应用权限");
            result.add("数据价值",
                "可推断用户日程规律、常用应用、职业特征和生活习惯");
        }

        return result.build();
    }

    private int countDangerousPerms(final PackageInfo pkg) {
        if (pkg.requestedPermissions == null) return 0;
        int count = 0;
        for (final String p : pkg.requestedPermissions)
            for (final String sp : SENSITIVE_PERMISSIONS)
                if (p.contains(sp)) { count++; break; }
        return count;
    }

    private void collectUsageStats(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final UsageStatsManager usm = env.getSystemService(UsageStatsManager.class);
            if (usm == null) {
                result.addDegrade("应用使用统计", DegradeReason.SERVICE_UNAVAILABLE,
                    "UsageStatsManager 不可用");
                return;
            }
            final long now     = System.currentTimeMillis();
            final long weekAgo = now - 7L * 24 * 60 * 60 * 1000;
            final List<UsageStats> stats =
                usm.queryUsageStats(UsageStatsManager.INTERVAL_BEST, weekAgo, now);

            if (stats == null || stats.isEmpty()) {
                result.addDegrade("应用使用统计", DegradeReason.NO_DATA,
                    "queryUsageStats 返回空，请确认已授权");
                return;
            }

            final List<UsageStats> filtered = new ArrayList<>();
            for (final UsageStats s : stats)
                if (s.getTotalTimeInForeground() > 0) filtered.add(s);
            filtered.sort((a, b) ->
                Long.compare(b.getTotalTimeInForeground(), a.getTotalTimeInForeground()));

            result.add("有记录的应用数", String.valueOf(filtered.size()));
            final SimpleDateFormat sdf =
                new SimpleDateFormat("MM-dd HH:mm", Locale.getDefault());
            final int limit = Math.min(filtered.size(), MAX_USAGE_STATS_DISPLAY);
            for (int i = 0; i < limit; i++) {
                final UsageStats s = filtered.get(i);
                result.addHighRisk(s.getPackageName(),
                    "使用 " + formatDuration(s.getTotalTimeInForeground())
                    + " | 最后: " + sdf.format(new Date(s.getLastTimeUsed())));
            }
        } catch (final Exception e) {
            result.addDegrade("应用使用统计", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private boolean hasUsageStatsPerm(@NonNull final SystemEnvironment env) {
        try {
            final AppOpsManager aom = env.getSystemService(AppOpsManager.class);
            if (aom == null) return false;
            final int mode = aom.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                env.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (final Exception e) {
            return false;
        }
    }

    private boolean isSystemPackageName(final String packageName) {
        if (packageName == null) return false;
        for (final String prefix : SYSTEM_PKG_PREFIXES) {
            if (packageName.startsWith(prefix)) return true;
        }
        return false;
    }

    private boolean hasSensitivePerm(final PackageInfo pkg) {
        if (pkg.requestedPermissions == null) return false;
        for (final String p : pkg.requestedPermissions)
            for (final String sp : SENSITIVE_PERMISSIONS)
                if (p.contains(sp)) return true;
        return false;
    }

    private String formatDuration(final long ms) {
        long sec = ms / 1000;
        if (sec < 60) return sec + "秒";
        long min = sec / 60;
        if (min < 60) return min + "分" + (sec % 60) + "秒";
        return (min / 60) + "时" + (min % 60) + "分";
    }
}
