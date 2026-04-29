package com.ucas.infocollect.collector;

import android.app.AppOpsManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 已安装应用与使用情况收集器
 *
 * 展示内容：
 * - 统计概览：用户/系统/高危权限应用数量
 * - 用户应用列表（APP_ITEM 可点击 → 详情页）：显示图标 + 危险权限徽章
 * - 应用使用统计（需 UsageStats 权限）
 */
public class AppCollector implements InfoCollector {

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

    // 安全/分析工具关键词（仅匹配用户应用，且排除 VPN 关键词）
    private static final String[] SECURITY_KEYWORDS = {
        "antivirus", "360", "kaspersky", "avast", "mcafee",
        "supersu", "magisk", "xposed", "frida", "objection"
    };

    // VPN 关键词单独处理（系统 VPN 组件不应标为"分析工具"）
    private static final String[] VPN_KEYWORDS = { "vpn" };

    // 系统包名前缀白名单：这些前缀的应用不归入安全/VPN 工具
    private static final String[] SYSTEM_PKG_PREFIXES = {
        "com.android.", "android.", "com.google.", "com.coloros.",
        "com.oppo.", "com.realme.", "com.miui.", "com.xiaomi.",
        "com.huawei.", "com.samsung.", "com.oneplus.", "com.oplus."
    };

    @Override
    public List<InfoRow> collect(Context context) {
        PackageManager pm = context.getPackageManager();
        List<InfoRow> items = new ArrayList<>();

        List<PackageInfo> packages = new ArrayList<>();
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        } catch (Exception e) {
            try {
                packages = pm.getInstalledPackages(0);
            } catch (Exception e2) {
                CollectorUtils.add(items, "错误", "无法获取应用列表: " + e2.getMessage());
                return items;
            }
        }

        if (packages.isEmpty()) {
            CollectorUtils.add(items, "提示",
                "未获取到应用列表。\nAndroid 11+ 需要 QUERY_ALL_PACKAGES 权限。");
            return items;
        }

        // ── 统计概览 ─────────────────────────────────────────────────
        CollectorUtils.addHeader(items, "应用统计概览");
        int userApps = 0, sysApps = 0, highPermApps = 0;
        List<String> securityTools = new ArrayList<>();
        List<String> vpnApps      = new ArrayList<>();

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) sysApps++; else userApps++;
            if (hasSensitivePerm(pkg)) highPermApps++;

            // 安全工具识别：仅匹配用户应用，且排除系统包名前缀
            boolean isSysPkg = isSystemPackageName(pkg.packageName);
            if (!isSys && !isSysPkg) {
                String pkgLower = pkg.packageName.toLowerCase(Locale.ROOT);
                for (String kw : SECURITY_KEYWORDS) {
                    if (pkgLower.contains(kw)) { securityTools.add(pkg.packageName); break; }
                }
                for (String kw : VPN_KEYWORDS) {
                    if (pkgLower.contains(kw)) { vpnApps.add(pkg.packageName); break; }
                }
            }
        }

        CollectorUtils.add(items, "用户应用数量",       String.valueOf(userApps));
        CollectorUtils.add(items, "系统应用数量",       String.valueOf(sysApps));
        CollectorUtils.add(items, "持有高危权限的应用", String.valueOf(highPermApps));
        CollectorUtils.add(items, "检测到的安全/分析工具（用户应用）",
            securityTools.isEmpty() ? "无"
                : CollectorUtils.HIGH_RISK_PREFIX + String.join(", ", securityTools));
        CollectorUtils.add(items, "VPN 相关应用（用户应用）",
            vpnApps.isEmpty() ? "无" : String.join(", ", vpnApps));
        CollectorUtils.add(items, "提示", "点击下方应用可查看完整权限详情 →");

        // ── 用户应用列表（APP_ITEM 可点击）────────────────────────────
        CollectorUtils.addHeader(items, "用户安装应用（点击查看权限详情）");
        int count = 0;
        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;
            if (count++ >= MAX_USER_APP_DISPLAY) {
                CollectorUtils.add(items, "更多", "还有更多应用（仅展示前 " + MAX_USER_APP_DISPLAY + " 条）");
                break;
            }

            String label = pkg.packageName;
            try { label = pm.getApplicationLabel(pkg.applicationInfo).toString(); }
            catch (Exception ignored) {}

            int dangerousCount = countDangerousPerms(pkg);
            RiskLevel risk = dangerousCount > 0 ? RiskLevel.HIGH : RiskLevel.NORMAL;
            String permSummary = dangerousCount > 0
                ? dangerousCount + " 项危险权限" : "无危险权限";

            CollectorUtils.addAppItem(items, label, permSummary, risk, pkg.packageName);
        }

        // ── 应用使用统计 ──────────────────────────────────────────────
        CollectorUtils.addHeader(items, "应用使用统计（过去7天）");
        if (hasUsageStatsPerm(context)) {
            collectUsageStats(context, items);
        } else {
            CollectorUtils.add(items, "未授权",
                "请在「设置→隐私→使用情况访问权限」中开启本应用权限");
            CollectorUtils.add(items, "数据价值",
                "可推断用户日程规律、常用应用、职业特征和生活习惯");
        }

        return items;
    }

    private int countDangerousPerms(PackageInfo pkg) {
        if (pkg.requestedPermissions == null) return 0;
        int count = 0;
        for (String p : pkg.requestedPermissions)
            for (String sp : SENSITIVE_PERMISSIONS)
                if (p.contains(sp)) { count++; break; }
        return count;
    }

    private void collectUsageStats(Context context, List<InfoRow> items) {
        try {
            UsageStatsManager usm =
                (UsageStatsManager) context.getSystemService(Context.USAGE_STATS_SERVICE);
            long now = System.currentTimeMillis();
            long weekAgo = now - 7L * 24 * 60 * 60 * 1000;
            List<UsageStats> stats =
                usm.queryUsageStats(UsageStatsManager.INTERVAL_BEST, weekAgo, now);

            if (stats == null || stats.isEmpty()) {
                CollectorUtils.add(items, "无数据", "queryUsageStats 返回空，请确认已授权");
                return;
            }

            List<UsageStats> filtered = new ArrayList<>();
            for (UsageStats s : stats)
                if (s.getTotalTimeInForeground() > 0) filtered.add(s);
            filtered.sort((a, b) ->
                Long.compare(b.getTotalTimeInForeground(), a.getTotalTimeInForeground()));

            CollectorUtils.add(items, "有记录的应用数", String.valueOf(filtered.size()));
            SimpleDateFormat sdf = new SimpleDateFormat("MM-dd HH:mm", Locale.getDefault());
            int limit = Math.min(filtered.size(), MAX_USAGE_STATS_DISPLAY);
            for (int i = 0; i < limit; i++) {
                UsageStats s = filtered.get(i);
                CollectorUtils.add(items, s.getPackageName(),
                    CollectorUtils.HIGH_RISK_PREFIX + "使用 "
                        + formatDuration(s.getTotalTimeInForeground())
                        + " | 最后: " + sdf.format(new Date(s.getLastTimeUsed())));
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "读取失败", e.getMessage());
        }
    }

    private boolean hasUsageStatsPerm(Context context) {
        try {
            AppOpsManager aom =
                (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
            int mode = aom.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(), context.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) { return false; }
    }

    private boolean isSystemPackageName(String packageName) {
        for (String prefix : SYSTEM_PKG_PREFIXES) {
            if (packageName.startsWith(prefix)) return true;
        }
        return false;
    }

    private boolean hasSensitivePerm(PackageInfo pkg) {
        if (pkg.requestedPermissions == null) return false;
        for (String p : pkg.requestedPermissions)
            for (String sp : SENSITIVE_PERMISSIONS)
                if (p.contains(sp)) return true;
        return false;
    }

    private String formatDuration(long ms) {
        long sec = ms / 1000;
        if (sec < 60) return sec + "秒";
        long min = sec / 60;
        if (min < 60) return min + "分" + (sec % 60) + "秒";
        return (min / 60) + "时" + (min % 60) + "分";
    }
}
