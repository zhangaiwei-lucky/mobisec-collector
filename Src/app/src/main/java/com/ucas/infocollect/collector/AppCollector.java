package com.ucas.infocollect.collector;

import android.app.AppOpsManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 已安装应用与使用情况收集器
 */
public class AppCollector {

    private static final String[] SENSITIVE_PERMISSIONS = {
        "READ_CONTACTS", "READ_CALL_LOG", "READ_SMS", "SEND_SMS",
        "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "CAMERA",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS",
        "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
        "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_DEVICE_ADMIN"
    };

    private static final String[] SECURITY_KEYWORDS = {
        "antivirus", "360", "kaspersky", "avast", "mcafee", "vpn",
        "supersu", "magisk", "xposed", "frida", "objection"
    };

    private final Context context;
    private final PackageManager pm;

    public AppCollector(Context context) {
        this.context = context;
        this.pm = context.getPackageManager();
    }

    public List<Map.Entry<String, String>> collect() {
        List<Map.Entry<String, String>> items = new ArrayList<>();

        // 获取应用列表：优先用 GET_PERMISSIONS，失败则降级到 0
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
                "未获取到应用列表。\nAndroid 11+ 需要 QUERY_ALL_PACKAGES 权限。\n" +
                "当前只能看到本应用自身。");
            return items;
        }

        // ── 统计概览 ─────────────────────────────────────────────
        CollectorUtils.addHeader(items, "应用统计概览");
        int userApps = 0, sysApps = 0, highPermApps = 0;
        List<String> securityTools = new ArrayList<>();

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) sysApps++; else userApps++;
            if (hasSensitivePerm(pkg)) highPermApps++;

            String pkgLower = pkg.packageName.toLowerCase(Locale.ROOT);
            for (String kw : SECURITY_KEYWORDS) {
                if (pkgLower.contains(kw)) { securityTools.add(pkg.packageName); break; }
            }
        }

        CollectorUtils.add(items, "用户应用数量",   String.valueOf(userApps));
        CollectorUtils.add(items, "系统应用数量",   String.valueOf(sysApps));
        CollectorUtils.add(items, "持有高危权限的应用", String.valueOf(highPermApps));
        CollectorUtils.add(items, "检测到的安全/分析工具",
            securityTools.isEmpty() ? "无" : "[HIGH]" + String.join(", ", securityTools));

        // ── 用户应用详情（最多30条）─────────────────────────────
        CollectorUtils.addHeader(items, "用户安装应用（权限分析）");
        int count = 0;
        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;
            if (count++ >= 30) {
                CollectorUtils.add(items, "...", "还有更多应用（仅展示前30条）");
                break;
            }

            String label = pkg.packageName;
            try {
                label = pm.getApplicationLabel(pkg.applicationInfo).toString();
            } catch (Exception ignored) {}

            StringBuilder perms = new StringBuilder();
            if (pkg.requestedPermissions != null) {
                for (String p : pkg.requestedPermissions) {
                    for (String sp : SENSITIVE_PERMISSIONS) {
                        if (p.contains(sp)) { perms.append(sp).append(" "); break; }
                    }
                }
            }

            String val = "v" + (pkg.versionName != null ? pkg.versionName : "?");
            if (perms.length() > 0)
                val += "\n[HIGH]危险权限: " + perms.toString().trim();
            CollectorUtils.add(items, label + "\n" + pkg.packageName, val);
        }

        // ── 应用使用统计 ──────────────────────────────────────────
        CollectorUtils.addHeader(items, "应用使用统计（过去7天）");
        if (hasUsageStatsPerm()) {
            collectUsageStats(items);
        } else {
            CollectorUtils.add(items, "未授权", "请在「设置→隐私→使用情况访问权限」中开启本应用的权限");
            CollectorUtils.add(items, "数据价值", "可推断用户日程规律、常用应用、职业特征和生活习惯");
        }

        return items;
    }

    private void collectUsageStats(List<Map.Entry<String, String>> items) {
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

            // 过滤掉 0 使用时长，按使用时长降序排列
            List<UsageStats> filtered = new ArrayList<>();
            for (UsageStats s : stats) {
                if (s.getTotalTimeInForeground() > 0) filtered.add(s);
            }
            filtered.sort((a, b) ->
                Long.compare(b.getTotalTimeInForeground(), a.getTotalTimeInForeground()));

            CollectorUtils.add(items, "有记录的应用数", String.valueOf(filtered.size()));

            SimpleDateFormat sdf = new SimpleDateFormat("MM-dd HH:mm", Locale.getDefault());
            int limit = Math.min(filtered.size(), 20);
            for (int i = 0; i < limit; i++) {
                UsageStats s = filtered.get(i);
                CollectorUtils.add(items, s.getPackageName(),
                    "[HIGH]使用 " + formatDuration(s.getTotalTimeInForeground())
                    + " | 最后: " + sdf.format(new Date(s.getLastTimeUsed())));
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "读取失败", e.getMessage());
        }
    }

    private boolean hasUsageStatsPerm() {
        try {
            AppOpsManager aom =
                (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
            int mode = aom.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(), context.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
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
