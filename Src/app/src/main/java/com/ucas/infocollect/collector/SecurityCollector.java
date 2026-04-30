package com.ucas.infocollect.collector;

import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import com.ucas.infocollect.model.InfoRow;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SecurityCollector implements InfoCollector {

    private static final int MAX_SIGNATURE_SAMPLE = 5;
    private static final int MAX_EXPORTED_COMPONENT_SAMPLE = 5;
    private static final int MAX_PROVIDER_SAMPLE = 5;
    private static final int MAX_OVER_PRIVILEGED_TOP = 10;
    private static final int MAX_CLEARTEXT_APP_SAMPLE = 10;
    private static final int MAX_PROCESS_SAMPLE = 15;
    private static final long MAX_SIGNING_BLOCK_BYTES = 8L * 1024L * 1024L; // 8 MB
    private static final int ZIP_EOCD_MIN_SIZE = 22;
    private static final int ZIP_EOCD_MAX_SEARCH = 65535 + ZIP_EOCD_MIN_SIZE;
    private static final int ZIP_EOCD_MAGIC = 0x06054b50;
    private static final long APK_SIG_BLOCK_MAGIC_LOW = 0x20676953204b5041L;   // "APK Sig "
    private static final long APK_SIG_BLOCK_MAGIC_HIGH = 0x3234206b636f6c42L;  // "Block 42"
    private static final int APK_SIG_SCHEME_V2_BLOCK_ID = 0x7109871a;
    private static final int APK_SIG_SCHEME_V3_BLOCK_ID = 0xf05368c0;
    private static final int APK_SIG_SCHEME_V31_BLOCK_ID = 0x1b93ad61;

    private enum DetectionConfidence {
        HIGH,
        MEDIUM,
        LOW
    }

    private static class SignatureDetectionResult {
        final String packageName;
        final boolean hasV1Signature;
        final boolean hasV2Block;
        final boolean hasV3Block;
        final Boolean hasV4Block; // null means unknown/not parsed
        final DetectionConfidence detectionConfidence;
        final String detectionNote;
        final boolean undetermined;

        SignatureDetectionResult(
                String packageName,
                boolean hasV1Signature,
                boolean hasV2Block,
                boolean hasV3Block,
                Boolean hasV4Block,
                DetectionConfidence detectionConfidence,
                String detectionNote,
                boolean undetermined
        ) {
            this.packageName = packageName;
            this.hasV1Signature = hasV1Signature;
            this.hasV2Block = hasV2Block;
            this.hasV3Block = hasV3Block;
            this.hasV4Block = hasV4Block;
            this.detectionConfidence = detectionConfidence;
            this.detectionNote = detectionNote;
            this.undetermined = undetermined;
        }
    }

    private static class SigningBlockParseResult {
        final boolean parsed;
        final boolean hasSigningBlock;
        final boolean hasV2Block;
        final boolean hasV3Block;
        final String note;

        SigningBlockParseResult(
                boolean parsed,
                boolean hasSigningBlock,
                boolean hasV2Block,
                boolean hasV3Block,
                String note
        ) {
            this.parsed = parsed;
            this.hasSigningBlock = hasSigningBlock;
            this.hasV2Block = hasV2Block;
            this.hasV3Block = hasV3Block;
            this.note = note;
        }
    }

    @Override
    public List<InfoRow> collect(Context context) {
        PackageManager pm = context.getPackageManager();
        List<InfoRow> items = new ArrayList<>();

        CollectorUtils.addHeader(items, "SELinux / SEAndroid 安全状态");
        collectSeLinux(items);

        CollectorUtils.addHeader(items, "系统敏感文件可访问性");
        checkSensitiveFiles(items);

        CollectorUtils.addHeader(items, "导出组件扫描（Intent/IPC 攻击面）");
        scanExportedComponents(pm, items);

        CollectorUtils.addHeader(items, "Content Provider 路径遍历风险");
        scanDangerousProviders(pm, items);

        CollectorUtils.addHeader(items, "APK 签名方案 / Janus 漏洞");
        analyzeSignatureSchemes(pm, items);

        CollectorUtils.addHeader(items, "过权限应用 Top 10");
        scanOverPrivilegedApps(pm, items);

        CollectorUtils.addHeader(items, "允许明文 HTTP 的应用（静态配置风险初筛）");
        scanCleartextApps(pm, items);

        CollectorUtils.addHeader(items, "运行中进程与可疑服务");
        checkRunningProcesses(context, items);

        return items;
    }

    private void collectSeLinux(List<InfoRow> items) {
        String enforceRaw = readFile("/sys/fs/selinux/enforce").trim();
        Boolean fileEnforcing = null;
        if (!enforceRaw.isEmpty()) {
            fileEnforcing = enforceRaw.equals("1");
            CollectorUtils.add(items, "SELinux 模式（/sys/fs/selinux/enforce）",
                fileEnforcing ? "1 → Enforcing（强制）✓ MAC 策略生效"
                              : CollectorUtils.HIGH_RISK_PREFIX
                                + "0 → Permissive（宽松）— MAC 策略不生效，提权风险高");
        } else {
            CollectorUtils.add(items, "SELinux 模式（/sys/fs/selinux/enforce）",
                "无法读取（Android 系统限制，请以 adb shell getenforce 复核）");
        }

        String paranoidRaw = readFile("/proc/sys/kernel/perf_event_paranoid").trim();
        if (!paranoidRaw.isEmpty()) {
            try {
                int val = Integer.parseInt(paranoidRaw);
                if (val >= 2) {
                    CollectorUtils.add(items, "perf_event 偏执级别", val + "（≥2，安全）");
                } else if (val >= 0) {
                    CollectorUtils.add(items, "perf_event 偏执级别",
                        CollectorUtils.HIGH_RISK_PREFIX + val + "（< 2，侧信道泄露风险）");
                } else {
                    CollectorUtils.add(items, "perf_event 偏执级别",
                        "无法确认（读取值: " + val + "，属内核特殊配置，系统限制）");
                }
            } catch (NumberFormatException e) {
                CollectorUtils.add(items, "perf_event 偏执级别", "无法读取/系统限制（内容: " + paranoidRaw + "）");
            }
        } else {
            CollectorUtils.add(items, "perf_event 偏执级别", "无法读取/系统限制");
        }

        try {
            Class<?> seLinux = Class.forName("android.os.SELinux");
            Method isSELinuxEnabled = seLinux.getMethod("isSELinuxEnabled");
            Method isSELinuxEnforced = seLinux.getMethod("isSELinuxEnforced");
            boolean enabled  = (Boolean) isSELinuxEnabled.invoke(null);
            boolean enforced = (Boolean) isSELinuxEnforced.invoke(null);
            CollectorUtils.add(items, "SELinux 已启用（反射辅助）", String.valueOf(enabled));

            if (fileEnforcing != null) {
                if (fileEnforcing == enforced) {
                    CollectorUtils.add(items, "SELinux 已强制（反射辅助）",
                        enforced ? "是（与 /sys 来源一致 ✓）" : "否（与 /sys 来源一致）");
                } else {
                    CollectorUtils.add(items, "SELinux 已强制（反射辅助，结果存疑）",
                        "反射返回: " + enforced + "，与 /sys 文件来源不一致，"
                        + "请以 adb shell getenforce 复核");
                }
            } else {
                CollectorUtils.add(items, "SELinux 已强制（反射，仅供参考）",
                    enforced ? "是（仅反射来源，建议 adb shell getenforce 复核）"
                             : "否（仅反射来源，不能确认为 Permissive，请 adb shell getenforce 复核）");
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "SELinux 反射读取", "不支持: " + e.getMessage());
        }

        String aslr = readFile("/proc/sys/kernel/randomize_va_space").trim();
        if (!aslr.isEmpty()) {
            try {
                int val = Integer.parseInt(aslr);
                CollectorUtils.add(items, "ASLR 级别",
                    val + (val == 2 ? "（完全随机化 ✓）"
                         : val == 1 ? "（部分随机化）"
                         : CollectorUtils.HIGH_RISK_PREFIX + "（已禁用，ROP/ret2libc 攻击更易实施）"));
            } catch (NumberFormatException e) {
                CollectorUtils.add(items, "ASLR 级别", "无法读取/系统限制");
            }
        }
    }

    private void checkSensitiveFiles(List<InfoRow> items) {
        String[][] sensitiveFiles = {
            {"/data/system/gesture.key",        "手势锁图案"},
            {"/data/system/password.key",       "PIN/密码哈希"},
            {"/data/system/access_control.key", "访问控制密钥"},
            {"/data/system/locksettings.db",    "锁屏设置数据库"},
            {"/data/system/users/0/settings_global.xml", "全局设置"},
            {"/proc/net/tcp",                   "TCP 连接状态（无需权限）"},
            {"/proc/net/udp",                   "UDP 连接状态（无需权限）"},
            {"/proc/net/arp",                   "ARP 缓存（局域网设备）"},
            {"/sys/class/power_supply/battery/capacity", "电池电量"},
            {"/sys/class/power_supply/battery/temp",     "电池温度"},
        };

        for (String[] f : sensitiveFiles) {
            File file = new File(f[0]);
            boolean exists   = file.exists();
            boolean readable = file.canRead();
            String status;
            if (!exists) {
                status = "不存在";
            } else if (readable) {
                String preview = readFilePreview(f[0], 80);
                status = CollectorUtils.HIGH_RISK_PREFIX + "可读！内容: " + (preview.isEmpty() ? "(空)" : preview);
            } else {
                if (f[0].startsWith("/proc/net/")) {
                    status = "存在但当前 App 无权限读取（Android 高版本系统限制，非 root 问题）";
                } else {
                    status = "存在但无读权限（需 root）";
                }
            }
            CollectorUtils.add(items, f[1] + "\n" + f[0], status);
        }

        CollectorUtils.add(items, "/proc/net 访问说明",
            "/proc/net/tcp、udp、arp 在高版本 Android 中受限，\n"
            + "普通 App 可通过 ConnectivityManager / NetworkInterface 获取部分网络状态，\n"
            + "但不能完整读取内核连接表（系统设计限制，并非需要 root）");

        String cpuModel = readFirstMatchingLine("/proc/cpuinfo", "Hardware");
        CollectorUtils.add(items, "/proc/cpuinfo 硬件型号", cpuModel.isEmpty() ? "无" : cpuModel);
    }

    private void scanExportedComponents(PackageManager pm, List<InfoRow> items) {
        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(
                PackageManager.GET_ACTIVITIES |
                PackageManager.GET_SERVICES |
                PackageManager.GET_RECEIVERS |
                PackageManager.GET_PROVIDERS);
        } catch (Exception e) {
            CollectorUtils.add(items, "扫描失败", e.getMessage());
            return;
        }

        int exportedActivity = 0, exportedService = 0,
            exportedReceiver = 0, exportedProvider = 0;
        List<String> highRisk = new ArrayList<>();
        List<String> deepLinkRisk = new ArrayList<>();

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;

            if (pkg.activities != null) {
                for (ActivityInfo a : pkg.activities) {
                    if (a.exported) {
                        exportedActivity++;
                        boolean noPermission = (a.permission == null);
                        if (noPermission) {
                            highRisk.add("Activity: " + a.name);
                            deepLinkRisk.add(pkg.packageName + "/" + a.name);
                        }
                    }
                }
            }
            if (pkg.services != null) {
                for (ServiceInfo s : pkg.services) {
                    if (s.exported) {
                        exportedService++;
                        if (s.permission == null) highRisk.add("Service: " + s.name);
                    }
                }
            }
            if (pkg.receivers != null) {
                for (ActivityInfo r : pkg.receivers) {
                    if (r.exported) {
                        exportedReceiver++;
                        if (r.permission == null) highRisk.add("Receiver: " + r.name);
                    }
                }
            }
            if (pkg.providers != null) {
                for (ProviderInfo p : pkg.providers) {
                    if (p.exported) exportedProvider++;
                }
            }
        }

        CollectorUtils.add(items, "用户App导出Activity数",  String.valueOf(exportedActivity));
        CollectorUtils.add(items, "用户App导出Service数",   String.valueOf(exportedService));
        CollectorUtils.add(items, "用户App导出Receiver数",  String.valueOf(exportedReceiver));
        CollectorUtils.add(items, "用户App导出Provider数",  String.valueOf(exportedProvider));
        CollectorUtils.add(items, "无权限保护的导出组件",
            highRisk.isEmpty() ? "无" : CollectorUtils.HIGH_RISK_PREFIX + highRisk.size() + " 个");

        int shown = 0;
        for (String comp : highRisk) {
            if (shown++ >= MAX_EXPORTED_COMPONENT_SAMPLE) break;
            CollectorUtils.add(items, "高风险组件", CollectorUtils.HIGH_RISK_PREFIX + comp);
        }

        if (!deepLinkRisk.isEmpty()) {
            CollectorUtils.add(items, "潜在 Deep Link 入口",
                CollectorUtils.HIGH_RISK_PREFIX + deepLinkRisk.size()
                + " 个无权限保护的导出 Activity（可被外部 App/网页唤起）");
            CollectorUtils.add(items, "Deep Link 攻击说明",
                "Intent Scheme URL 攻击：攻击者构造 intent://... URL，\n"
                + "通过网页或其他 App 唤起目标 Activity 并传递恶意参数。\n"
                + "点击应用标签 → 「安全分析」→ 查看具体应用详情。");
        }
    }

    private void scanDangerousProviders(PackageManager pm, List<InfoRow> items) {
        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PROVIDERS);
        } catch (Exception e) {
            CollectorUtils.add(items, "扫描失败", e.getMessage());
            return;
        }

        List<String> riskyProviders = new ArrayList<>();
        int total = 0;

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (pkg.providers == null) continue;

            for (ProviderInfo p : pkg.providers) {
                if (!p.exported) continue;
                total++;
                boolean noReadPerm  = (p.readPermission == null);
                boolean noWritePerm = (p.writePermission == null);
                boolean noAuth      = (p.authority != null);
                if (!isSys && noReadPerm && noWritePerm) {
                    riskyProviders.add(p.authority + "\n  → " + pkg.packageName);
                }
            }
        }

        CollectorUtils.add(items, "导出 ContentProvider 总数", String.valueOf(total));
        CollectorUtils.add(items, "无权限保护的用户 ContentProvider",
            riskyProviders.isEmpty() ? "无" : CollectorUtils.HIGH_RISK_PREFIX + riskyProviders.size() + " 个");
        CollectorUtils.add(items, "路径遍历攻击说明",
            "通过 content://authority/../../../data/data/target/file 可能读取其他 App 文件");

        int shown = 0;
        for (String p : riskyProviders) {
            if (shown++ >= MAX_PROVIDER_SAMPLE) break;
            CollectorUtils.add(items, "高风险 Provider", CollectorUtils.HIGH_RISK_PREFIX + p);
        }
    }

    private void analyzeSignatureSchemes(PackageManager pm, List<InfoRow> items) {
        CollectorUtils.add(items, "Janus 漏洞说明",
            "CVE-2017-13156：仅用 V1 签名的 APK 在 Android 5.1-8.0 上\n" +
            "可在文件头附加 DEX 字节码而不破坏签名，实现无感更新劫持");
        CollectorUtils.add(items, "审计提示",
            "以下结果用于风险提示与初筛，不是完整 APK 签名法证审计结论");
        CollectorUtils.add(items, "当前系统 API", String.valueOf(Build.VERSION.SDK_INT));
        CollectorUtils.add(items, "Janus 影响范围", Build.VERSION.SDK_INT <= 26
            ? CollectorUtils.HIGH_RISK_PREFIX + "当前系统在受影响范围内（API ≤ 26）"
            : "当前系统不在典型受影响范围（API > 26）");

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(0);
        } catch (Exception e) {
            CollectorUtils.add(items, "签名扫描失败", e.getMessage());
            return;
        }

        int total = 0;
        List<SignatureDetectionResult> modernSigned = new ArrayList<>();
        List<SignatureDetectionResult> possibleV1Only = new ArrayList<>();
        List<SignatureDetectionResult> undetermined = new ArrayList<>();

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;
            total++;

            SignatureDetectionResult result = detectSignatureScheme(pkg);
            if (result.undetermined) {
                undetermined.add(result);
            } else if (result.hasV2Block || result.hasV3Block) {
                modernSigned.add(result);
            } else if (result.hasV1Signature) {
                possibleV1Only.add(result);
            } else {
                undetermined.add(result);
            }
        }

        CollectorUtils.add(items, "扫描用户应用总数", String.valueOf(total));
        CollectorUtils.add(items, "检测到 V2/V3 签名",
            modernSigned.isEmpty() ? "0" : modernSigned.size() + " 个");
        CollectorUtils.add(items, "可能 V1-only（中/低置信度）",
            possibleV1Only.isEmpty() ? "0"
                : CollectorUtils.HIGH_RISK_PREFIX + possibleV1Only.size() + " 个（需进一步离线审计确认）");
        CollectorUtils.add(items, "无法判断（解析失败或读取受限）",
            undetermined.isEmpty() ? "0" : undetermined.size() + " 个");

        addSignatureSamples(items, "V2/V3 样本", modernSigned, MAX_SIGNATURE_SAMPLE, false);
        addSignatureSamples(items, "可能 V1-only 样本", possibleV1Only, MAX_SIGNATURE_SAMPLE, true);
        addSignatureSamples(items, "无法判断样本", undetermined, MAX_SIGNATURE_SAMPLE, false);
    }

    private void scanOverPrivilegedApps(PackageManager pm, List<InfoRow> items) {
        CollectorUtils.add(items, "背景",
            "研究表明 56% 的应用存在过度权限声明；\n" +
            "60% 的应用拥有 INTERNET 权限（数据外传通道）");

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        } catch (Exception e) {
            CollectorUtils.add(items, "扫描失败", e.getMessage());
            return;
        }

        List<Map.Entry<String, Integer>> permCounts = new ArrayList<>();
        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys || pkg.requestedPermissions == null) continue;
            int dangerous = 0;
            for (String perm : pkg.requestedPermissions) {
                if (isDangerousPerm(perm)) dangerous++;
            }
            if (dangerous > 0) {
                permCounts.add(new AbstractMap.SimpleEntry<>(pkg.packageName, dangerous));
            }
        }
        permCounts.sort((a, b) -> b.getValue() - a.getValue());

        CollectorUtils.add(items, "声明危险权限的用户应用数", String.valueOf(permCounts.size()));
        int top = Math.min(permCounts.size(), MAX_OVER_PRIVILEGED_TOP);
        for (int i = 0; i < top; i++) {
            Map.Entry<String, Integer> e = permCounts.get(i);
            CollectorUtils.add(items, "#" + (i + 1) + " " + e.getKey(),
                CollectorUtils.HIGH_RISK_PREFIX + "声明了 " + e.getValue() + " 项危险权限");
        }
    }

    private void scanCleartextApps(PackageManager pm, List<InfoRow> items) {
        CollectorUtils.add(items, "背景",
            "AFNetworking 漏洞案例：1500+ 应用因错误配置 SSL 验证，\n" +
            "在同一 WiFi 下可被 MITM 攻击并截获所有 HTTPS 流量");

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(0);
        } catch (Exception e) {
            CollectorUtils.add(items, "扫描失败", e.getMessage());
            return;
        }

        List<String> cleartextApps = new ArrayList<>();
        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;
            if ((pkg.applicationInfo.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0) {
                cleartextApps.add(pkg.packageName);
            }
        }

        CollectorUtils.add(items, "判断依据", "AndroidManifest 中 usesCleartextTraffic=true（FLAG_USES_CLEARTEXT_TRAFFIC）");
        CollectorUtils.add(items, "重要说明",
            "此结果为静态配置风险初筛，不代表当前正在传输明文敏感数据；\n"
            + "可作为 MITM 攻击面评估依据，需进一步动态验证");
        CollectorUtils.add(items, "允许明文 HTTP 的用户应用",
            cleartextApps.isEmpty() ? "无（全部强制 HTTPS）"
                : cleartextApps.size() + " 个（静态配置允许明文 HTTP，MITM 攻击面初筛）");
        int shown = 0;
        for (String app : cleartextApps) {
            if (shown++ >= MAX_CLEARTEXT_APP_SAMPLE) break;
            CollectorUtils.add(items, "允许明文 HTTP（FLAG_USES_CLEARTEXT_TRAFFIC）",
                CollectorUtils.HIGH_RISK_PREFIX + app);
        }
    }

    private static final String TAG_PROCESS = "SecurityCollector";

    private void checkRunningProcesses(Context context, List<InfoRow> items) {
        CollectorUtils.add(items, "挖矿木马特征",
            "CpuMiner 服务以 AndroidManifest 中注册的后台服务形式运行，\n" +
            "持续占用 CPU。可通过进程列表和 CPU 使用率检测。");

        Set<String> seen = new LinkedHashSet<>();
        Set<String> suspicious = new LinkedHashSet<>();

        int amProcCount  = collectFromActivityManagerProcesses(context, items, seen, suspicious);
        int amSvcCount   = collectFromActivityManagerServices(context, items, seen, suspicious);
        int usageCount   = collectFromUsageStats(context, items, seen, suspicious);
        int procCount    = collectFromProc(items, seen, suspicious);

        Log.i(TAG_PROCESS, "[PROC] AM.processes=" + amProcCount
            + " AM.services=" + amSvcCount
            + " UsageStats=" + usageCount
            + " /proc=" + procCount
            + " union=" + seen.size()
            + " suspicious=" + suspicious.size());

        CollectorUtils.add(items, "进程检测合计（去重后）",
            String.format(Locale.US,
                "ActivityManager 进程=%d · 服务=%d · UsageStats 应用=%d · /proc=%d · 合计去重=%d",
                amProcCount, amSvcCount, usageCount, procCount, seen.size()));

        if (!suspicious.isEmpty()) {
            for (String s : suspicious) {
                CollectorUtils.add(items, "⚠ 可疑进程", CollectorUtils.HIGH_RISK_PREFIX + s);
            }
        } else {
            CollectorUtils.add(items, "可疑进程检测", "在当前可见范围内未发现已知挖矿/Root工具进程");
        }
    }

    private int collectFromActivityManagerProcesses(Context context, List<InfoRow> items,
                                                    Set<String> seen, Set<String> suspicious) {
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (am == null) {
            CollectorUtils.add(items, "[来源 A] ActivityManager", "不可用");
            return 0;
        }
        List<ActivityManager.RunningAppProcessInfo> procs = null;
        try {
            procs = am.getRunningAppProcesses();
        } catch (Exception e) {
            CollectorUtils.add(items, "[来源 A] getRunningAppProcesses 异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        int count = (procs == null) ? 0 : procs.size();
        CollectorUtils.add(items, "[来源 A] ActivityManager.getRunningAppProcesses",
            count + " 个" + (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? "（API 26+ 系统限制：仅返回当前 App 自身的进程）"
                : "（旧系统可见全局进程）"));
        if (procs != null) {
            int shown = 0;
            for (ActivityManager.RunningAppProcessInfo p : procs) {
                String key = "AM:" + p.processName;
                if (seen.add(key) && shown < MAX_PROCESS_SAMPLE) {
                    CollectorUtils.add(items, "AM.proc " + p.pid,
                        p.processName + " · importance=" + describeImportance(p.importance));
                    shown++;
                }
                checkSuspicious(p.processName, "AM.proc " + p.pid, suspicious);
            }
        }
        return count;
    }

    private int collectFromActivityManagerServices(Context context, List<InfoRow> items,
                                                   Set<String> seen, Set<String> suspicious) {
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (am == null) return 0;
        List<ActivityManager.RunningServiceInfo> svcs = null;
        try {
            svcs = am.getRunningServices(50);
        } catch (Exception e) {
            CollectorUtils.add(items, "[来源 B] getRunningServices 异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        int count = (svcs == null) ? 0 : svcs.size();
        CollectorUtils.add(items, "[来源 B] ActivityManager.getRunningServices",
            count + " 个" + (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? "（API 26+ 系统限制：仅返回当前 App 自身的服务）"
                : ""));
        if (svcs != null) {
            int shown = 0;
            for (ActivityManager.RunningServiceInfo s : svcs) {
                String pkgName = s.service != null ? s.service.getPackageName() : "(unknown)";
                String svcName = s.service != null ? s.service.getShortClassName() : "(unknown)";
                String key = "AM.svc:" + pkgName + "/" + svcName;
                if (seen.add(key) && shown < MAX_PROCESS_SAMPLE) {
                    CollectorUtils.add(items, "AM.svc " + s.pid,
                        pkgName + "/" + svcName + (s.foreground ? " (foreground)" : ""));
                    shown++;
                }
                checkSuspicious(pkgName + " " + svcName, "AM.svc " + s.pid, suspicious);
            }
        }
        return count;
    }

    private int collectFromUsageStats(Context context, List<InfoRow> items,
                                      Set<String> seen, Set<String> suspicious) {
        boolean granted = isUsageStatsGranted(context);
        if (!granted) {
            CollectorUtils.add(items, "[来源 C] UsageStatsManager",
                CollectorUtils.HIGH_RISK_PREFIX
                    + "未授予「使用情况访问权限」，全局应用活动不可见。\n"
                    + "在 Android 8+ 上这是合法获取全局进程信息的唯一通道，\n"
                    + "授予路径：设置 → 应用 → 特殊应用访问 → 使用情况访问 → 授予本应用");
            return 0;
        }
        UsageStatsManager usm = (UsageStatsManager) context.getSystemService(Context.USAGE_STATS_SERVICE);
        if (usm == null) {
            CollectorUtils.add(items, "[来源 C] UsageStatsManager", "服务不可用");
            return 0;
        }
        long now = System.currentTimeMillis();
        long start = now - 60L * 60L * 1000L;
        List<UsageStats> stats = null;
        try {
            stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_BEST, start, now);
        } catch (Exception e) {
            CollectorUtils.add(items, "[来源 C] queryUsageStats 异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        if (stats == null || stats.isEmpty()) {
            CollectorUtils.add(items, "[来源 C] UsageStatsManager", "已授权，但近 1 小时无活动数据");
            return 0;
        }
        List<UsageStats> active = new ArrayList<>();
        for (UsageStats us : stats) {
            if (us.getTotalTimeInForeground() > 0 || us.getLastTimeUsed() >= start) {
                active.add(us);
            }
        }
        active.sort(new Comparator<UsageStats>() {
            @Override public int compare(UsageStats a, UsageStats b) {
                return Long.compare(b.getLastTimeUsed(), a.getLastTimeUsed());
            }
        });
        CollectorUtils.add(items, "[来源 C] UsageStatsManager",
            "已授权 · 近 1 小时活跃应用 " + active.size() + " 个（按最近使用时间倒序）");
        int shown = 0;
        for (UsageStats us : active) {
            String pkg = us.getPackageName();
            String key = "Usage:" + pkg;
            if (seen.add(key) && shown < MAX_PROCESS_SAMPLE) {
                long fgSec = us.getTotalTimeInForeground() / 1000L;
                CollectorUtils.add(items, "Usage " + pkg,
                    "近 1 小时前台 " + fgSec + "s · 最近使用 "
                        + ((now - us.getLastTimeUsed()) / 1000L) + "s 前");
                shown++;
            }
            checkSuspicious(pkg, "Usage " + pkg, suspicious);
        }
        return active.size();
    }

    private int collectFromProc(List<InfoRow> items, Set<String> seen, Set<String> suspicious) {
        File proc = new File("/proc");
        File[] pids = proc.listFiles(f -> f.isDirectory() && f.getName().matches("\\d+"));
        if (pids == null) {
            CollectorUtils.add(items, "[来源 D] /proc 访问", "不可访问");
            return 0;
        }
        int myUid = Process.myUid();
        int sameUidCount = 0;
        int otherUidCount = 0;
        int shown = 0;
        for (File pidDir : pids) {
            String cmdline = readFile(pidDir.getAbsolutePath() + "/cmdline").replace('\0', ' ').trim();
            if (cmdline.isEmpty()) continue;
            String statusFirstUid = readFirstMatchingLine(pidDir.getAbsolutePath() + "/status", "Uid:");
            int procUid = parseFirstIntFromStatus(statusFirstUid);
            if (procUid == myUid) sameUidCount++; else otherUidCount++;

            String key = "/proc:" + pidDir.getName();
            if (seen.add(key) && shown < MAX_PROCESS_SAMPLE) {
                CollectorUtils.add(items, "PID " + pidDir.getName(),
                    cmdline + (procUid == myUid ? " (本应用进程)" : " (uid=" + procUid + ")"));
                shown++;
            }
            checkSuspicious(cmdline, "PID " + pidDir.getName(), suspicious);
        }
        CollectorUtils.add(items, "[来源 D] /proc 枚举",
            "可见 " + pids.length + " 个 PID（本应用 UID=" + sameUidCount
                + " · 其它 UID=" + otherUidCount + "）");
        if (otherUidCount == 0 && pids.length > 0) {
            CollectorUtils.add(items, "/proc 受限说明",
                "Android 7+ 启用 hidepid=2，第三方 App 几乎只能看到自身进程；\n"
                    + "这是系统级限制，不代表设备没有其他进程在运行。");
        }
        return pids.length;
    }

    private void checkSuspicious(String text, String labelPrefix, Set<String> suspicious) {
        if (text == null || text.isEmpty()) return;
        String[] suspiciousKeywords = {
            "miner", "monero", "bitcoin", "xmrig", "coinhive",
            "cpuminer", "minerd", "cryptonight", "kingoroot",
            "kingroot", "supersu", "magisk", "frida", "xposed"
        };
        String lower = text.toLowerCase(Locale.ROOT);
        for (String kw : suspiciousKeywords) {
            if (lower.contains(kw)) {
                suspicious.add(labelPrefix + ": " + text);
                return;
            }
        }
    }

    private int parseFirstIntFromStatus(String line) {
        if (line == null) return -1;
        String trimmed = line.trim();
        String[] tokens = trimmed.split("\\s+");
        for (int i = 1; i < tokens.length; i++) {
            try { return Integer.parseInt(tokens[i]); } catch (NumberFormatException ignored) {}
        }
        return -1;
    }

    private boolean isUsageStatsGranted(Context context) {
        try {
            AppOpsManager appOps = (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
            if (appOps == null) return false;
            int mode;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                mode = appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(), context.getPackageName());
            } else {
                mode = appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(), context.getPackageName());
            }
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            Log.w(TAG_PROCESS, "isUsageStatsGranted check failed", e);
            return false;
        }
    }

    private String describeImportance(int importance) {
        switch (importance) {
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND:        return "FOREGROUND";
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE:return "FOREGROUND_SERVICE";
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE:           return "VISIBLE";
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_PERCEPTIBLE:       return "PERCEPTIBLE";
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE:           return "SERVICE";
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED:            return "CACHED";
            case ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE:              return "GONE";
            default:                                                                 return "OTHER(" + importance + ")";
        }
    }


    private SignatureDetectionResult detectSignatureScheme(PackageInfo pkg) {
        String packageName = pkg.packageName != null ? pkg.packageName : "(unknown)";
        ApplicationInfo appInfo = pkg.applicationInfo;
        if (appInfo == null || appInfo.sourceDir == null || appInfo.sourceDir.isEmpty()) {
            return new SignatureDetectionResult(
                packageName, false, false, false, null,
                DetectionConfidence.LOW, "无法获取 APK 路径", true);
        }

        File apkFile = new File(appInfo.sourceDir);
        if (!apkFile.exists() || !apkFile.canRead()) {
            return new SignatureDetectionResult(
                packageName, false, false, false, null,
                DetectionConfidence.LOW, "APK 文件不存在或不可读", true);
        }

        boolean hasV1 = detectV1Signature(apkFile);
        SigningBlockParseResult blockResult = parseSigningBlock(apkFile);

        if (!blockResult.parsed) {
            String note = "Signing Block 解析失败: " + blockResult.note
                + (hasV1 ? "；检测到 META-INF 签名迹象" : "");
            return new SignatureDetectionResult(
                packageName, hasV1, false, false, null,
                DetectionConfidence.LOW, note, true);
        }

        if (blockResult.hasV2Block || blockResult.hasV3Block) {
            String note = (blockResult.hasV2Block ? "检测到 V2 " : "")
                + (blockResult.hasV3Block ? "检测到 V3 " : "")
                + "Signing Block";
            return new SignatureDetectionResult(
                packageName, hasV1, blockResult.hasV2Block, blockResult.hasV3Block, null,
                DetectionConfidence.HIGH, note.trim(), false);
        }

        if (hasV1) {
            String note = blockResult.hasSigningBlock
                ? "有 META-INF 签名文件，但未检测到 V2/V3 Block"
                : "检测到 META-INF 签名文件，且未发现 APK Signing Block";
            DetectionConfidence confidence = blockResult.hasSigningBlock
                ? DetectionConfidence.MEDIUM : DetectionConfidence.HIGH;
            return new SignatureDetectionResult(
                packageName, true, false, false, null,
                confidence, note, false);
        }

        return new SignatureDetectionResult(
            packageName, false, false, false, null,
            DetectionConfidence.LOW, "未检测到 V1 迹象，且无 V2/V3 Block 证据", true);
    }

    private boolean detectV1Signature(File apkFile) {
        try (ZipFile zipFile = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name == null) continue;
                String upper = name.toUpperCase(Locale.ROOT);
                if (upper.startsWith("META-INF/")
                        && (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC"))) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            return false;
        }
        return false;
    }

    private SigningBlockParseResult parseSigningBlock(File apkFile) {
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            long fileSize = raf.length();
            if (fileSize < ZIP_EOCD_MIN_SIZE) {
                return new SigningBlockParseResult(false, false, false, false, "文件太小，不是有效 APK");
            }

            long eocdOffset = findEocdOffset(raf, fileSize);
            if (eocdOffset < 0) {
                return new SigningBlockParseResult(false, false, false, false, "未找到 ZIP EOCD");
            }

            long centralDirOffset = readUInt32LE(raf, eocdOffset + 16);
            if (centralDirOffset <= 0 || centralDirOffset > fileSize) {
                return new SigningBlockParseResult(false, false, false, false, "Central Directory 偏移异常");
            }

            if (centralDirOffset < 24) {
                return new SigningBlockParseResult(true, false, false, false, "未发现 APK Signing Block");
            }

            long footerOffset = centralDirOffset - 24;
            byte[] footer = new byte[24];
            raf.seek(footerOffset);
            raf.readFully(footer);

            long magicLow = getUInt64LE(footer, 8);
            long magicHigh = getUInt64LE(footer, 16);
            if (magicLow != APK_SIG_BLOCK_MAGIC_LOW || magicHigh != APK_SIG_BLOCK_MAGIC_HIGH) {
                return new SigningBlockParseResult(true, false, false, false, "未发现 APK Signing Block");
            }

            long blockSize = getUInt64LE(footer, 0);
            long totalBlockSize = blockSize + 8;
            if (blockSize < 24 || totalBlockSize <= 0) {
                return new SigningBlockParseResult(false, false, false, false, "Signing Block 长度非法");
            }
            if (totalBlockSize > MAX_SIGNING_BLOCK_BYTES) {
                return new SigningBlockParseResult(false, false, false, false, "Signing Block 过大，跳过解析");
            }

            long blockStart = centralDirOffset - totalBlockSize;
            if (blockStart < 0) {
                return new SigningBlockParseResult(false, false, false, false, "Signing Block 起始偏移非法");
            }

            byte[] block = new byte[(int) totalBlockSize];
            raf.seek(blockStart);
            raf.readFully(block);

            long firstSize = getUInt64LE(block, 0);
            if (firstSize != blockSize) {
                return new SigningBlockParseResult(false, false, false, false, "Signing Block 前后长度不一致");
            }

            boolean hasV2 = false;
            boolean hasV3 = false;
            int cursor = 8;
            int entriesEnd = block.length - 24;
            while (cursor < entriesEnd) {
                long entryLen = getUInt64LE(block, cursor);
                cursor += 8;
                if (entryLen < 4 || entryLen > Integer.MAX_VALUE) {
                    return new SigningBlockParseResult(false, true, false, false, "Signing Block entry 长度异常");
                }
                if (cursor + entryLen > entriesEnd) {
                    return new SigningBlockParseResult(false, true, false, false, "Signing Block entry 越界");
                }

                int id = (int) getUInt32LE(block, cursor);
                if (id == APK_SIG_SCHEME_V2_BLOCK_ID) {
                    hasV2 = true;
                } else if (id == APK_SIG_SCHEME_V3_BLOCK_ID || id == APK_SIG_SCHEME_V31_BLOCK_ID) {
                    hasV3 = true;
                }
                cursor += (int) entryLen;
            }
            return new SigningBlockParseResult(true, true, hasV2, hasV3, "Signing Block 解析完成");
        } catch (Exception e) {
            return new SigningBlockParseResult(false, false, false, false, e.getClass().getSimpleName());
        }
    }

    private long findEocdOffset(RandomAccessFile raf, long fileSize) throws IOException {
        int scanSize = (int) Math.min(fileSize, ZIP_EOCD_MAX_SEARCH);
        byte[] tail = new byte[scanSize];
        long tailStart = fileSize - scanSize;
        raf.seek(tailStart);
        raf.readFully(tail);

        for (int i = tail.length - ZIP_EOCD_MIN_SIZE; i >= 0; i--) {
            if ((int) getUInt32LE(tail, i) == ZIP_EOCD_MAGIC) {
                return tailStart + i;
            }
        }
        return -1;
    }

    private long readUInt32LE(RandomAccessFile raf, long offset) throws IOException {
        byte[] buf = new byte[4];
        raf.seek(offset);
        raf.readFully(buf);
        return getUInt32LE(buf, 0);
    }

    private long getUInt32LE(byte[] src, int offset) {
        return ((long) src[offset] & 0xFF)
            | (((long) src[offset + 1] & 0xFF) << 8)
            | (((long) src[offset + 2] & 0xFF) << 16)
            | (((long) src[offset + 3] & 0xFF) << 24);
    }

    private long getUInt64LE(byte[] src, int offset) {
        return ((long) src[offset] & 0xFF)
            | (((long) src[offset + 1] & 0xFF) << 8)
            | (((long) src[offset + 2] & 0xFF) << 16)
            | (((long) src[offset + 3] & 0xFF) << 24)
            | (((long) src[offset + 4] & 0xFF) << 32)
            | (((long) src[offset + 5] & 0xFF) << 40)
            | (((long) src[offset + 6] & 0xFF) << 48)
            | (((long) src[offset + 7] & 0xFF) << 56);
    }

    private void addSignatureSamples(
            List<InfoRow> items,
            String label,
            List<SignatureDetectionResult> bucket,
            int maxSamples,
            boolean possiblyV1Only
    ) {
        int shown = 0;
        for (SignatureDetectionResult result : bucket) {
            if (shown++ >= maxSamples) break;
            StringBuilder value = new StringBuilder();
            value.append("V1:").append(result.hasV1Signature ? "✓" : "✗");
            value.append("  V2:").append(result.hasV2Block ? "✓" : "✗");
            value.append("  V3:").append(result.hasV3Block ? "✓" : "✗");
            value.append(" | 置信度:").append(result.detectionConfidence);
            value.append(" | ").append(result.detectionNote);

            boolean isJanusHighRisk = possiblyV1Only
                && !result.hasV2Block && !result.hasV3Block
                && Build.VERSION.SDK_INT <= 26;
            String janusNote = "";
            if (possiblyV1Only) {
                if (isJanusHighRisk) {
                    janusNote = "  ← Janus 高风险（V1-only + 当前系统 API≤26）";
                } else if (result.hasV2Block || result.hasV3Block) {
                    janusNote = "  ← 存在 V2/V3，Janus 典型风险较低";
                } else {
                    janusNote = "  ← 当前系统 API>" + Build.VERSION.SDK_INT + "，Janus 典型风险较低";
                }
            }

            CollectorUtils.add(items, label,
                (isJanusHighRisk ? CollectorUtils.HIGH_RISK_PREFIX : "")
                + result.packageName + "\n" + value + janusNote);
        }
    }

    private boolean isDangerousPerm(String perm) {
        String[] dangerous = {
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE", "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS",
            "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
            "BIND_NOTIFICATION_LISTENER_SERVICE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO"
        };
        for (String d : dangerous) if (perm.contains(d)) return true;
        return false;
    }

    private String readFile(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            return sb.toString().trim();
        } catch (IOException e) {
            return "";
        }
    }

    private String readFilePreview(String path, int maxChars) {
        String content = readFile(path);
        if (content.length() > maxChars) return content.substring(0, maxChars) + "...";
        return content;
    }

    private String readFirstMatchingLine(String path, String key) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(key)) return line;
            }
        } catch (IOException ignored) {}
        return "";
    }

    private int parseIntSafe(String s) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return -1; }
    }

}
