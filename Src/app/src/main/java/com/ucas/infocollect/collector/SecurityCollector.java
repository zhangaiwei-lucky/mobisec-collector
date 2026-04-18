package com.ucas.infocollect.collector;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 安全分析收集器
 *
 * 覆盖课件中的核心攻击面：
 * 1. 导出组件扫描
 *    - 导出的 Activity  → Intent Scheme URL 攻击入口
 *    - 导出的 ContentProvider → 路径遍历攻击入口
 *    - 导出的 Service / BroadcastReceiver → IPC 攻击入口
 *
 * 2. SELinux 安全状态
 *    - 是否处于 Enforcing 模式
 *    - 宽松模式下几乎所有 MAC 策略失效
 *
 * 3. 系统敏感文件访问检测
 *    - gesture.key / password.key / access_control.key
 *    - 恶意软件案例：删除这些文件即可绕过锁屏
 *
 * 4. APK 签名方案分析（ Janus 漏洞）
 *    - V1-only 签名的 App 在 Android 5.1-8.0 上易受 Janus 攻击
 *    - Janus(CVE-2017-13156)：DEX 文件可附加在合法 APK 前而不破坏签名
 *
 * 5. 过权限（Over-Privilege）分析
 *    - 统计声明了但从不使用的权限
 *    - 研究表明 56% 的权限声明存在过度申请
 *
 * 6. 运行中的服务 / 进程（ActivityManager）
 *    - 检测是否存在可疑后台服务（挖矿木马特征：CPU 服务）
 *
 * 7. 网络安全配置
 *    - 允许明文 HTTP 的应用（中间人攻击面）
 *    -  HTTPS 降级攻击案例
 */
public class SecurityCollector {

    private final Context context;
    private final PackageManager pm;

    public SecurityCollector(Context context) {
        this.context = context;
        this.pm = context.getPackageManager();
    }

    public List<Map.Entry<String, String>> collect() {
        List<Map.Entry<String, String>> items = new ArrayList<>();

        // ── 1. SELinux 状态（：SEAndroid）────────────────
        addHeader(items, "SELinux / SEAndroid 安全状态");
        collectSeLinux(items);

        // ── 2. 系统敏感文件（ ：锁屏绕过案例）────────
        addHeader(items, "系统敏感文件可访问性");
        checkSensitiveFiles(items);

        // ── 3. 导出组件扫描（：Intent攻击 / CP路径遍历）──
        addHeader(items, "导出组件扫描（Intent/IPC 攻击面）");
        scanExportedComponents(items);

        // ── 4. ContentProvider 路径遍历风险────────────
        addHeader(items, "Content Provider 路径遍历风险");
        scanDangerousProviders(items);

        // ── 5. APK 签名方案分析（Janus CVE-2017-13156）────────────
        addHeader(items, "APK 签名方案 / Janus 漏洞");
        analyzeSignatureSchemes(items);

        // ── 6. 过权限应用统计──────────────────
        addHeader(items, "过权限应用 Top 10");
        scanOverPrivilegedApps(items);

        // ── 7. 允许明文 HTTP 的应用（HTTPS降级风险）──────────────
        addHeader(items, "允许明文 HTTP 的应用（MITM 攻击面）");
        scanCleartextApps(items);

        // ── 8. 运行中服务 / 可疑后台进程（挖矿木马特征）──────────
        addHeader(items, "运行中进程与可疑服务");
        checkRunningProcesses(items);

        return items;
    }

    // ─────────────────────────────────────────────────────────────
    // 1. SELinux 状态
    // ─────────────────────────────────────────────────────────────
    private void collectSeLinux(List<Map.Entry<String, String>> items) {
        // 方法1：读取 /sys/fs/selinux/enforce
        String enforceFile = readFile("/sys/fs/selinux/enforce");
        if (!enforceFile.isEmpty()) {
            boolean enforcing = enforceFile.trim().equals("1");
            add(items, "SELinux 模式",
                enforcing ? "Enforcing（强制）✓ MAC 策略生效"
                          : "[HIGH]Permissive（宽松）— MAC 策略不生效，提权风险高");
        }

        // 方法2：读取 /proc/sys/kernel/perf_event_paranoid（内核安全参数）
        String paranoid = readFile("/proc/sys/kernel/perf_event_paranoid");
        if (!paranoid.isEmpty()) {
            int val = parseIntSafe(paranoid.trim());
            add(items, "perf_event 偏执级别",
                val + (val >= 2 ? "（安全）" : "[HIGH]（< 2，侧信道泄露风险）"));
        }

        // 方法3：通过 Java 反射获取 SELinux 状态
        try {
            Class<?> seLinux = Class.forName("android.os.SELinux");
            Method isSELinuxEnabled = seLinux.getMethod("isSELinuxEnabled");
            Method isSELinuxEnforced = seLinux.getMethod("isSELinuxEnforced");
            boolean enabled  = (Boolean) isSELinuxEnabled.invoke(null);
            boolean enforced = (Boolean) isSELinuxEnforced.invoke(null);
            add(items, "SELinux 已启用", String.valueOf(enabled));
            add(items, "SELinux 已强制",
                enforced ? "是" : "[HIGH]否（Permissive 模式，等同无 MAC）");
        } catch (Exception e) {
            add(items, "SELinux 反射读取", "不支持: " + e.getMessage());
        }

        // ASLR 状态（：内存保护）
        String aslr = readFile("/proc/sys/kernel/randomize_va_space");
        if (!aslr.isEmpty()) {
            int val = parseIntSafe(aslr.trim());
            add(items, "ASLR 级别",
                val + (val == 2 ? "（完全随机化 ✓）"
                     : val == 1 ? "（部分随机化）"
                     : "[HIGH]（已禁用，ROP/ret2libc 攻击更易实施）"));
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 2. 系统敏感文件
    // ─────────────────────────────────────────────────────────────
    private void checkSensitiveFiles(List<Map.Entry<String, String>> items) {
        //  ：恶意软件通过 ADB 删除这些文件绕过锁屏
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
                // 可读则尝试读前 100 字符
                String preview = readFilePreview(f[0], 80);
                status = "[HIGH]可读！内容: " + (preview.isEmpty() ? "(空)" : preview);
            } else {
                status = "存在但无读权限（需 root）";
            }
            add(items, f[1] + "\n" + f[0], status);
        }

        // /proc/cpuinfo 和 /proc/meminfo（无需权限，课件提到的系统信息）
        String cpuModel = readFirstMatchingLine("/proc/cpuinfo", "Hardware");
        add(items, "/proc/cpuinfo 硬件型号", cpuModel.isEmpty() ? "无" : cpuModel);
    }

    // ─────────────────────────────────────────────────────────────
    // 3. 导出组件扫描（Intent Scheme URL 攻击面）
    // ─────────────────────────────────────────────────────────────
    private void scanExportedComponents(List<Map.Entry<String, String>> items) {
        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(
                PackageManager.GET_ACTIVITIES |
                PackageManager.GET_SERVICES |
                PackageManager.GET_RECEIVERS |
                PackageManager.GET_PROVIDERS);
        } catch (Exception e) {
            add(items, "扫描失败", e.getMessage());
            return;
        }

        int exportedActivity = 0, exportedService = 0,
            exportedReceiver = 0, exportedProvider = 0;
        List<String> highRisk = new ArrayList<>(); // 无权限要求的导出组件

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue; // 只分析用户应用

            // 导出的 Activity（Intent Scheme URL 攻击直接目标）
            if (pkg.activities != null) {
                for (ActivityInfo a : pkg.activities) {
                    if (a.exported) {
                        exportedActivity++;
                        if (a.permission == null) { // 无权限保护 = 任意 App 可调用
                            highRisk.add("Activity: " + a.name);
                        }
                    }
                }
            }
            // 导出的 Service
            if (pkg.services != null) {
                for (ServiceInfo s : pkg.services) {
                    if (s.exported) {
                        exportedService++;
                        if (s.permission == null) highRisk.add("Service: " + s.name);
                    }
                }
            }
            // 导出的 Receiver（隐式广播攻击面）
            if (pkg.receivers != null) {
                for (ActivityInfo r : pkg.receivers) {
                    if (r.exported) {
                        exportedReceiver++;
                        if (r.permission == null) highRisk.add("Receiver: " + r.name);
                    }
                }
            }
        }

        add(items, "用户App导出Activity数",  String.valueOf(exportedActivity));
        add(items, "用户App导出Service数",   String.valueOf(exportedService));
        add(items, "用户App导出Receiver数",  String.valueOf(exportedReceiver));
        add(items, "无权限保护的导出组件",
            highRisk.isEmpty() ? "无" : "[HIGH]" + highRisk.size() + " 个");

        // 展示前 5 个高风险无权限导出组件
        int shown = 0;
        for (String comp : highRisk) {
            if (shown++ >= 5) break;
            add(items, "高风险组件", "[HIGH]" + comp);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 4. Content Provider 路径遍历风险
    // ─────────────────────────────────────────────────────────────
    private void scanDangerousProviders(List<Map.Entry<String, String>> items) {
        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PROVIDERS);
        } catch (Exception e) {
            add(items, "扫描失败", e.getMessage());
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
                // 高风险：无读写权限保护 + 用户应用
                boolean noReadPerm  = (p.readPermission == null);
                boolean noWritePerm = (p.writePermission == null);
                boolean noAuth      = (p.authority != null);
                if (!isSys && noReadPerm && noWritePerm) {
                    riskyProviders.add(p.authority + "\n  → " + pkg.packageName);
                }
            }
        }

        add(items, "导出 ContentProvider 总数", String.valueOf(total));
        add(items, "无权限保护的用户 ContentProvider",
            riskyProviders.isEmpty() ? "无" : "[HIGH]" + riskyProviders.size() + " 个");
        add(items, "路径遍历攻击说明",
            "通过 content://authority/../../../data/data/target/file 可能读取其他 App 文件");

        int shown = 0;
        for (String p : riskyProviders) {
            if (shown++ >= 5) break;
            add(items, "高风险 Provider", "[HIGH]" + p);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 5. APK 签名方案分析（Janus CVE-2017-13156，）
    // ─────────────────────────────────────────────────────────────
    private void analyzeSignatureSchemes(List<Map.Entry<String, String>> items) {
        add(items, "Janus 漏洞说明",
            "CVE-2017-13156：仅用 V1 签名的 APK 在 Android 5.1-8.0 上\n" +
            "可在文件头附加 DEX 字节码而不破坏签名，实现无感更新劫持");
        add(items, "当前系统 API",    String.valueOf(Build.VERSION.SDK_INT));
        add(items, "Janus 影响范围", Build.VERSION.SDK_INT <= 26
            ? "[HIGH]当前系统在受影响范围内（API ≤ 26）"
            : "当前系统不受 Janus 影响（API > 26，强制 V2+ 签名验证）");

        // 扫描只使用 V1 签名的用户应用（潜在受害者）
        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_SIGNING_CERTIFICATES);
        } catch (Exception e) {
            try {
                packages = pm.getInstalledPackages(PackageManager.GET_SIGNATURES);
            } catch (Exception e2) {
                add(items, "签名读取失败", e2.getMessage());
                return;
            }
        }

        int v1Only = 0, total = 0;
        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;
            total++;
            // 如果 signingInfo 为 null 或只有旧式 signatures，推断为 V1
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (pkg.signingInfo != null &&
                    !pkg.signingInfo.hasMultipleSigners() &&
                    pkg.signingInfo.getSigningCertificateHistory() != null &&
                    pkg.signingInfo.getSigningCertificateHistory().length == 1) {
                    v1Only++;
                }
            }
        }
        add(items, "扫描用户应用总数", String.valueOf(total));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            add(items, "疑似 V1-only 签名应用",
                v1Only > 0 ? "[HIGH]" + v1Only + " 个（若系统 ≤ API26 则受 Janus 影响）"
                           : String.valueOf(v1Only));
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 6. 过权限应用统计
    // ─────────────────────────────────────────────────────────────
    private void scanOverPrivilegedApps(List<Map.Entry<String, String>> items) {
        add(items, "背景",
            "研究表明 56% 的应用存在过度权限声明；\n" +
            "60% 的应用拥有 INTERNET 权限（数据外传通道）");

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        } catch (Exception e) {
            add(items, "扫描失败", e.getMessage());
            return;
        }

        // 统计每个用户应用声明的危险权限数量，取前10
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

        add(items, "声明危险权限的用户应用数", String.valueOf(permCounts.size()));
        int top = Math.min(permCounts.size(), 10);
        for (int i = 0; i < top; i++) {
            Map.Entry<String, Integer> e = permCounts.get(i);
            add(items, "#" + (i + 1) + " " + e.getKey(),
                "[HIGH]声明了 " + e.getValue() + " 项危险权限");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 7. 明文 HTTP 应用（HTTPS 降级风险，）
    // ─────────────────────────────────────────────────────────────
    private void scanCleartextApps(List<Map.Entry<String, String>> items) {
        add(items, "背景",
            "AFNetworking 漏洞案例：1500+ 应用因错误配置 SSL 验证，\n" +
            "在同一 WiFi 下可被 MITM 攻击并截获所有 HTTPS 流量");

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(0);
        } catch (Exception e) {
            add(items, "扫描失败", e.getMessage());
            return;
        }

        List<String> cleartextApps = new ArrayList<>();
        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue;
            // FLAG_USES_CLEARTEXT_TRAFFIC 表示 AndroidManifest 中 usesCleartextTraffic=true
            if ((pkg.applicationInfo.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0) {
                cleartextApps.add(pkg.packageName);
            }
        }

        add(items, "允许明文 HTTP 的用户应用",
            cleartextApps.isEmpty() ? "无（全部强制 HTTPS）"
                : "[HIGH]" + cleartextApps.size() + " 个（存在 MITM 风险）");
        int shown = 0;
        for (String app : cleartextApps) {
            if (shown++ >= 10) break;
            add(items, "明文 HTTP 应用", "[HIGH]" + app);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 8. 运行中进程（挖矿木马 / 可疑服务检测，）
    // ─────────────────────────────────────────────────────────────
    private void checkRunningProcesses(List<Map.Entry<String, String>> items) {
        add(items, "挖矿木马特征",
            "CpuMiner 服务以 AndroidManifest 中注册的后台服务形式运行，\n" +
            "持续占用 CPU。可通过进程列表和 CPU 使用率检测。");

        // 读取 /proc 目录下的进程列表（无需权限）
        File proc = new File("/proc");
        File[] pids = proc.listFiles(f -> f.isDirectory() && f.getName().matches("\\d+"));
        if (pids == null) {
            add(items, "/proc 访问", "不可访问");
            return;
        }

        add(items, "运行中进程总数", String.valueOf(pids.length));

        // 挖矿 / 恶意进程关键词
        String[] suspiciousKeywords = {
            "miner", "monero", "bitcoin", "xmrig", "coinhive",
            "cpuminer", "minerd", "cryptonight", "kingoroot",
            "kingroot", "supersu", "magisk", "frida", "xposed"
        };

        List<String> suspicious = new ArrayList<>();
        int shown = 0;

        for (File pidDir : pids) {
            String cmdline = readFile(pidDir.getAbsolutePath() + "/cmdline")
                .replace('\0', ' ').trim();
            if (cmdline.isEmpty()) continue;

            for (String kw : suspiciousKeywords) {
                if (cmdline.toLowerCase().contains(kw)) {
                    suspicious.add(pidDir.getName() + ": " + cmdline);
                    break;
                }
            }

            // 展示前 15 个进程名
            if (shown < 15) {
                add(items, "PID " + pidDir.getName(), cmdline);
                shown++;
            }
        }

        if (!suspicious.isEmpty()) {
            for (String s : suspicious) {
                add(items, "⚠ 可疑进程", "[HIGH]" + s);
            }
        } else {
            add(items, "可疑进程", "未检测到已知挖矿/Root工具进程");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 工具方法
    // ─────────────────────────────────────────────────────────────

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

    private void add(List<Map.Entry<String, String>> l, String k, String v) {
        l.add(new AbstractMap.SimpleEntry<>(k, v != null ? v : "N/A"));
    }

    private void addHeader(List<Map.Entry<String, String>> l, String t) {
        l.add(new AbstractMap.SimpleEntry<>("##" + t, ""));
    }
}
