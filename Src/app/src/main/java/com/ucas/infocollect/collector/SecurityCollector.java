package com.ucas.infocollect.collector;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.os.Build;

import com.ucas.infocollect.model.InfoRow;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

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

        // ── 1. SELinux 状态（：SEAndroid）────────────────
        CollectorUtils.addHeader(items, "SELinux / SEAndroid 安全状态");
        collectSeLinux(items);

        // ── 2. 系统敏感文件（ ：锁屏绕过案例）────────
        CollectorUtils.addHeader(items, "系统敏感文件可访问性");
        checkSensitiveFiles(items);

        // ── 3. 导出组件扫描（：Intent攻击 / CP路径遍历）──
        CollectorUtils.addHeader(items, "导出组件扫描（Intent/IPC 攻击面）");
        scanExportedComponents(pm, items);

        // ── 4. ContentProvider 路径遍历风险────────────
        CollectorUtils.addHeader(items, "Content Provider 路径遍历风险");
        scanDangerousProviders(pm, items);

        // ── 5. APK 签名方案分析（Janus CVE-2017-13156）────────────
        CollectorUtils.addHeader(items, "APK 签名方案 / Janus 漏洞");
        analyzeSignatureSchemes(pm, items);

        // ── 6. 过权限应用统计──────────────────
        CollectorUtils.addHeader(items, "过权限应用 Top 10");
        scanOverPrivilegedApps(pm, items);

        // ── 7. 允许明文 HTTP 的应用（HTTPS降级风险）──────────────
        CollectorUtils.addHeader(items, "允许明文 HTTP 的应用（静态配置风险初筛）");
        scanCleartextApps(pm, items);

        // ── 8. 运行中服务 / 可疑后台进程（挖矿木马特征）──────────
        CollectorUtils.addHeader(items, "运行中进程与可疑服务");
        checkRunningProcesses(items);

        return items;
    }

    // ─────────────────────────────────────────────────────────────
    // 1. SELinux 状态
    // ─────────────────────────────────────────────────────────────
    private void collectSeLinux(List<InfoRow> items) {
        // 方法1：读取 /sys/fs/selinux/enforce（优先来源，1=Enforcing，0=Permissive）
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

        // 方法2：读取 /proc/sys/kernel/perf_event_paranoid（内核安全参数）
        // 注意：-1 在某些内核含义为"无限制"，读取失败时显示系统限制而非标高危
        String paranoidRaw = readFile("/proc/sys/kernel/perf_event_paranoid").trim();
        if (!paranoidRaw.isEmpty()) {
            try {
                int val = Integer.parseInt(paranoidRaw);
                if (val >= 2) {
                    CollectorUtils.add(items, "perf_event 偏执级别", val + "（≥2，安全）");
                } else if (val >= 0) {
                    // 0 或 1：确实存在侧信道泄露风险
                    CollectorUtils.add(items, "perf_event 偏执级别",
                        CollectorUtils.HIGH_RISK_PREFIX + val + "（< 2，侧信道泄露风险）");
                } else {
                    // val < 0（如 -1）：内核特殊配置，不作为确定高危
                    CollectorUtils.add(items, "perf_event 偏执级别",
                        "无法确认（读取值: " + val + "，属内核特殊配置，系统限制）");
                }
            } catch (NumberFormatException e) {
                CollectorUtils.add(items, "perf_event 偏执级别", "无法读取/系统限制（内容: " + paranoidRaw + "）");
            }
        } else {
            CollectorUtils.add(items, "perf_event 偏执级别", "无法读取/系统限制");
        }

        // 方法3：通过 Java 反射获取 SELinux 状态（辅助来源，与文件来源交叉比对）
        try {
            Class<?> seLinux = Class.forName("android.os.SELinux");
            Method isSELinuxEnabled = seLinux.getMethod("isSELinuxEnabled");
            Method isSELinuxEnforced = seLinux.getMethod("isSELinuxEnforced");
            boolean enabled  = (Boolean) isSELinuxEnabled.invoke(null);
            boolean enforced = (Boolean) isSELinuxEnforced.invoke(null);
            CollectorUtils.add(items, "SELinux 已启用（反射辅助）", String.valueOf(enabled));

            if (fileEnforcing != null) {
                // 与文件来源交叉比对
                if (fileEnforcing == enforced) {
                    CollectorUtils.add(items, "SELinux 已强制（反射辅助）",
                        enforced ? "是（与 /sys 来源一致 ✓）" : "否（与 /sys 来源一致）");
                } else {
                    // 两个来源不一致，不得确定结论
                    CollectorUtils.add(items, "SELinux 已强制（反射辅助，结果存疑）",
                        "反射返回: " + enforced + "，与 /sys 文件来源不一致，"
                        + "请以 adb shell getenforce 复核");
                }
            } else {
                // 文件不可读，仅有反射来源，结论需谨慎
                CollectorUtils.add(items, "SELinux 已强制（反射，仅供参考）",
                    enforced ? "是（仅反射来源，建议 adb shell getenforce 复核）"
                             : "否（仅反射来源，不能确认为 Permissive，请 adb shell getenforce 复核）");
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "SELinux 反射读取", "不支持: " + e.getMessage());
        }

        // ASLR 状态（内存保护）
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

    // ─────────────────────────────────────────────────────────────
    // 2. 系统敏感文件
    // ─────────────────────────────────────────────────────────────
    private void checkSensitiveFiles(List<InfoRow> items) {
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
                status = CollectorUtils.HIGH_RISK_PREFIX + "可读！内容: " + (preview.isEmpty() ? "(空)" : preview);
            } else {
                // 区分 /proc/net/ 与 /data/system/ 的限制原因
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

        // /proc/cpuinfo 和 /proc/meminfo（无需权限，课件提到的系统信息）
        String cpuModel = readFirstMatchingLine("/proc/cpuinfo", "Hardware");
        CollectorUtils.add(items, "/proc/cpuinfo 硬件型号", cpuModel.isEmpty() ? "无" : cpuModel);
    }

    // ─────────────────────────────────────────────────────────────
    // 3. 导出组件扫描（Intent Scheme URL 攻击面）
    // ─────────────────────────────────────────────────────────────
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
        List<String> highRisk = new ArrayList<>(); // 无权限要求的导出组件
        // Deep Link: exported Activity + BROWSABLE + 无权限
        List<String> deepLinkRisk = new ArrayList<>();

        for (PackageInfo pkg : packages) {
            boolean isSys = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSys) continue; // 只分析用户应用

            // 导出的 Activity（Intent Scheme URL 攻击直接目标）
            if (pkg.activities != null) {
                for (ActivityInfo a : pkg.activities) {
                    if (a.exported) {
                        exportedActivity++;
                        boolean noPermission = (a.permission == null);
                        if (noPermission) {
                            highRisk.add("Activity: " + a.name);
                            // 检查是否有 BROWSABLE（外部可唤起，Deep Link）
                            // PackageManager 返回的 ActivityInfo 不含 IntentFilter，
                            // 但无权限保护的导出 Activity 本身已是高风险入口
                            deepLinkRisk.add(pkg.packageName + "/" + a.name);
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
            // 导出的 ContentProvider（修复原先未统计的问题）
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

        // 展示前 5 个高风险无权限导出组件
        int shown = 0;
        for (String comp : highRisk) {
            if (shown++ >= MAX_EXPORTED_COMPONENT_SAMPLE) break;
            CollectorUtils.add(items, "高风险组件", CollectorUtils.HIGH_RISK_PREFIX + comp);
        }

        // Deep Link 分析
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

    // ─────────────────────────────────────────────────────────────
    // 4. Content Provider 路径遍历风险
    // ─────────────────────────────────────────────────────────────
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
                // 高风险：无读写权限保护 + 用户应用
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

    // ─────────────────────────────────────────────────────────────
    // 5. APK 签名方案分析（Janus CVE-2017-13156，）
    // ─────────────────────────────────────────────────────────────
    /**
     * 说明：
     * 1) 当前实现通过 APK 文件结构（META-INF 迹象 + APK Signing Block）做风险初筛。
     * 2) 这是“工程化近似检测”，并非完整法证级审计流程。
     * 3) 检测结论仅供安全提示，不应作为漏洞归因的唯一依据。
     */
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

        // 仅扫描用户应用，避免系统应用噪声
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

    // ─────────────────────────────────────────────────────────────
    // 6. 过权限应用统计
    // ─────────────────────────────────────────────────────────────
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

        CollectorUtils.add(items, "声明危险权限的用户应用数", String.valueOf(permCounts.size()));
        int top = Math.min(permCounts.size(), MAX_OVER_PRIVILEGED_TOP);
        for (int i = 0; i < top; i++) {
            Map.Entry<String, Integer> e = permCounts.get(i);
            CollectorUtils.add(items, "#" + (i + 1) + " " + e.getKey(),
                CollectorUtils.HIGH_RISK_PREFIX + "声明了 " + e.getValue() + " 项危险权限");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 7. 明文 HTTP 应用（HTTPS 降级风险，）
    // ─────────────────────────────────────────────────────────────
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
            // FLAG_USES_CLEARTEXT_TRAFFIC 表示 AndroidManifest 中 usesCleartextTraffic=true
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

    // ─────────────────────────────────────────────────────────────
    // 8. 运行中进程（挖矿木马 / 可疑服务检测，）
    // ─────────────────────────────────────────────────────────────
    private void checkRunningProcesses(List<InfoRow> items) {
        CollectorUtils.add(items, "挖矿木马特征",
            "CpuMiner 服务以 AndroidManifest 中注册的后台服务形式运行，\n" +
            "持续占用 CPU。可通过进程列表和 CPU 使用率检测。");

        // 读取 /proc 目录下的进程列表（无需权限）
        File proc = new File("/proc");
        File[] pids = proc.listFiles(f -> f.isDirectory() && f.getName().matches("\\d+"));
        if (pids == null) {
            CollectorUtils.add(items, "/proc 访问", "不可访问");
            return;
        }

        CollectorUtils.add(items, "当前可见进程数", String.valueOf(pids.length));
        CollectorUtils.add(items, "说明",
            "Android 高版本限制普通 App 枚举其他进程；\n"
            + "此处仅显示当前 App 可见进程（通常只有本 App 自身及少量系统进程），\n"
            + "不代表设备运行中的进程总数。");

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
            if (shown < MAX_PROCESS_SAMPLE) {
                CollectorUtils.add(items, "PID " + pidDir.getName(), cmdline);
                shown++;
            }
        }

        if (!suspicious.isEmpty()) {
            for (String s : suspicious) {
                CollectorUtils.add(items, "⚠ 可疑进程", CollectorUtils.HIGH_RISK_PREFIX + s);
            }
        } else {
            CollectorUtils.add(items, "可疑进程检测", "在当前可见范围内未发现已知挖矿/Root工具进程");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 工具方法
    // ─────────────────────────────────────────────────────────────

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
            // 展示签名方案字段
            StringBuilder value = new StringBuilder();
            value.append("V1:").append(result.hasV1Signature ? "✓" : "✗");
            value.append("  V2:").append(result.hasV2Block ? "✓" : "✗");
            value.append("  V3:").append(result.hasV3Block ? "✓" : "✗");
            value.append(" | 置信度:").append(result.detectionConfidence);
            value.append(" | ").append(result.detectionNote);

            // Janus 风险仅在 V1-only 且 API ≤ 26 时标为高危
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
