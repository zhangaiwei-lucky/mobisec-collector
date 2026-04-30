package com.ucas.infocollect.collector.security.scanner;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ucas.infocollect.collector.security.Finding;
import com.ucas.infocollect.collector.security.ScanResult;
import com.ucas.infocollect.collector.security.SecurityScanContext;
import com.ucas.infocollect.collector.security.SecurityScanner;
import com.ucas.infocollect.collector.security.Severity;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * 内核安全状态探测扫描器。
 *
 * <h2>威胁模型覆盖</h2>
 * <dl>
 *   <dt>SELinux Permissive 模式</dt>
 *   <dd>Linux 强制访问控制（MAC）完全失效。任何具有代码执行能力的攻击者均可
 *       跨进程边界访问任意文件、绑定任意 Service、修改系统属性，
 *       提权链中最关键的沙箱屏障被彻底移除。CVSS 基础分最高可达 9.8（AV:L/AC:L）。</dd>
 *
 *   <dt>ASLR 禁用或部分启用</dt>
 *   <dd>地址空间布局随机化缺失，使 ROP（Return-Oriented Programming）、
 *       ret2libc、JIT Spray 等内存破坏漏洞利用难度大幅降低。
 *       Level 0（关闭）意味着攻击者可在不进行任何信息泄露的前提下构造利用链。</dd>
 *
 *   <dt>perf_event_paranoid 值过低</dt>
 *   <dd>内核性能计数器对非特权进程开放，可被用于旁信道攻击（Side-Channel），
 *       包括 Spectre 变种和基于 CPU 缓存的信息泄露。值 < 2 表示非 root 进程
 *       也可访问内核级事件，在共享核（Shared Core）场景下风险显著。</dd>
 * </dl>
 *
 * <h2>SELinux 三重探测链</h2>
 * <pre>
 *   ① /sys/fs/selinux/enforce           （最可靠，直接读取内核暴露的状态位）
 *      └─ 失败（不可读 / 不存在）
 *         ↓
 *   ② android.os.SELinux 反射           （Android SDK 内部 API，需反射绕过访问控制）
 *      └─ 失败（ClassNotFoundException / SecurityException）
 *         ↓
 *   ③ android.os.SystemProperties 反射  （读取 ro.boot.selinux 启动属性）
 *      └─ 失败 → 记录探测失败错误，标记 partial
 * </pre>
 *
 * <p>每条探测链的 Finding 会携带 {@code source} attribute 标注数据来源，
 * 使审计人员可以追溯置信度。</p>
 */
public final class KernelSecurityScanner implements SecurityScanner {

    public static final String SCANNER_ID = "KERNEL_SECURITY";

    // ── 文件路径常量 ───────────────────────────────────────────────────────────
    private static final String PATH_SELINUX_ENFORCE      = "/sys/fs/selinux/enforce";
    private static final String PATH_ASLR                 = "/proc/sys/kernel/randomize_va_space";
    private static final String PATH_PERF_EVENT_PARANOID  = "/proc/sys/kernel/perf_event_paranoid";

    // ── Finding Type 常量 ──────────────────────────────────────────────────────
    private static final String FT_SELINUX_PERMISSIVE      = "SELINUX_PERMISSIVE_MODE";
    private static final String FT_SELINUX_ENFORCING        = "SELINUX_ENFORCING_MODE";
    private static final String FT_SELINUX_UNDETECTABLE     = "SELINUX_STATUS_UNDETECTABLE";
    private static final String FT_ASLR_DISABLED            = "ASLR_DISABLED";
    private static final String FT_ASLR_PARTIAL             = "ASLR_PARTIAL";
    private static final String FT_ASLR_FULL                = "ASLR_FULL_RANDOMIZATION";
    private static final String FT_PERF_EVENT_UNRESTRICTED  = "PERF_EVENT_UNRESTRICTED";
    private static final String FT_PERF_EVENT_RESTRICTED    = "PERF_EVENT_RESTRICTED";

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
        return "内核安全状态探测 — SELinux / ASLR / perf_event_paranoid";
    }

    @NonNull
    @Override
    public ScanResult scan(@NonNull final SecurityScanContext ctx) {
        final List<Finding> findings = new ArrayList<>();
        final List<String>  errors   = new ArrayList<>();

        detectSeLinux(ctx, findings, errors);
        detectAslr(ctx, findings, errors);
        detectPerfEventParanoid(ctx, findings, errors);

        return errors.isEmpty()
                ? ScanResult.success(SCANNER_ID, findings)
                : ScanResult.partial(SCANNER_ID, findings, errors);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §1  SELinux 状态检测
    // ─────────────────────────────────────────────────────────────────────────

    private void detectSeLinux(
            @NonNull final SecurityScanContext ctx,
            @NonNull final List<Finding>       findings,
            @NonNull final List<String>        errors) {

        // ① 首选路径：直接读取内核暴露的 sysfs 节点
        final String enforceVal = ctx.readSystemFile(PATH_SELINUX_ENFORCE);
        if (enforceVal != null) {
            findings.add(buildSeLinuxFindingFromEnforceFile(enforceVal));
            return;
        }

        // ② 降级路径 1：android.os.SELinux 反射（比 sysfs 读取稍低置信度）
        final Boolean reflectedEnforced = querySeLinuxViaReflection(errors);
        if (reflectedEnforced != null) {
            findings.add(buildSeLinuxFindingFromReflection(reflectedEnforced));
            return;
        }

        // ③ 降级路径 2：android.os.SystemProperties 读取 ro.boot.selinux
        final String bootSeLinuxProp = querySystemProperty("ro.boot.selinux", errors);
        if (bootSeLinuxProp != null) {
            findings.add(buildSeLinuxFindingFromBootProp(bootSeLinuxProp));
            return;
        }

        // 三条链全部失败——无法确定 SELinux 状态，本身就值得记录
        findings.add(Finding.of(FT_SELINUX_UNDETECTABLE, Severity.MEDIUM)
                .title("SELinux 状态无法确定")
                .description(
                        "三条探测链均未能获取 SELinux 状态：① " + PATH_SELINUX_ENFORCE
                        + " 不可读；② android.os.SELinux 反射失败；"
                        + "③ ro.boot.selinux 属性读取失败。"
                        + "在具有完善 SELinux 策略的正常设备上，该文件通常可读。"
                        + "状态不可读本身可能指示非标准内核配置或主动防御措施。")
                .attribute("source", "all_methods_failed")
                .build());
    }

    @NonNull
    private static Finding buildSeLinuxFindingFromEnforceFile(@NonNull final String rawValue) {
        if ("1".equals(rawValue)) {
            return Finding.of(FT_SELINUX_ENFORCING, Severity.INFO)
                    .title("SELinux 处于 Enforcing（强制执行）模式")
                    .description(
                            "强制访问控制策略生效。所有未经 SELinux Policy 明确允许的操作均被拒绝，"
                            + "进程沙箱隔离、IPC 过滤和文件访问控制均处于正常防护状态。")
                    .attribute("enforce_value", rawValue)
                    .attribute("source",        PATH_SELINUX_ENFORCE)
                    .build();
        } else if ("0".equals(rawValue)) {
            return Finding.of(FT_SELINUX_PERMISSIVE, Severity.CRITICAL)
                    .title("SELinux 处于 Permissive（宽松）模式 — MAC 策略失效")
                    .description(
                            "SELinux Permissive 模式下，内核仅记录策略违规日志，不执行任何拒绝操作。"
                            + "这意味着：① 进程间的域隔离屏障完全失效；"
                            + "② 攻击者在获得任意代码执行后可横向移动至任意进程上下文；"
                            + "③ /data 分区文件、Binder 接口、系统属性均无 MAC 保护。"
                            + "宽松模式通常仅见于开发设备、已 Root 设备或被攻击者主动降级的设备。"
                            + "生产环境中此状态等同于 SELinux 被完全禁用。")
                    .attribute("enforce_value", rawValue)
                    .attribute("source",        PATH_SELINUX_ENFORCE)
                    .build();
        } else {
            // 非预期值——记录为 MEDIUM 供人工审查
            return Finding.of(FT_SELINUX_UNDETECTABLE, Severity.MEDIUM)
                    .title("SELinux enforce 文件返回非预期值")
                    .description(
                            PATH_SELINUX_ENFORCE + " 返回值 \"" + rawValue
                            + "\" 不符合规范（预期为 \"0\" 或 \"1\"）。"
                            + "可能原因：非标准内核补丁、文件被重定向或虚拟化环境。")
                    .attribute("enforce_value", rawValue)
                    .attribute("source",        PATH_SELINUX_ENFORCE)
                    .build();
        }
    }

    @NonNull
    private static Finding buildSeLinuxFindingFromReflection(final boolean enforced) {
        if (enforced) {
            return Finding.of(FT_SELINUX_ENFORCING, Severity.INFO)
                    .title("SELinux 处于 Enforcing 模式（via android.os.SELinux 反射）")
                    .description("android.os.SELinux.isSELinuxEnforced() 返回 true，MAC 策略正常执行。"
                            + "置信度：MEDIUM（间接 API，结果依赖 Android 框架层报告的准确性）。")
                    .attribute("source",     "android.os.SELinux reflection")
                    .attribute("confidence", "MEDIUM")
                    .build();
        } else {
            return Finding.of(FT_SELINUX_PERMISSIVE, Severity.CRITICAL)
                    .title("SELinux 未处于 Enforcing 模式（via android.os.SELinux 反射）")
                    .description(
                            "android.os.SELinux 报告 SELinux 未启用或处于 Permissive 模式。"
                            + "MAC 策略可能完全失效，建议结合 " + PATH_SELINUX_ENFORCE
                            + " 直接读取进行交叉验证。")
                    .attribute("source",     "android.os.SELinux reflection")
                    .attribute("confidence", "MEDIUM")
                    .build();
        }
    }

    @NonNull
    private static Finding buildSeLinuxFindingFromBootProp(@NonNull final String propValue) {
        final boolean permissive = "permissive".equalsIgnoreCase(propValue);
        final Severity severity  = permissive ? Severity.HIGH : Severity.INFO;
        final String type        = permissive ? FT_SELINUX_PERMISSIVE : FT_SELINUX_ENFORCING;
        final String modeStr     = permissive ? "Permissive" : "Enforcing";

        return Finding.of(type, severity)
                .title("SELinux 启动属性指示 " + modeStr + " 模式（via ro.boot.selinux）")
                .description(
                        "ro.boot.selinux 系统属性值为 \"" + propValue + "\"。"
                        + "注意：该属性在启动时由 init 进程读取，运行时内核状态可能已被动态修改，"
                        + "置信度低于直接读取 sysfs 节点。"
                        + (permissive
                                ? "Permissive 模式：MAC 策略可能失效，建议通过其他方法二次确认。"
                                : "MAC 策略应处于正常执行状态。"))
                .attribute("prop_value", propValue)
                .attribute("source",     "ro.boot.selinux via SystemProperties")
                .attribute("confidence", "LOW")
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §2  ASLR 级别检测
    // ─────────────────────────────────────────────────────────────────────────

    private void detectAslr(
            @NonNull final SecurityScanContext ctx,
            @NonNull final List<Finding>       findings,
            @NonNull final List<String>        errors) {

        final String raw = ctx.readSystemFile(PATH_ASLR);
        if (raw == null) {
            errors.add("ASLR: " + PATH_ASLR + " is not readable");
            return;
        }

        final int level = parseIntSafe(raw);
        if (level < 0) {
            errors.add("ASLR: unexpected non-integer value \"" + raw + "\" in " + PATH_ASLR);
            return;
        }

        switch (level) {
            case 0:
                findings.add(Finding.of(FT_ASLR_DISABLED, Severity.HIGH)
                        .title("ASLR 已禁用（randomize_va_space=0）")
                        .description(
                                "地址空间布局随机化完全关闭。堆、栈、mmap 区域和可执行文件的加载地址"
                                + "在每次运行时均固定不变。攻击者在构造内存破坏漏洞利用链时无需"
                                + "任何信息泄露原语，可直接对硬编码地址执行 ROP / ret2libc 攻击。"
                                + "生产设备禁用 ASLR 通常是 Root 工具或自定义内核的副作用。")
                        .attribute("randomize_va_space", raw)
                        .attribute("source", PATH_ASLR)
                        .build());
                break;

            case 1:
                findings.add(Finding.of(FT_ASLR_PARTIAL, Severity.MEDIUM)
                        .title("ASLR 仅部分启用（randomize_va_space=1）")
                        .description(
                                "堆和栈地址已随机化，但共享库（mmap 区域）的加载地址固定。"
                                + "通过 JIT Spray 或针对固定共享库的 Return-to-library 攻击，"
                                + "攻击者仍可绕过部分 ASLR 防护。完全随机化（level=2）可消除此攻击面。")
                        .attribute("randomize_va_space", raw)
                        .attribute("source", PATH_ASLR)
                        .build());
                break;

            case 2:
                findings.add(Finding.of(FT_ASLR_FULL, Severity.INFO)
                        .title("ASLR 完全随机化（randomize_va_space=2）")
                        .description(
                                "堆、栈和 mmap 区域均参与随机化，内存布局对攻击者不可预测。"
                                + "配合栈 Canary（-fstack-protector）和 PIE 可执行文件，"
                                + "提供最强的内存破坏漏洞缓解覆盖。")
                        .attribute("randomize_va_space", raw)
                        .attribute("source", PATH_ASLR)
                        .build());
                break;

            default:
                errors.add("ASLR: unexpected randomize_va_space=" + level);
                break;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §3  perf_event_paranoid 级别检测
    // ─────────────────────────────────────────────────────────────────────────

    private void detectPerfEventParanoid(
            @NonNull final SecurityScanContext ctx,
            @NonNull final List<Finding>       findings,
            @NonNull final List<String>        errors) {

        final String raw = ctx.readSystemFile(PATH_PERF_EVENT_PARANOID);
        if (raw == null) {
            errors.add("perf_event: " + PATH_PERF_EVENT_PARANOID + " is not readable");
            return;
        }

        final int level = parseIntSafe(raw);
        if (level < 0) {
            errors.add("perf_event: unexpected value \"" + raw + "\" in " + PATH_PERF_EVENT_PARANOID);
            return;
        }

        if (level >= 2) {
            findings.add(Finding.of(FT_PERF_EVENT_RESTRICTED, Severity.INFO)
                    .title("perf_event_paranoid=" + level + " — 内核性能计数器已限制")
                    .description(
                            "非特权进程无法访问内核级性能事件计数器，"
                            + "基于硬件 PMU 的旁信道攻击（如 Spectre 变种）面临较高门槛。")
                    .attribute("perf_event_paranoid", raw)
                    .attribute("source", PATH_PERF_EVENT_PARANOID)
                    .build());
        } else {
            // level 0 或 1：非 root 进程可访问内核事件
            final Severity severity    = (level <= 0) ? Severity.MEDIUM : Severity.LOW;
            final String   riskDetail  = (level <= 0)
                    ? "任意非特权进程均可访问内核级事件计数器，Spectre / Meltdown 侧信道利用难度最低。"
                    : "非特权进程可访问除内核事件计数器外的大多数 perf 事件，旁信道利用面较宽。";

            findings.add(Finding.of(FT_PERF_EVENT_UNRESTRICTED, severity)
                    .title("perf_event_paranoid=" + level + " — 性能计数器对非特权进程开放")
                    .description(
                            "内核 perf_event_paranoid 值为 " + level + "（安全建议值为 ≥ 2）。"
                            + riskDetail
                            + "在 CPU 超线程（HT）开启且多租户共享核心的环境下，"
                            + "攻击者可利用此接口实施基于缓存时序的信息泄露。"
                            + "CVE-2018-3639（Spectre v4）、CVE-2019-1125（SWAPGS）"
                            + "等漏洞的 PoC 均依赖低 paranoid 级别。")
                    .attribute("perf_event_paranoid", raw)
                    .attribute("recommended_value",   "2")
                    .attribute("source", PATH_PERF_EVENT_PARANOID)
                    .build());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §4  反射工具方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 通过反射调用 {@code android.os.SELinux.isSELinuxEnforced()}。
     *
     * <p>该类是 Android SDK 的隐藏 API（{@code @hide}），在所有 Android 版本中
     * 均通过反射可达（直至 Android 9 引入的 Hidden API 限制，但 targetSdk < 28 时仍可反射）。</p>
     *
     * @return {@code true} = Enforcing，{@code false} = Permissive/Disabled，
     *         {@code null} = 反射失败
     */
    @Nullable
    private static Boolean querySeLinuxViaReflection(@NonNull final List<String> errors) {
        try {
            final Class<?> seLinuxClass = Class.forName("android.os.SELinux");
            final Method   isSELinuxEnabled  = seLinuxClass.getMethod("isSELinuxEnabled");
            final Method   isSELinuxEnforced = seLinuxClass.getMethod("isSELinuxEnforced");
            final boolean  enabled  = Boolean.TRUE.equals(isSELinuxEnabled.invoke(null));
            final boolean  enforced = Boolean.TRUE.equals(isSELinuxEnforced.invoke(null));
            return enabled && enforced;
        } catch (final ClassNotFoundException e) {
            errors.add("SELinux reflection chain 2: android.os.SELinux class not found");
        } catch (final NoSuchMethodException e) {
            errors.add("SELinux reflection chain 2: method not found — " + e.getMessage());
        } catch (final SecurityException e) {
            errors.add("SELinux reflection chain 2: SecurityException — " + e.getMessage());
        } catch (final Exception e) {
            errors.add("SELinux reflection chain 2: " + e.getClass().getSimpleName()
                    + " — " + e.getMessage());
        }
        return null;
    }

    /**
     * 通过反射调用 {@code android.os.SystemProperties.get(key)} 读取系统属性。
     *
     * <p>{@code SystemProperties} 是 Android SDK 的隐藏 API，所有平台版本均可反射访问。</p>
     *
     * @return 属性值字符串；属性不存在或反射失败时返回 {@code null}
     */
    @Nullable
    private static String querySystemProperty(
            @NonNull final String         key,
            @NonNull final List<String>   errors) {
        try {
            final Class<?> spClass = Class.forName("android.os.SystemProperties");
            final Method   getMethod = spClass.getMethod("get", String.class);
            final String   value     = (String) getMethod.invoke(null, key);
            return (value != null && !value.isEmpty()) ? value : null;
        } catch (final ClassNotFoundException e) {
            errors.add("SELinux reflection chain 3: android.os.SystemProperties not found");
        } catch (final NoSuchMethodException e) {
            errors.add("SELinux reflection chain 3: SystemProperties.get() method not found");
        } catch (final SecurityException e) {
            errors.add("SELinux reflection chain 3: SecurityException — " + e.getMessage());
        } catch (final Exception e) {
            errors.add("SELinux reflection chain 3: " + e.getClass().getSimpleName()
                    + " — " + e.getMessage());
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §5  通用工具方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 将字符串安全解析为 int，失败时返回 {@code -1}（所有合法内核参数值均 ≥ 0）。
     */
    private static int parseIntSafe(@NonNull final String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (final NumberFormatException e) {
            return -1;
        }
    }
}
