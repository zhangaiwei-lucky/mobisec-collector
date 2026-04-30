package com.ucas.infocollect.collector.security.scanner;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ucas.infocollect.collector.security.Finding;
import com.ucas.infocollect.collector.security.ScanResult;
import com.ucas.infocollect.collector.security.SecurityScanContext;
import com.ucas.infocollect.collector.security.SecurityScanner;
import com.ucas.infocollect.collector.security.Severity;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 可疑进程嗅探扫描器（Suspicious Process Scanner）。
 *
 * <h2>设计原则</h2>
 * <p>本扫描器<b>不依赖任何 Android 框架 API</b>（无 ActivityManager、无 PackageManager）。
 * 完全通过 Linux procfs（{@code /proc}）的目录遍历和文本文件读取实现，
 * 属于纯 JVM 可测试的 I/O 驱动扫描逻辑。</p>
 *
 * <p>这种设计有两个关键优势：</p>
 * <ol>
 *   <li><b>绕过框架过滤：</b>{@code ActivityManager.getRunningAppProcesses()} 自 Android 7.0 起
 *       仅返回当前应用的进程，对第三方进程不可见；而 {@code /proc} 目录在非 root 设备上仍然
 *       可遍历，每个 PID 目录的 {@code cmdline} 文件对普通应用可读。</li>
 *   <li><b>对抗进程隐藏：</b>部分恶意软件会将自身从 ActivityManager 列表中隐藏（通过 SELinux
 *       策略绕过或框架 hook），但内核进程表（procfs）无法被用户态代码伪造，
 *       从内核视角进行枚举可获得更真实的进程快照。</li>
 * </ol>
 *
 * <h2>检测机制</h2>
 * <ol>
 *   <li>枚举 {@code /proc/} 目录下所有以纯数字命名的子目录——每个目录名即为
 *       一个活动进程的 PID（Process ID）。</li>
 *   <li>读取 {@code /proc/{pid}/cmdline} 文件，获取进程的完整命令行参数列表。
 *       {@code cmdline} 文件格式：参数间以 {@code NUL}（{@code \0}，ASCII 0x00）
 *       分隔，文件末尾以 {@code \0} 结束。本扫描器将 {@code \0} 替换为空格后进行匹配。</li>
 *   <li>对规范化后的 cmdline 执行<b>大小写不敏感的子串匹配</b>，与
 *       {@link #SUSPICIOUS_KEYWORDS} 中的 21 个特征关键词逐一比对。</li>
 *   <li>一旦匹配，立即生成 {@link Severity#CRITICAL} 的 {@link Finding}，
 *       Attributes 包含 {@code pid}、{@code cmdline}、{@code matchedKeyword}。</li>
 *   <li>每个进程仅上报第一个匹配关键词（避免同进程重复生成多条 Finding）。</li>
 * </ol>
 *
 * <h2>竞争条件处理</h2>
 * <p>Linux 进程可在任何时刻退出。因此，目录枚举成功后，读取对应 PID 的 {@code cmdline}
 * 可能因进程已消失而返回 {@code null}（{@code FileNotFoundException}）。
 * 本扫描器对此竞争条件静默处理——跳过此类 PID，不记录错误。
 * 这是 procfs 遍历的正常现象，无论多短暂的进程都不会导致扫描逻辑异常。</p>
 *
 * <h2>内核线程的排除</h2>
 * <p>内核线程（kthread）的 {@code cmdline} 文件内容为空（长度为 0）。
 * 本扫描器对空 cmdline 静默跳过，不生成任何 Finding。</p>
 *
 * <h2>权限说明</h2>
 * <p>本扫描器不需要任何 Android 运行时危险权限。</p>
 * <p><b>SELinux 注意：</b>在 SELinux Enforcing 模式下，某些高权限进程的
 * {@code /proc/{pid}/cmdline} 可能对普通应用不可读（返回空或权限拒绝）。
 * 这种情况下该 PID 会被静默跳过，不会触发扫描错误。</p>
 */
public final class SuspiciousProcessScanner implements SecurityScanner {

    public static final String SCANNER_ID = "SUSPICIOUS_PROCESS";

    // ── Finding Type 常量 ──────────────────────────────────────────────────────
    private static final String FT_SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS_DETECTED";
    private static final String FT_SCAN_SUMMARY       = "SUSPICIOUS_PROCESS_SCAN_SUMMARY";

    /** /proc 根目录路径。 */
    private static final String PROC_ROOT = "/proc";

    /**
     * cmdline 文本在 UI 中的最大显示长度（字符数）。
     * 超出部分截断并追加省略号，避免单条 InfoRow 文本过长影响 RecyclerView 滚动性能。
     */
    private static final int MAX_CMDLINE_DISPLAY_LENGTH = 120;

    /**
     * 总 Finding 上限。在极端环境下（如大规模僵尸进程感染），
     * 限制输出条数防止内存消耗过大。精确计数写入摘要 Attribute。
     */
    private static final int MAX_PROCESS_FINDINGS = 50;

    /**
     * 可疑进程特征关键词表（全小写，执行大小写不敏感子串匹配）。
     *
     * <p>匹配对象为进程 {@code /proc/{pid}/cmdline} 的全文内容（含路径中的目录名）。
     * 例如 {@code /data/local/tmp/frida-server-16.0.0-android-arm64} 可被 {@code "frida"} 命中。</p>
     *
     * <table border="1" cellpadding="4">
     *   <caption>关键词分类说明</caption>
     *   <tr><th>分类</th><th>关键词</th><th>说明</th></tr>
     *   <tr>
     *     <td>Root 管理 / 提权工具</td>
     *     <td>magisk, supersu, kinguser</td>
     *     <td>Root 管理守护进程常驻后台，其存在表明设备已被提权，所有安全沙箱屏障可能失效。</td>
     *   </tr>
     *   <tr>
     *     <td>动态插桩 / Hook 框架</td>
     *     <td>frida, xposed, edxposed, lsposed, substrate</td>
     *     <td>可在运行时 hook 任意应用的 Java / Native 函数，用于绕过证书校验、
     *         读取内存数据、篡改业务逻辑。Frida-server 作为独立进程运行时可被此规则命中。</td>
     *   </tr>
     *   <tr>
     *     <td>调试工具</td>
     *     <td>gdb, lldb, strace</td>
     *     <td>调试器可附加到任意进程读取内存、寄存器和系统调用序列，
     *         用于提取密钥、重放 API 请求或分析加密算法。</td>
     *   </tr>
     *   <tr>
     *     <td>网络嗅探 / MITM 工具</td>
     *     <td>tcpdump, wireshark, bettercap, mitmproxy</td>
     *     <td>被动或主动截获网络流量，提取 TLS 解密前的明文数据；
     *         可绕过证书绑定（Certificate Pinning）弱实现。</td>
     *   </tr>
     *   <tr>
     *     <td>游戏作弊工具</td>
     *     <td>gameguardian, cheatengine</td>
     *     <td>内存扫描和修改工具，也常被用于应用破解和绕过付费验证。</td>
     *   </tr>
     *   <tr>
     *     <td>挖矿木马</td>
     *     <td>xmrig, minerd</td>
     *     <td>后台挖矿进程大量消耗 CPU 和电池，是移动端僵尸网络的典型载荷。</td>
     *   </tr>
     *   <tr>
     *     <td>漏洞利用框架 / 通用注入</td>
     *     <td>metasploit, inject, netcat, busybox</td>
     *     <td>exploit 工具或支撑提权链的系统工具；
     *         busybox 常被 Root 工具附带，本身无害但频繁被恶意脚本依赖。</td>
     *   </tr>
     * </table>
     */
    private static final String[] SUSPICIOUS_KEYWORDS = {
            // Root 管理 / 提权工具
            "magisk",        // Magisk Root 管理框架守护进程（magiskd / magisk）
            "supersu",       // SuperSU su 守护进程
            "kinguser",      // KingUser su 守护进程（国内流行 ROM）

            // 动态插桩 / Hook 框架
            "frida",         // Frida 动态插桩工具服务端（frida-server、frida-gadget）
            "xposed",        // Xposed Framework 安装进程或 zygote hook 产生的进程名残留
            "edxposed",      // EdXposed（Riru 模块，Xposed 后继）
            "lsposed",       // LSPosed（Zygisk 模块，现代 Xposed 实现）
            "substrate",     // Cydia MobileSubstrate / Cydia Substrate 注入守护进程

            // 调试工具
            "gdb",           // GNU Debugger（gdb / gdbserver）
            "lldb",          // LLVM Debugger（lldb-server / debugserver）
            "strace",        // 系统调用追踪器（可泄露 I/O 路径、网络地址、秘密等系统调用参数）

            // 网络嗅探 / MITM
            "tcpdump",       // 经典网络抓包工具
            "wireshark",     // tshark（Wireshark 命令行版）常见于测试环境
            "bettercap",     // 现代一体化 MITM / 网络攻击框架
            "mitmproxy",     // 透明 HTTP/HTTPS 中间人代理

            // 游戏作弊工具
            "gameguardian",  // GameGuardian 内存修改工具（可用于应用破解）
            "cheatengine",   // Cheat Engine（主机版，Wine/Box64 下可能出现）

            // 挖矿木马
            "xmrig",         // 高性能 Monero / RandomX 挖矿程序（移动端僵尸网络主要载荷）
            "minerd",        // cpuminer / pooler-cpuminer（多算法 CPU 矿工）

            // 漏洞利用框架 / 通用注入工具
            "metasploit",    // Metasploit msfconsole / msfvenom payload shell
            "inject",        // 通用进程注入关键词（inject32、inject64、libinject 等）
    };

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
        return "可疑进程嗅探 — /proc 遍历 / Root 工具 / Hook 框架 / 挖矿木马关键词匹配";
    }

    /**
     * {@inheritDoc}
     *
     * <p>本扫描器不需要任何 Android 运行时危险权限。
     * 所有操作基于 Java {@link File} I/O 对 {@code /proc} 的直接读取，
     * 不依赖 ActivityManager、PackageManager 或任何 Android 框架 API。</p>
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
    public ScanResult scan(@NonNull final SecurityScanContext ctx) {
        final List<Finding> findings = new ArrayList<>();
        final List<String>  errors   = new ArrayList<>();

        // ── 1. 枚举 /proc 下的 PID 目录 ────────────────────────────────────
        final File   procRoot   = new File(PROC_ROOT);
        final File[] procEntries = procRoot.listFiles();

        if (procEntries == null) {
            // /proc 不可遍历（极端的 SELinux 限制或非标准内核）
            // 标记 partial 而非 failed——说明扫描受限，而非运行错误
            errors.add(PROC_ROOT + " is not listable — "
                    + "filesystem may be restricted by SELinux policy or unavailable");
            return ScanResult.partial(SCANNER_ID, findings, errors);
        }

        // ── 2. 统计变量 ──────────────────────────────────────────────────────
        int scannedPidCount  = 0;
        int skippedPidCount  = 0;  // 空 cmdline / 进程退出（竞争条件）计数
        int matchCount       = 0;

        // ── 3. 遍历 PID 目录 ────────────────────────────────────────────────
        for (final File entry : procEntries) {
            if (entry == null) continue;

            // 过滤：只处理纯数字目录名（PID）
            final int pid = parsePid(entry.getName());
            if (pid <= 0) continue;

            // 防御性确认是目录（procfs 中偶有特殊 inode 类型）
            if (!entry.isDirectory()) continue;

            scannedPidCount++;

            // ── 4. 读取 /proc/{pid}/cmdline ──────────────────────────────────
            // 使用 SecurityScanContext.readSystemFile() 实现（纯 Java BufferedReader）
            // 若进程已退出，FileNotFoundException 被 readSystemFile 捕获并返回 null
            final String rawCmdline = ctx.readSystemFile(PROC_ROOT + "/" + pid + "/cmdline");

            if (rawCmdline == null) {
                // 可能原因：进程已退出（竞争条件）、SELinux 拒绝读取、文件不存在
                // 以上均属正常，静默跳过，不写入 errors
                skippedPidCount++;
                continue;
            }

            // ── 5. 规范化 cmdline ────────────────────────────────────────────
            // cmdline 格式：参数间以 \0 分隔，文件末尾以 \0 结束
            // readSystemFile 中的 trim() 已移除首尾的 \0（code point 0 < 32）
            // 但参数间的 \0 仍存在，替换为空格后进行可读性展示和关键词匹配
            final String cmdline = rawCmdline.replace('\0', ' ').trim();

            if (cmdline.isEmpty()) {
                // 内核线程（kthread）的 cmdline 为空，静默跳过
                skippedPidCount++;
                continue;
            }

            // ── 6. 大小写不敏感的关键词匹配 ──────────────────────────────────
            final String cmdlineLower = cmdline.toLowerCase();

            for (final String keyword : SUSPICIOUS_KEYWORDS) {
                if (cmdlineLower.contains(keyword)) {
                    matchCount++;

                    // 每个进程只上报第一个匹配关键词，防止同进程重复上报
                    if (findings.size() < MAX_PROCESS_FINDINGS) {
                        findings.add(buildSuspiciousProcessFinding(pid, cmdline, keyword));
                    }

                    // 匹配到第一个关键词后立即停止继续匹配该进程
                    break;
                }
            }
        }

        // ── 7. 摘要 Finding ──────────────────────────────────────────────────
        final boolean truncated = (findings.size() >= MAX_PROCESS_FINDINGS)
                && (matchCount > MAX_PROCESS_FINDINGS);

        final StringBuilder desc = new StringBuilder();
        desc.append("共扫描 ").append(scannedPidCount).append(" 个活动进程（PID 目录），")
            .append("跳过 ").append(skippedPidCount).append(" 个（空 cmdline / 进程退出 / 无读权限），")
            .append("匹配到 ").append(matchCount).append(" 个可疑进程。");

        if (matchCount == 0) {
            desc.append(" 未检测到已知可疑工具的进程特征。");
        }
        if (truncated) {
            desc.append(" [注意：Finding 输出上限 ").append(MAX_PROCESS_FINDINGS)
                .append(" 条，实际可疑进程数量为 ").append(matchCount).append(" 个]");
        }

        findings.add(Finding.of(FT_SCAN_SUMMARY, Severity.INFO)
                .title("可疑进程扫描摘要")
                .description(desc.toString())
                .attribute("scanned_pid_count", String.valueOf(scannedPidCount))
                .attribute("suspicious_count",  String.valueOf(matchCount))
                .attribute("skipped_count",      String.valueOf(skippedPidCount))
                .build());

        return errors.isEmpty()
                ? ScanResult.success(SCANNER_ID, findings)
                : ScanResult.partial(SCANNER_ID, findings, errors);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Finding 工厂方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 构建单条可疑进程 Finding。
     *
     * <p>cmdline 超过 {@link #MAX_CMDLINE_DISPLAY_LENGTH} 字符时截断，
     * 完整 cmdline 对于 Finding 的机器可读处理无损——截断仅影响 UI 展示。</p>
     */
    @NonNull
    private static Finding buildSuspiciousProcessFinding(
            final int    pid,
            @NonNull final String cmdline,
            @NonNull final String matchedKeyword) {

        final String displayCmdline = cmdline.length() > MAX_CMDLINE_DISPLAY_LENGTH
                ? cmdline.substring(0, MAX_CMDLINE_DISPLAY_LENGTH) + "…"
                : cmdline;

        return Finding.of(FT_SUSPICIOUS_PROCESS, Severity.CRITICAL)
                .title("可疑进程 [" + matchedKeyword + "]: PID " + pid)
                .description(
                        "进程 PID " + pid + " 的命令行中包含可疑关键词 \""
                        + matchedKeyword + "\"。\n"
                        + "该关键词与以下类别的已知工具相关联：\n"
                        + "  • Root 管理守护进程（设备可能已越狱）\n"
                        + "  • 动态插桩 / Hook 框架（Frida / Xposed / LSPosed 等）\n"
                        + "  • 调试器 / 系统调用追踪器\n"
                        + "  • 网络嗅探 / 中间人攻击工具\n"
                        + "  • 游戏作弊工具（可用于应用内存修改和破解）\n"
                        + "  • 挖矿木马 / 恶意载荷\n"
                        + "建议人工确认进程来源及在设备上的合法性。\n"
                        + "若确认为 Root 工具或 Hook 框架，该设备已处于"
                        + "不可信执行环境（Untrusted Execution Environment），"
                        + "任何敏感业务逻辑（如密钥存储、生物认证、支付流程）"
                        + "均应视为已被潜在破坏。")
                .attribute("pid",            String.valueOf(pid))
                .attribute("cmdline",        displayCmdline)
                .attribute("matchedKeyword", matchedKeyword)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 内部工具方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 将 /proc 目录条目名称解析为 PID 整数。
     *
     * <p>有效 PID 为正整数。{@code /proc/self}、{@code /proc/cpuinfo} 等
     * 非 PID 条目因包含非数字字符而被过滤。</p>
     *
     * @param name {@code /proc} 下的条目目录名
     * @return 有效 PID（> 0），或 {@code -1}（非数字名称或解析失败）
     */
    private static int parsePid(@Nullable final String name) {
        if (name == null || name.isEmpty()) return -1;
        // 快速预筛：只接受全数字字符串（ASCII '0'-'9'）
        for (int i = 0; i < name.length(); i++) {
            final char c = name.charAt(i);
            if (c < '0' || c > '9') return -1;
        }
        try {
            final int pid = Integer.parseInt(name);
            return pid > 0 ? pid : -1;
        } catch (final NumberFormatException e) {
            // 数字字符串但超出 int 范围（长度 > 10 位），视为无效
            return -1;
        }
    }
}
