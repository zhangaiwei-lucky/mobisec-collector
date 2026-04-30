package com.ucas.infocollect.collector.security;

import android.content.pm.PackageManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ucas.infocollect.collector.SystemEnvironment;

/**
 * 安全扫描专用上下文，对 {@link SystemEnvironment} 的扩展。
 *
 * <p>相较基础的 {@link SystemEnvironment}，增加了安全扫描所必需的
 * {@link PackageManager} 访问能力。</p>
 *
 * <p>设计约束：</p>
 * <ul>
 *   <li>接口继承而非组合，使任何 {@link SystemEnvironment} 实现都能通过委托
 *       快速升级为 {@code SecurityScanContext}，无需重写已有方法。</li>
 *   <li>{@link SecurityScanner} 的 {@code scan()} 方法接受本接口而非
 *       直接接受 {@code PackageManager}，保留了后续扩展（如注入
 *       {@code UsageStatsManager}、{@code AppOpsManager}）的空间。</li>
 *   <li>实现类（{@code AndroidSecurityScanContext}）仍是 Context 唯一合法的
 *       存在位置，扫描器实现内部禁止出现任何 {@code android.content.Context} 引用。</li>
 * </ul>
 */
public interface SecurityScanContext extends SystemEnvironment {

    /**
     * 提供 {@link PackageManager} 实例，供需要枚举已安装包的子扫描器使用。
     *
     * <p>调用方不得持久持有返回的引用；每次使用前应重新通过本方法获取，
     * 以防止 Activity 重建后出现陈旧实例。</p>
     */
    @NonNull
    PackageManager getPackageManager();

    /**
     * 读取 Linux 虚拟文件系统中的纯文本文件（{@code /proc/*}、{@code /sys/*} 等）。
     *
     * <p>此方法专为内核安全状态探测设计，目标路径均为 procfs / sysfs 中的
     * 只读伪文件。实现类不应尝试读取 {@code /data/} 等用户数据分区路径，
     * 调用方亦不得将返回内容直接用于安全决策，应先进行格式校验。</p>
     *
     * <p>读取的文件通常以换行符结尾；实现类应对返回值执行 {@code trim()}，
     * 调用方收到结果后即可直接进行字符串比较，无需再次清理。</p>
     *
     * @param path 绝对路径，例如 {@code "/sys/fs/selinux/enforce"}
     * @return 文件全文内容（已 trim）；若文件不存在、无读权限或 I/O 异常则返回 {@code null}
     */
    @Nullable
    String readSystemFile(@NonNull String path);
}
