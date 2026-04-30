package com.ucas.infocollect.collector.security;

import androidx.annotation.NonNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 单个 {@link SecurityScanner} 的结构化输出容器（不可变）。
 *
 * <p>三种工厂方法对应三种扫描结果状态：</p>
 * <ul>
 *   <li>{@link #success} — 扫描完整执行，{@link #findings} 包含全部发现。</li>
 *   <li>{@link #partial} — 部分数据因权限或服务不可用而缺失，
 *       {@link #findings} 含已获取部分，{@link #errors} 含缺失原因。</li>
 *   <li>{@link #failed}  — 扫描因致命异常无法执行，{@link #findings} 为空。</li>
 * </ul>
 */
public final class ScanResult {

    /** 产生本结果的扫描器 ID，与 {@link SecurityScanner#getId()} 对应。 */
    @NonNull public final String        scannerId;

    /**
     * 本次扫描产生的发现列表。
     * 空列表表示"扫描成功但未发现问题"，与 {@link #failed} 状态语义不同。
     */
    @NonNull public final List<Finding> findings;

    /**
     * 扫描器级别的错误信息（非发现本身）。
     * 例如：PackageManager 不可用、/proc 无读权限、APK 文件解析失败等。
     */
    @NonNull public final List<String>  errors;

    /**
     * 结果是否不完整。
     * {@code true} 时调用层应在 UI 展示"部分数据缺失"的提示，
     * 避免用户将"未发现"误读为"已排查无风险"。
     */
    public final boolean partial;

    private ScanResult(
            @NonNull final String        scannerId,
            @NonNull final List<Finding> findings,
            @NonNull final List<String>  errors,
            final boolean                partial) {
        this.scannerId = Objects.requireNonNull(scannerId);
        this.findings  = Collections.unmodifiableList(new ArrayList<>(findings));
        this.errors    = Collections.unmodifiableList(new ArrayList<>(errors));
        this.partial   = partial;
    }

    /** 扫描完整执行，无错误。 */
    @NonNull
    public static ScanResult success(
            @NonNull final String        scannerId,
            @NonNull final List<Finding> findings) {
        return new ScanResult(scannerId, findings, Collections.emptyList(), false);
    }

    /** 扫描部分执行，{@code errors} 描述哪些数据源不可达。 */
    @NonNull
    public static ScanResult partial(
            @NonNull final String        scannerId,
            @NonNull final List<Finding> findings,
            @NonNull final List<String>  errors) {
        return new ScanResult(scannerId, findings, errors, true);
    }

    /** 扫描因致命异常无法执行，结果无效。 */
    @NonNull
    public static ScanResult failed(
            @NonNull final String scannerId,
            @NonNull final String error) {
        return new ScanResult(
                scannerId,
                Collections.emptyList(),
                Collections.singletonList(error),
                true);
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }

    public boolean hasErrors() {
        return !errors.isEmpty();
    }
}
