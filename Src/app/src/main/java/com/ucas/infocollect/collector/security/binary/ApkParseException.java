package com.ucas.infocollect.collector.security.binary;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * APK 二进制结构解析失败时的受检异常。
 *
 * <p>调用方（通常是 {@code ApkSignatureScanner}）负责捕获并转换为
 * {@link com.ucas.infocollect.collector.security.ScanResult#partial}，
 * 而非向上层传播。</p>
 *
 * <p>区分两类错误来源：</p>
 * <ul>
 *   <li>{@link Reason#IO_ERROR} — 底层 I/O 异常（文件不可读、权限被拒等）。</li>
 *   <li>{@link Reason#MALFORMED_STRUCTURE} — 文件结构不符合 ZIP/APK Signing Block 规范。</li>
 * </ul>
 */
public final class ApkParseException extends Exception {

    /** 解析失败原因分类。 */
    public enum Reason {
        /** 底层文件读取失败（权限、文件不存在、I/O 错误）。 */
        IO_ERROR,
        /** APK/ZIP 二进制结构不符合规范（EOCD 缺失、偏移越界、魔数不匹配等）。 */
        MALFORMED_STRUCTURE
    }

    @NonNull
    public final Reason reason;

    public ApkParseException(@NonNull final Reason reason, @NonNull final String message) {
        super(message);
        this.reason = reason;
    }

    public ApkParseException(
            @NonNull final Reason reason,
            @NonNull final String message,
            @Nullable final Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }
}
