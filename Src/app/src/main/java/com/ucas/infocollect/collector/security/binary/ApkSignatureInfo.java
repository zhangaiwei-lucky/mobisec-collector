package com.ucas.infocollect.collector.security.binary;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Objects;

/**
 * APK 签名方案检测结果（不可变值对象）。
 *
 * <p>由 {@link ApkSignatureParser#parse} 返回，描述一个 APK 文件中
 * 各版本签名方案的存在情况及检测置信度。</p>
 *
 * <h3>字段说明</h3>
 * <dl>
 *   <dt>{@link #hasV1Signature}</dt>
 *   <dd>{@code META-INF/} 目录下存在 {@code .RSA}、{@code .DSA} 或 {@code .EC} 文件
 *       （即 JAR 签名方案存在迹象）。</dd>
 *   <dt>{@link #hasV2Block}</dt>
 *   <dd>APK Signing Block 中检测到 V2 Signature Block ID（{@code 0x7109871a}）。</dd>
 *   <dt>{@link #hasV3Block}</dt>
 *   <dd>APK Signing Block 中检测到 V3 或 V3.1 Signature Block ID。</dd>
 *   <dt>{@link #hasV4Signature}</dt>
 *   <dd>V4 签名（{@code .apk.idsig} 伴随文件），{@code null} 表示本次未检测
 *       （解析器实现可选支持）。</dd>
 *   <dt>{@link #confidence}</dt>
 *   <dd>检测置信度：{@code HIGH} 表示直接解析 Signing Block 成功；
 *       {@code MEDIUM} 表示结构存在但部分字段无法确认；
 *       {@code LOW} 表示仅凭间接迹象推断，结论须离线验证。</dd>
 *   <dt>{@link #note}</dt>
 *   <dd>可人类阅读的检测附注，如"Signing Block 解析完成"或"APK 文件不可读"。</dd>
 * </dl>
 */
public final class ApkSignatureInfo {

    /** 检测置信度。 */
    public enum Confidence {
        /** Signing Block 直接解析成功，结论可靠。 */
        HIGH,
        /** 结构性证据存在但存在歧义，建议二次确认。 */
        MEDIUM,
        /** 仅凭间接迹象推断，不应作为安全归因的唯一依据。 */
        LOW
    }

    public final boolean    hasV1Signature;
    public final boolean    hasV2Block;
    public final boolean    hasV3Block;
    @Nullable
    public final Boolean    hasV4Signature;
    @NonNull
    public final Confidence confidence;
    @NonNull
    public final String     note;

    public ApkSignatureInfo(
            final boolean    hasV1Signature,
            final boolean    hasV2Block,
            final boolean    hasV3Block,
            @Nullable final Boolean    hasV4Signature,
            @NonNull  final Confidence confidence,
            @NonNull  final String     note) {
        this.hasV1Signature = hasV1Signature;
        this.hasV2Block     = hasV2Block;
        this.hasV3Block     = hasV3Block;
        this.hasV4Signature = hasV4Signature;
        this.confidence     = Objects.requireNonNull(confidence, "confidence must not be null");
        this.note           = Objects.requireNonNull(note,       "note must not be null");
    }

    /**
     * 是否属于"现代签名"：V2 或 V3 Block 至少存在其一。
     * 现代签名可防止 Janus（CVE-2017-13156）攻击。
     */
    public boolean isModernSigned() {
        return hasV2Block || hasV3Block;
    }

    /**
     * 是否属于高风险的纯 V1 签名：存在 V1 迹象且不存在 V2/V3 Block。
     * 在 Android 5.1–8.0（API 22–26）上易受 Janus 攻击。
     */
    public boolean isPossiblyV1Only() {
        return hasV1Signature && !hasV2Block && !hasV3Block;
    }

    @Override
    @NonNull
    public String toString() {
        return "ApkSignatureInfo{"
                + "V1=" + hasV1Signature
                + ", V2=" + hasV2Block
                + ", V3=" + hasV3Block
                + ", V4=" + hasV4Signature
                + ", confidence=" + confidence
                + ", note='" + note + "'}";
    }
}
