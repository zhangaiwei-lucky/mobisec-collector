package com.ucas.infocollect.engine.crypto;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 硬件支持的对称加密引擎。
 *
 * <h2>密钥管理</h2>
 * 引擎在 {@code AndroidKeyStore} 中持有一把 256 位 AES 主密钥
 * （别名：{@value #DEFAULT_KEY_ALIAS}）。密钥的属性满足：
 * <ul>
 *   <li><b>不可导出</b>：受 KeyStore 内核保护，进程或调试器都拿不到原始字节，
 *       即使设备被 root 也只能在 keystore 进程内调用，不能复制密钥材料。</li>
 *   <li><b>用途严格限定</b>：仅 {@link KeyProperties#PURPOSE_ENCRYPT} 和
 *       {@link KeyProperties#PURPOSE_DECRYPT}；任何 wrap/sign/verify 调用都会被拒绝。</li>
 *   <li><b>算法套件锁定</b>：仅支持 GCM 块模式与 {@link KeyProperties#ENCRYPTION_PADDING_NONE}，
 *       任何 ECB/CBC/PKCS7 误用都会在 {@link Cipher#init(int, java.security.Key,
 *       java.security.spec.AlgorithmParameterSpec)} 阶段失败。</li>
 *   <li><b>不强制用户认证</b>：避免在锁屏/无 PIN 场景下无法解密。但生命周期仍受
 *       系统约束 —— 用户清除/更换主锁屏可能触发
 *       {@link KeyPermanentlyInvalidatedException}，本类会以
 *       {@link CryptoException#KEY_INVALIDATED} 显式上报，调用方应丢弃历史密文。</li>
 * </ul>
 *
 * <h2>加密策略</h2>
 * 算法固定为 {@code AES/GCM/NoPadding}：
 * <ul>
 *   <li><b>IV 长度</b>：12 字节（96 位）。这是 NIST SP 800-38D §5.2.1.1 推荐的
 *       GCM IV 长度，能让 GHASH 跳过 padding 子块、获得最佳性能与最强抗碰撞性。</li>
 *   <li><b>IV 来源</b>：调用 {@link Cipher#init(int, java.security.Key)}（不传
 *       AlgorithmParameterSpec），由 AndroidKeyStore 内部用强 RNG 生成并返回，
 *       绝不复用上一次的 IV，更不允许调用方指定。</li>
 *   <li><b>GCM Tag 长度</b>：128 位（16 字节），AES-GCM 允许的最大值，
 *       提供最高的伪造抗性。Tag 由 GCM 模式自动追加在密文末尾。</li>
 * </ul>
 *
 * <h2>密文容器格式</h2>
 * {@link #encrypt(byte[])} 返回的字节流为自描述的 V1 容器：
 * <pre>
 *   +---------+---------+----------+----------+--------------------+
 *   | magic   | version | iv_len   |   IV     |  ciphertext+tag    |
 *   |  4 B    |   1 B   |   1 B    |  12 B    |    n + 16 B        |
 *   |"MSC1"   |  0x01   |  0x0C    |          |                    |
 *   +---------+---------+----------+----------+--------------------+
 * </pre>
 * 设计要点：
 * <ul>
 *   <li>魔数 {@code "MSC1"} 让损坏文件能在第一字节就被识破，避免误把任意垃圾喂给
 *       Cipher 引发不可预期的 {@link javax.crypto.AEADBadTagException}。</li>
 *   <li>{@code version} 字段保留升级空间，未来若改用 ChaCha20-Poly1305 或调整
 *       Tag 长度，可在不破坏旧数据的前提下并行解码。</li>
 *   <li>{@code iv_len} 显式编码 IV 长度，使容器对未来调整 IV 大小（例如 16 B）保持兼容。</li>
 * </ul>
 *
 * <h2>线程模型</h2>
 * 本类内部不持有可变状态：每次加/解密都会向 {@link Cipher#getInstance(String)}
 * 申请一个新的 Cipher 实例（Cipher 本身非线程安全）。SecretKey 引用在
 * AndroidKeyStore 一侧由内核保证线程安全，可被任意线程并发使用。所有公共方法
 * 标注 {@link AnyThread}，但请勿在主线程调用——KeyStore 操作可能产生 IPC 延迟。
 */
public final class CipherEngine {

    // ── 常量：算法/参数 ─────────────────────────────────────────────────

    /** AndroidKeyStore Provider 名称，KeyStore/KeyGenerator 共用。 */
    private static final String PROVIDER       = "AndroidKeyStore";
    /** 默认密钥别名；同一进程内的多个 CipherEngine 通常应共享。 */
    public  static final String DEFAULT_KEY_ALIAS = "mobisec.collector.snapshot.aes";

    /** 密钥长度（位）。AES-256 提供最高安全级别，硬件 AES 加速通常在数据中心规模都微不足道。 */
    private static final int    KEY_SIZE_BITS  = 256;
    /** GCM 认证 Tag 长度（位），AES-GCM 允许的最大值。 */
    private static final int    GCM_TAG_BITS   = 128;
    /** GCM IV 长度（字节），NIST SP 800-38D 推荐值。 */
    private static final int    GCM_IV_BYTES   = 12;

    /** 完整 Cipher 变换串：算法/模式/填充。 */
    private static final String TRANSFORMATION =
            KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_GCM + "/"
                    + KeyProperties.ENCRYPTION_PADDING_NONE;

    // ── 容器格式常量 ─────────────────────────────────────────────────

    private static final byte[] MAGIC          = { 'M', 'S', 'C', '1' };
    private static final byte   CONTAINER_V1   = 0x01;
    /** Header 总长度：4 (magic) + 1 (version) + 1 (iv_len) + GCM_IV_BYTES。 */
    private static final int    HEADER_BYTES   = MAGIC.length + 1 + 1 + GCM_IV_BYTES;

    // ── 实例字段 ─────────────────────────────────────────────────────

    @NonNull
    private final String keyAlias;

    /**
     * 使用默认别名 {@link #DEFAULT_KEY_ALIAS} 构造。
     * 推荐在应用范围内仅持有一个实例（例如由 DI 容器或 Application 提供）。
     */
    public CipherEngine() {
        this(DEFAULT_KEY_ALIAS);
    }

    /**
     * 自定义别名构造，主要用于隔离测试或多租户场景。
     * @param keyAlias 非空，调用方负责保证其 ASCII 安全且全局唯一。
     */
    @VisibleForTesting
    public CipherEngine(@NonNull final String keyAlias) {
        if (keyAlias.isEmpty()) {
            throw new IllegalArgumentException("keyAlias must not be empty");
        }
        this.keyAlias = keyAlias;
    }

    // ── 公共 API ────────────────────────────────────────────────────

    /**
     * 加密给定明文。
     *
     * @param plaintext 非空字节数组，可以是空数组（返回的容器仍带认证 tag，可解密为 0 字节）。
     * @return 自描述的 V1 容器字节流，可直接落盘或传输。
     * @throws CryptoException 当 KeyStore 不可用、密钥被失效或底层加密失败时抛出。
     */
    @AnyThread
    @NonNull
    public byte[] encrypt(@NonNull final byte[] plaintext) throws CryptoException {
        try {
            final SecretKey key = obtainOrCreateKey();
            final Cipher    cipher = Cipher.getInstance(TRANSFORMATION);
            // 不传 ParameterSpec —— 强制让 AndroidKeyStore 用其内部 RNG 自行生成 IV，
            // 杜绝调用方误用静态/递增 IV 导致的 GCM 灾难性失效。
            cipher.init(Cipher.ENCRYPT_MODE, key);

            final byte[] iv = cipher.getIV();
            if (iv == null || iv.length != GCM_IV_BYTES) {
                throw new CryptoException(
                        CryptoException.UNEXPECTED,
                        "Provider returned IV with unexpected length: "
                                + (iv == null ? "null" : iv.length));
            }

            final byte[] ciphertext = cipher.doFinal(plaintext);
            return packContainer(iv, ciphertext);

        } catch (KeyPermanentlyInvalidatedException e) {
            throw new CryptoException(CryptoException.KEY_INVALIDATED,
                    "AES key invalidated by lockscreen change; historical ciphertexts unrecoverable.",
                    e);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(CryptoException.UNEXPECTED,
                    "encrypt() failed: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * 解密由 {@link #encrypt(byte[])} 产出的 V1 容器。
     *
     * @param ciphertext 完整容器字节流，长度至少 {@code HEADER_BYTES + 16}。
     * @return 原始明文。
     * @throws CryptoException 任意一种失败均归一为本类型异常，并附 {@link CryptoException#code}：
     * <ul>
     *   <li>{@link CryptoException#CORRUPTED} —— magic/版本/长度校验失败，
     *       通常意味着文件被截断、被替换或非本引擎产物。</li>
     *   <li>{@link CryptoException#TAMPERED} —— GCM Tag 校验失败（{@link
     *       javax.crypto.AEADBadTagException}），表明密文被篡改或密钥不匹配。</li>
     *   <li>{@link CryptoException#KEY_INVALIDATED} —— 密钥已因锁屏变化失效，
     *       调用方应清理历史快照并重建。</li>
     *   <li>{@link CryptoException#UNEXPECTED} —— 其它运行时错误。</li>
     * </ul>
     */
    @AnyThread
    @NonNull
    public byte[] decrypt(@NonNull final byte[] ciphertext) throws CryptoException {
        if (ciphertext.length < HEADER_BYTES + (GCM_TAG_BITS / 8)) {
            throw new CryptoException(CryptoException.CORRUPTED,
                    "Ciphertext too short: " + ciphertext.length);
        }
        // 校验魔数
        for (int i = 0; i < MAGIC.length; i++) {
            if (ciphertext[i] != MAGIC[i]) {
                throw new CryptoException(CryptoException.CORRUPTED,
                        "Bad magic at offset " + i);
            }
        }
        final byte version = ciphertext[MAGIC.length];
        if (version != CONTAINER_V1) {
            throw new CryptoException(CryptoException.CORRUPTED,
                    "Unsupported container version: " + (version & 0xFF));
        }
        final int ivLen = ciphertext[MAGIC.length + 1] & 0xFF;
        if (ivLen != GCM_IV_BYTES) {
            throw new CryptoException(CryptoException.CORRUPTED,
                    "Unexpected IV length: " + ivLen);
        }

        final byte[] iv     = new byte[GCM_IV_BYTES];
        System.arraycopy(ciphertext, HEADER_BYTES - GCM_IV_BYTES, iv, 0, GCM_IV_BYTES);
        final int    bodyOff = HEADER_BYTES;
        final int    bodyLen = ciphertext.length - HEADER_BYTES;

        try {
            final SecretKey key    = obtainOrCreateKey();
            final Cipher    cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext, bodyOff, bodyLen);

        } catch (KeyPermanentlyInvalidatedException e) {
            throw new CryptoException(CryptoException.KEY_INVALIDATED,
                    "AES key invalidated; cannot decrypt historical snapshot.", e);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new CryptoException(CryptoException.TAMPERED,
                    "GCM authentication tag mismatch: ciphertext tampered or key mismatch.", e);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(CryptoException.UNEXPECTED,
                    "decrypt() failed: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * 显式删除 KeyStore 中的密钥。
     *
     * <p>当 {@link CryptoException#KEY_INVALIDATED} 发生后，调用方应在清理历史
     * 密文的同时调用本方法，使下一次 {@link #encrypt(byte[])} 能透明地生成新密钥。</p>
     *
     * @return true 表示别名存在并已删除；false 表示别名本就不存在或 KeyStore 报错。
     */
    @AnyThread
    public boolean deleteKey() {
        try {
            final KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            if (ks.containsAlias(keyAlias)) {
                ks.deleteEntry(keyAlias);
                return true;
            }
            return false;
        } catch (KeyStoreException | NoSuchAlgorithmException
                 | CertificateException | IOException e) {
            return false;
        }
    }

    /**
     * 是否已在 KeyStore 中持有该别名的密钥（仅用于诊断/UI 展示，不影响加解密语义）。
     */
    @AnyThread
    public boolean hasKey() {
        try {
            final KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            return ks.containsAlias(keyAlias);
        } catch (GeneralSecurityException | IOException e) {
            return false;
        }
    }

    // ── 内部工具 ─────────────────────────────────────────────────────

    /**
     * 获取既有密钥；不存在则创建。
     *
     * <p>注意：KeyStore 不要求线程同步 —— 重复创建同名密钥会被 {@link KeyGenerator}
     * 内部 idempotent 地处理（先删后建），但实际生产中并发竞争极少出现，因此本类不加锁。</p>
     */
    @NonNull
    private SecretKey obtainOrCreateKey()
            throws GeneralSecurityException, IOException {

        final KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);

        if (ks.containsAlias(keyAlias)) {
            try {
                final KeyStore.Entry entry = ks.getEntry(keyAlias, null);
                if (entry instanceof KeyStore.SecretKeyEntry) {
                    return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                }
                // 类型异常 —— 例如别名被外部代码当成非对称密钥写入 —— 删除后重建
                ks.deleteEntry(keyAlias);
            } catch (UnrecoverableKeyException e) {
                // 密钥实体存在但已不可读（多发生于跨设备恢复或 KeyStore 损坏）。
                // 删除后重建是唯一可行恢复路径；旧密文不可恢复。
                ks.deleteEntry(keyAlias);
            }
        }
        return generateKey();
    }

    @NonNull
    private SecretKey generateKey()
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   java.security.InvalidAlgorithmParameterException {

        final KeyGenerator kg =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);

        final KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(KEY_SIZE_BITS)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                // 显式禁止由调用方提供 IV：与 encrypt() 中 cipher.getIV() 路径配合，
                // 强制使用 KeyStore 内部 RNG，杜绝静态 IV 漏洞。
                .setRandomizedEncryptionRequired(true)
                .build();

        kg.init(spec);
        return kg.generateKey();
    }

    @NonNull
    private static byte[] packContainer(@NonNull final byte[] iv, @NonNull final byte[] body) {
        final ByteBuffer buf = ByteBuffer.allocate(HEADER_BYTES + body.length);
        buf.put(MAGIC);
        buf.put(CONTAINER_V1);
        buf.put((byte) GCM_IV_BYTES);
        buf.put(iv);
        buf.put(body);
        return buf.array();
    }

    // ── 异常类型 ─────────────────────────────────────────────────────

    /**
     * 加解密统一异常类型，附带语义化错误码，便于上层做差异化处理：
     * <ul>
     *   <li>对 {@link #KEY_INVALIDATED} 应清理历史密文并允许引擎重建密钥；</li>
     *   <li>对 {@link #CORRUPTED} 应仅丢弃当前文件、保留其它历史；</li>
     *   <li>对 {@link #TAMPERED} 应触发安全告警（可能存在外部攻击）；</li>
     *   <li>对 {@link #UNEXPECTED} 通常需要人工介入或重试。</li>
     * </ul>
     */
    public static final class CryptoException extends Exception {

        public static final int UNEXPECTED      = 0;
        public static final int CORRUPTED       = 1;
        public static final int TAMPERED        = 2;
        public static final int KEY_INVALIDATED = 3;

        public final int code;

        public CryptoException(final int code, @NonNull final String msg) {
            super(msg);
            this.code = code;
        }

        public CryptoException(final int code, @NonNull final String msg,
                               @NonNull final Throwable cause) {
            super(msg, cause);
            this.code = code;
        }
    }
}
