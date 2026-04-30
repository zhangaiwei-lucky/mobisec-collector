package com.ucas.infocollect.collector.security.binary;

import androidx.annotation.NonNull;

import java.io.File;

/**
 * APK 二进制签名结构解析器契约。
 *
 * <p>此接口将"字节级文件解析"从业务扫描逻辑中彻底剥离。
 * 实现类（如 {@code ZipApkSignatureParser}）负责所有底层 I/O 操作
 * （ZIP EOCD 定位、APK Signing Block 遍历、LE 字节序读取），
 * 上层的 {@code ApkSignatureScanner} 只依赖本接口，不接触任何字节操作。</p>
 *
 * <h3>实现约定</h3>
 * <ol>
 *   <li>实现类必须是无状态的（Stateless），同一实例可被并发安全地复用。</li>
 *   <li>所有 I/O 资源（{@code RandomAccessFile}、{@code ZipFile}）必须在
 *       {@code parse} 调用完成后关闭，不得向调用方泄漏。</li>
 *   <li>实现类不得引用任何 Android 框架类；此接口及其实现应可在纯 JVM
 *       环境下测试（例如使用 JUnit 4 而无需 Robolectric）。</li>
 *   <li>任何结构性错误或 I/O 失败均通过 {@link ApkParseException} 抛出，
 *       不返回哨兵值（sentinel）或 null。</li>
 * </ol>
 *
 * <h3>协议层次（ZIP / APK Signing Block 规范）</h3>
 * <pre>
 *  ┌──────────────────────────────────────────────────────────────────┐
 *  │ APK 文件结构                                                      │
 *  ├───────────────────────┬──────────────────────────────────────────┤
 *  │ Contents of ZIP entry │ ZIP 数据区                                │
 *  ├───────────────────────┤                                          │
 *  │ APK Signing Block     │ 位于 Central Directory 之前（V2/V3/V4）   │
 *  │  ├ size_lo (8B LE)    │                                          │
 *  │  ├ id-value pairs ... │ 0x7109871a = V2, 0xf05368c0 = V3         │
 *  │  ├ size_hi (8B LE)    │                                          │
 *  │  └ magic (16B)        │ "APK Sig Block 42"                       │
 *  ├───────────────────────┤                                          │
 *  │ Central Directory     │ EOCD.centralDirOffset 指向此处             │
 *  ├───────────────────────┤                                          │
 *  │ EOCD (End of CD)      │ 0x06054b50 魔数，从文件尾向前搜索          │
 *  └───────────────────────┴──────────────────────────────────────────┘
 * </pre>
 */
public interface ApkSignatureParser {

    /**
     * 解析指定 APK 文件的签名方案信息。
     *
     * <p>实现须完成以下步骤（顺序不强制，但逻辑等价）：</p>
     * <ol>
     *   <li>V1 检测：以 ZIP 方式枚举条目，查找 {@code META-INF/*.RSA|.DSA|.EC}。</li>
     *   <li>EOCD 定位：从文件尾向前扫描 {@code 0x06054b50} 魔数。</li>
     *   <li>Central Directory 偏移读取：从 EOCD + 16 处读取 4 字节 LE 整数。</li>
     *   <li>APK Signing Block 魔数验证：在 Central Directory 偏移前 24 字节处
     *       检查 "APK Sig Block 42" 魔数（{@code 0x20676953_204b5041} ||
     *       {@code 0x3234206b_636f6c42}）。</li>
     *   <li>Block ID 遍历：迭代 id-value 对，识别 V2（{@code 0x7109871a}）
     *       和 V3/V3.1（{@code 0xf05368c0} / {@code 0x1b93ad61}）Block。</li>
     * </ol>
     *
     * @param apkFile 目标 APK 文件，调用方保证文件存在且可读
     * @return 包含各签名方案检测结果和置信度的不可变对象
     * @throws ApkParseException 文件 I/O 失败（{@link ApkParseException.Reason#IO_ERROR}）
     *                           或 ZIP/APK 结构不合规（{@link ApkParseException.Reason#MALFORMED_STRUCTURE}）
     */
    @NonNull
    ApkSignatureInfo parse(@NonNull File apkFile) throws ApkParseException;
}
