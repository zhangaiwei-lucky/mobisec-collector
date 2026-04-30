package com.ucas.infocollect.collector.security.binary;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * {@link ApkSignatureParser} 的标准实现——基于 {@link FileChannel} + {@link ByteBuffer}
 * 的低拷贝（Low-Copy）二进制解析引擎。
 *
 * <h2>解析流水线（The Pipeline）</h2>
 * <pre>
 *  ┌──────────────────────────────────────────────────────────────────────────┐
 *  │  parse(apkFile)                                                          │
 *  │    │                                                                     │
 *  │    ├─ [Step 0] V1 Detection                                              │
 *  │    │    └── ZipFile.entries() → META-INF/*.RSA|.DSA|.EC                 │
 *  │    │                                                                     │
 *  │    └─ [Step 1-4] Modern Signature Block Detection (FileChannel path)     │
 *  │         │                                                                │
 *  │         ├─ [Step 1] findEocdOffset()                                     │
 *  │         │    └── Read tail ≤ 65557 bytes once; scan backwards for        │
 *  │         │        0x06054b50 with comment-length cross-validation          │
 *  │         │                                                                │
 *  │         ├─ [Step 2] readCentralDirOffset()                               │
 *  │         │    └── Read EOCD record (22 bytes); extract CD offset @EOCD+16 │
 *  │         │                                                                │
 *  │         ├─ [Step 3] readAndVerifySigningBlockFooter()                    │
 *  │         │    └── Read 24-byte footer before CD; verify magic +           │
 *  │         │        size consistency between header and footer              │
 *  │         │                                                                │
 *  │         └─ [Step 4] parseBlockEntries()                                  │
 *  │              └── Stream through ID-value pairs; O(1) memory per entry   │
 *  │                  Identify V2 (0x7109871a) / V3 (0xf05368c0)             │
 *  └──────────────────────────────────────────────────────────────────────────┘
 * </pre>
 *
 * <h2>内存策略</h2>
 * <ul>
 *   <li>仅分配五类小型 {@link ByteBuffer}：尾部扫描缓冲（≤ 64 KB）、
 *       EOCD 记录缓冲（22 B）、Signing Block 页脚缓冲（24 B）、
 *       块头部 size 缓冲（8 B）、条目头部缓冲（12 B）。</li>
 *   <li>Signing Block 的 value 字节通过 {@link FileChannel#position} 跳过，
 *       永远不进入内存。</li>
 *   <li>条目头部缓冲在循环中复用（{@code clear()} 重置，不重新分配）。</li>
 * </ul>
 *
 * <h2>线程安全性</h2>
 * 实现类无任何实例状态，{@link #parse} 可被并发安全地复用。
 * 每次调用均在内部独立的 {@link RandomAccessFile} / {@link FileChannel} 上操作。
 */
public final class DefaultApkSignatureParser implements ApkSignatureParser {

    // ─────────────────────────────────────────────────────────────────────────
    // §1  ZIP EOCD (End of Central Directory) 常量
    // ─────────────────────────────────────────────────────────────────────────

    /** ZIP EOCD 签名魔数：bytes = 50 4B 05 06（little-endian 表示为 0x06054B50）。 */
    private static final int EOCD_MAGIC = 0x06054B50;

    /** EOCD 记录的固定长度（不含文件注释），单位：字节。 */
    private static final int EOCD_FIXED_SIZE = 22;

    /** ZIP 规范允许的最大文件注释长度，单位：字节（uint16 最大值）。 */
    private static final int EOCD_MAX_COMMENT_SIZE = 65535;

    /**
     * 尾部扫描区间上限 = 固定 EOCD 大小 + 最大注释长度。
     * 任何有效 EOCD 必然落在文件末尾的此范围内。
     */
    private static final int EOCD_MAX_SCAN_SIZE = EOCD_FIXED_SIZE + EOCD_MAX_COMMENT_SIZE;

    // EOCD 记录内部字段偏移量（相对于 EOCD 记录起始位置）：
    /** magic 字段偏移量（4 字节）：0x06054B50。 */
    private static final int EOCD_OFF_MAGIC        = 0;
    /** Central Directory 起始偏移量字段（4 字节 uint32 LE），位于 EOCD+16。 */
    private static final int EOCD_OFF_CD_OFFSET    = 16;
    /** 文件注释长度字段（2 字节 uint16 LE），位于 EOCD+20。 */
    private static final int EOCD_OFF_COMMENT_LEN  = 20;

    // ─────────────────────────────────────────────────────────────────────────
    // §2  APK Signing Block 常量
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * APK Signing Block 魔数低 8 字节（小端）：
     * ASCII "APK Sig " = 41 50 4B 20 53 69 67 20 → LE uint64 = 0x20676953_204B5041。
     */
    private static final long SIG_BLOCK_MAGIC_LO = 0x20676953_204B5041L;

    /**
     * APK Signing Block 魔数高 8 字节（小端）：
     * ASCII "Block 42" = 42 6C 6F 63 6B 20 34 32 → LE uint64 = 0x3234206B_636F6C42。
     */
    private static final long SIG_BLOCK_MAGIC_HI = 0x3234206B_636F6C42L;

    /**
     * APK Signing Block 页脚（footer）大小：
     * sizeOfBlock(8 B) + magic_lo(8 B) + magic_hi(8 B) = 24 B。
     * 该 24 字节紧邻 Central Directory 之前。
     */
    private static final int SIG_BLOCK_FOOTER_SIZE = 24;

    /**
     * APK Signing Block 最小合法总字节数 = 块头(8 B) + 页脚(24 B) = 32 B。
     * 即使 ID-value 对区域为空，整个块也必须至少占 32 字节。
     */
    private static final int SIG_BLOCK_MIN_TOTAL_SIZE = 32;

    /**
     * APK Signing Block 解析安全上限：8 MiB。
     * 超过此大小的块视为异常或恶意构造，拒绝解析。
     */
    private static final long SIG_BLOCK_MAX_TOTAL_SIZE = 8L * 1024L * 1024L;

    // Signing Block 页脚字段偏移量（相对于页脚缓冲区起始）：
    private static final int FOOTER_OFF_SIZE_FIELD = 0;   // 8 B — sizeOfBlock (不含前 8B)
    private static final int FOOTER_OFF_MAGIC_LO   = 8;   // 8 B — "APK Sig "
    private static final int FOOTER_OFF_MAGIC_HI   = 16;  // 8 B — "Block 42"

    // ─────────────────────────────────────────────────────────────────────────
    // §3  APK 签名方案 Block ID 常量
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * APK Signature Scheme v2 Block ID：0x7109871A。
     * 防止 Janus（CVE-2017-13156）攻击的最低现代签名门槛。
     */
    private static final int ID_V2 = 0x7109871A;

    /**
     * APK Signature Scheme v3 Block ID：0xF05368C0。
     * 支持 Android 9（API 28）引入的密钥轮换（Key Rotation）。
     */
    private static final int ID_V3 = 0xF05368C0;

    /**
     * APK Signature Scheme v3.1 Block ID：0x1B93AD61。
     * v3 的扩展版本，允许对特定 SDK 范围应用不同的轮换密钥。
     */
    private static final int ID_V3_1 = 0x1B93AD61;

    // ─────────────────────────────────────────────────────────────────────────
    // §4  I/O 相关常量
    // ─────────────────────────────────────────────────────────────────────────

    /** 条目头部读取宽度：entryLen(8 B) + id(4 B) = 12 B，每次迭代读一次。 */
    private static final int ENTRY_HEADER_SIZE = 12;

    /** 通用小型字段缓冲区大小（uint64 最大宽度）：8 字节。 */
    private static final int UINT64_SIZE = 8;

    // ─────────────────────────────────────────────────────────────────────────
    // §5  公开入口
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * {@inheritDoc}
     *
     * <p>执行完整的四阶段解析流水线（见类级注释）。
     * 任何 I/O 错误或结构违规均通过 {@link ApkParseException} 抛出，
     * 不返回 null 或部分填充的对象。</p>
     */
    @NonNull
    @Override
    public ApkSignatureInfo parse(@NonNull final File apkFile) throws ApkParseException {
        guardFileAccessible(apkFile);

        // Step 0：V1 通过 ZipFile 中央目录枚举，与 FileChannel 路径完全解耦。
        final boolean hasV1 = detectV1Signature(apkFile);

        // Step 1-4：现代签名块检测，使用 FileChannel 低拷贝路径。
        try (final RandomAccessFile raf     = new RandomAccessFile(apkFile, "r");
             final FileChannel      channel = raf.getChannel()) {

            final long fileSize = channel.size();
            guardMinFileSize(fileSize);

            final SigningBlockSummary summary = detectSigningBlock(channel, fileSize);

            return new ApkSignatureInfo(
                    hasV1,
                    summary.hasV2,
                    summary.hasV3,
                    null,                  // V4 需检查独立 .apk.idsig 文件，本实现不覆盖
                    summary.confidence,
                    summary.note);

        } catch (final ApkParseException e) {
            throw e;
        } catch (final IOException e) {
            throw new ApkParseException(
                    ApkParseException.Reason.IO_ERROR,
                    "I/O failure while parsing APK [" + apkFile.getName() + "]: " + e.getMessage(),
                    e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §6  Step 0 — V1 签名检测（ZipFile 路径）
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 通过枚举 ZIP 中央目录条目检测 V1（JAR）签名迹象。
     *
     * <p>{@link ZipFile} 直接解析中央目录，不将 Entry 数据加载入内存，
     * 内存消耗与 APK 大小无关。</p>
     *
     * <p>检测依据：V1 签名强制在 {@code META-INF/} 下生成 {@code *.RSA}、
     * {@code *.DSA} 或 {@code *.EC} 三类证书块文件。若至少存在其一，
     * 即认为 V1 签名迹象存在。</p>
     */
    private boolean detectV1Signature(@NonNull final File apkFile) throws ApkParseException {
        try (final ZipFile zipFile = new ZipFile(apkFile)) {
            final Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                final ZipEntry entry = entries.nextElement();
                final String   name  = entry.getName();
                if (name == null) continue;
                final String upper = name.toUpperCase(Locale.ROOT);
                if (upper.startsWith("META-INF/")
                        && (upper.endsWith(".RSA")
                        ||  upper.endsWith(".DSA")
                        ||  upper.endsWith(".EC"))) {
                    return true;
                }
            }
            return false;
        } catch (final IOException e) {
            throw new ApkParseException(
                    ApkParseException.Reason.IO_ERROR,
                    "Cannot open APK as ZIP for V1 detection: " + e.getMessage(),
                    e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §7  Steps 1-4 编排器
    // ─────────────────────────────────────────────────────────────────────────

    @NonNull
    private SigningBlockSummary detectSigningBlock(
            @NonNull final FileChannel channel,
            final long fileSize) throws IOException, ApkParseException {

        // Step 1
        final long eocdOffset = findEocdOffset(channel, fileSize);

        // Step 2
        final long cdOffset = readCentralDirOffset(channel, eocdOffset, fileSize);

        // Step 3：若 CD 之前没有足够空间放置页脚，则确定不存在 Signing Block。
        if (cdOffset < SIG_BLOCK_FOOTER_SIZE) {
            return SigningBlockSummary.absent("No APK Signing Block: insufficient space before Central Directory");
        }

        final long totalBlockSize = readAndVerifySigningBlockFooter(channel, cdOffset);
        if (totalBlockSize == 0L) {
            // 页脚魔数未命中——合法状态（V1-only APK 或未签名）。
            return SigningBlockSummary.absent("No APK Signing Block magic found before Central Directory");
        }

        // Step 4
        final long blockStart = cdOffset - totalBlockSize;
        guardNonNegative(blockStart,
                "Signing Block start offset is negative (cdOffset="
                + cdOffset + ", totalBlockSize=" + totalBlockSize + ")");

        return parseBlockEntries(channel, blockStart, cdOffset);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §8  Step 1 — EOCD 定位（尾部反向扫描）
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 从文件末尾向前扫描，精确定位 ZIP EOCD 记录的起始文件偏移量。
     *
     * <h3>扫描策略</h3>
     * <ol>
     *   <li>一次性读取文件末尾 {@code min(fileSize, 65557)} 字节到尾部缓冲区。</li>
     *   <li>从缓冲区尾部向前迭代每个 4 字节对齐候选位置，检查是否等于
     *       {@link #EOCD_MAGIC}（{@code 0x06054B50}）。</li>
     *   <li>对每个命中的候选位置，读取注释长度字段（{@code uint16} at offset+20），
     *       验证 {@code candidatePos + EOCD_FIXED_SIZE + commentLen == fileSize}。
     *       此交叉验证排除文件内容中偶然出现的魔数伪命中（False Positive）。</li>
     *   <li>取最靠近文件末尾的合法候选，即为 EOCD 起始偏移。</li>
     * </ol>
     *
     * <p>缓冲区 {@link ByteOrder} 设置为 {@link ByteOrder#LITTLE_ENDIAN}，
     * 保证 {@link ByteBuffer#getInt}/{@link ByteBuffer#getShort} 的端序语义与
     * ZIP 规范一致。</p>
     *
     * @throws ApkParseException 如果扫描范围内不存在任何合法 EOCD 记录
     */
    private long findEocdOffset(
            @NonNull final FileChannel channel,
            final long fileSize) throws IOException, ApkParseException {

        final int  scanSize  = (int) Math.min(fileSize, EOCD_MAX_SCAN_SIZE);
        final long tailStart = fileSize - scanSize;

        // 一次性读取尾部区间，避免逐字节 seek——O(1) I/O 操作。
        final ByteBuffer tailBuf = ByteBuffer.allocate(scanSize);
        tailBuf.order(ByteOrder.LITTLE_ENDIAN);
        channel.position(tailStart);
        readFully(channel, tailBuf);

        // 反向扫描：EOCD 至少需要 EOCD_FIXED_SIZE 字节，故候选范围为
        // [0, scanSize - EOCD_FIXED_SIZE]（含两端）。
        for (int i = scanSize - EOCD_FIXED_SIZE; i >= 0; i--) {
            // 使用绝对 get，不移动 position，避免意外影响后续读取。
            if (tailBuf.getInt(i) != EOCD_MAGIC) {
                continue;
            }

            // 候选命中：交叉验证注释长度字段。
            // tailBuf.getShort() 返回有符号 short，需 & 0xFFFF 升为无符号整数。
            final int commentLen      = tailBuf.getShort(i + EOCD_OFF_COMMENT_LEN) & 0xFFFF;
            final int expectedTailEnd = i + EOCD_FIXED_SIZE + commentLen;

            if (expectedTailEnd == scanSize) {
                // 注释长度与实际文件尾距离吻合——合法 EOCD。
                return tailStart + i;
            }
            // 不吻合：继续向前扫描，寻找更靠前的候选（处理注释内含伪魔数情况）。
        }

        throw new ApkParseException(
                ApkParseException.Reason.MALFORMED_STRUCTURE,
                "No valid ZIP EOCD found in the last " + scanSize + " bytes"
                + " (fileSize=" + fileSize + "). File may be corrupt or not a valid ZIP/APK.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §9  Step 2 — 解析 Central Directory 偏移量
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 从已定位的 EOCD 记录中读取 Central Directory 的起始文件偏移量。
     *
     * <p>CD 偏移量是 EOCD 内的 {@code uint32 LE} 字段，位于 EOCD+16。
     * 读取后提升为 {@code long}（{@code & 0xFFFFFFFFL}）避免符号扩展。</p>
     *
     * <p>合法性约束：</p>
     * <ul>
     *   <li>{@code 0 <= cdOffset <= eocdOffset}（CD 必须在 EOCD 之前）。</li>
     *   <li>{@code cdOffset < fileSize}（CD 不能超出文件边界）。</li>
     * </ul>
     */
    private long readCentralDirOffset(
            @NonNull final FileChannel channel,
            final long eocdOffset,
            final long fileSize) throws IOException, ApkParseException {

        // 验证：EOCD 记录必须完整落在文件边界内。
        guardOffsetRange(eocdOffset, EOCD_FIXED_SIZE, fileSize,
                "EOCD record extends beyond file boundary");

        final ByteBuffer eocdBuf = ByteBuffer.allocate(EOCD_FIXED_SIZE);
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN);
        channel.position(eocdOffset);
        readFully(channel, eocdBuf);

        // 二次校验魔数（防止并发文件修改导致数据错位）。
        if (eocdBuf.getInt(EOCD_OFF_MAGIC) != EOCD_MAGIC) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "EOCD magic mismatch at 0x" + Long.toHexString(eocdOffset)
                    + " on re-read (file may have been modified concurrently)");
        }

        // uint32 LE → long（无符号提升）。
        final long cdOffset = eocdBuf.getInt(EOCD_OFF_CD_OFFSET) & 0xFFFFFFFFL;

        if (cdOffset > eocdOffset) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "Central Directory offset (0x" + Long.toHexString(cdOffset)
                    + ") exceeds EOCD offset (0x" + Long.toHexString(eocdOffset)
                    + "). EOCD must follow Central Directory.");
        }
        if (cdOffset >= fileSize) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "Central Directory offset (0x" + Long.toHexString(cdOffset)
                    + ") is at or beyond file size (" + fileSize + ")");
        }

        return cdOffset;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §10  Step 3 — APK Signing Block 页脚魔数验证与块大小读取
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 读取 Central Directory 之前的 24 字节 Signing Block 页脚，
     * 验证魔数，并返回经过一致性校验的块总大小。
     *
     * <h3>页脚布局（相对于 {@code cdOffset - 24}）</h3>
     * <pre>
     *   偏移  大小  字段
     *   ───── ───── ──────────────────────────────────────────────────────────
     *   0      8 B  sizeOfBlock（uint64 LE）— 块总字节数减去前 8 字节
     *   8      8 B  magic_lo = 0x20676953_204B5041（"APK Sig "）
     *   16     8 B  magic_hi = 0x3234206B_636F6C42（"Block 42"）
     * </pre>
     *
     * <p>额外一致性校验：在块起始位置（{@code cdOffset - totalBlockSize}）
     * 再次读取 {@code sizeOfBlock} 字段，与页脚值比对。任何不一致均视为
     * 块结构损坏。</p>
     *
     * @return 经过验证的块总字节数（{@code sizeOfBlock + 8}）；
     *         若魔数不存在则返回 {@code 0L}（合法：无 Signing Block）。
     * @throws ApkParseException 魔数存在但结构字段非法或前后 size 不一致时抛出。
     */
    private long readAndVerifySigningBlockFooter(
            @NonNull final FileChannel channel,
            final long cdOffset) throws IOException, ApkParseException {

        final long footerStart = cdOffset - SIG_BLOCK_FOOTER_SIZE;

        final ByteBuffer footer = ByteBuffer.allocate(SIG_BLOCK_FOOTER_SIZE);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        channel.position(footerStart);
        readFully(channel, footer);

        // 魔数检查——不符合则认为无 Signing Block（V1-only 或未签名 APK 的正常状态）。
        final long magicLo = footer.getLong(FOOTER_OFF_MAGIC_LO);
        final long magicHi = footer.getLong(FOOTER_OFF_MAGIC_HI);
        if (magicLo != SIG_BLOCK_MAGIC_LO || magicHi != SIG_BLOCK_MAGIC_HI) {
            return 0L;
        }

        // 读取 sizeOfBlock（页脚版本）。
        // sizeOfBlock = totalBlockSize - 8（不含第一个 size 字段自身的 8 字节）。
        final long sizeOfBlock = footer.getLong(FOOTER_OFF_SIZE_FIELD);

        // 合法性：块最小总大小为 32 B（头 8B + 页脚 24B），故 sizeOfBlock >= 24。
        if (sizeOfBlock < SIG_BLOCK_MIN_TOTAL_SIZE - UINT64_SIZE) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "APK Signing Block sizeOfBlock=" + sizeOfBlock
                    + " is below minimum valid value of "
                    + (SIG_BLOCK_MIN_TOTAL_SIZE - UINT64_SIZE));
        }

        final long totalBlockSize = sizeOfBlock + UINT64_SIZE;  // 加上头部 size 字段本身

        if (totalBlockSize > SIG_BLOCK_MAX_TOTAL_SIZE) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "APK Signing Block size (" + totalBlockSize + " B)"
                    + " exceeds safety limit of " + SIG_BLOCK_MAX_TOTAL_SIZE + " B."
                    + " Refusing to parse — possible crafted/corrupt file.");
        }

        // 计算块起始偏移并验证不为负。
        final long blockStart = cdOffset - totalBlockSize;
        guardNonNegative(blockStart,
                "Signing Block start offset is negative (cdOffset=" + cdOffset
                + ", totalBlockSize=" + totalBlockSize + ")");

        // 一致性校验：从块头部再读一次 sizeOfBlock，与页脚值比对。
        final ByteBuffer headerSizeBuf = ByteBuffer.allocate(UINT64_SIZE);
        headerSizeBuf.order(ByteOrder.LITTLE_ENDIAN);
        channel.position(blockStart);
        readFully(channel, headerSizeBuf);

        final long headerSizeField = headerSizeBuf.getLong(0);
        if (headerSizeField != sizeOfBlock) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "APK Signing Block size mismatch: header=" + headerSizeField
                    + ", footer=" + sizeOfBlock
                    + ". Block is likely corrupt (truncated write or bit-flip).");
        }

        return totalBlockSize;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §11  Step 4 — ID-Value 键值对迭代
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 以流式方式迭代 APK Signing Block 内的 ID-value 键值对，
     * 识别是否存在 V2 / V3 / V3.1 签名方案的 Block ID。
     *
     * <h3>ID-Value 对格式（每条目）</h3>
     * <pre>
     *   偏移  大小  字段
     *   ───── ───── ──────────────────────────────────────────────────────────
     *   0      8 B  entryLen（uint64 LE）— 后续 id+value 的合计字节数
     *   8      4 B  id（uint32 LE）— 签名方案或辅助数据的 Block ID
     *   12   entryLen-4 B  value（不透明，本实现直接跳过）
     * </pre>
     *
     * <h3>内存策略</h3>
     * 每次迭代仅读取 12 字节的条目头部（{@link #ENTRY_HEADER_SIZE}），
     * 通过 {@link FileChannel#position} 跳过 value 字节，不将任何 value
     * 数据装载入内存，内存使用与 Signing Block 大小无关。
     *
     * <h3>遍历区间</h3>
     * <pre>
     *   entriesStart = blockStart + 8              （跳过头部 sizeOfBlock 字段）
     *   entriesEnd   = cdOffset   - SIG_BLOCK_FOOTER_SIZE  （页脚前）
     * </pre>
     */
    @NonNull
    private SigningBlockSummary parseBlockEntries(
            @NonNull final FileChannel channel,
            final long blockStart,
            final long cdOffset) throws IOException, ApkParseException {

        final long entriesStart = blockStart + UINT64_SIZE;          // 跳过头部 size(8B)
        final long entriesEnd   = cdOffset   - SIG_BLOCK_FOOTER_SIZE; // 页脚之前

        if (entriesStart >= entriesEnd) {
            // 合法但罕见：Signing Block 存在但 ID-value 区域为空。
            return new SigningBlockSummary(
                    false, false,
                    ApkSignatureInfo.Confidence.HIGH,
                    "APK Signing Block present but contains no ID-value entries");
        }

        boolean hasV2 = false;
        boolean hasV3 = false;
        long    cursor = entriesStart;

        // 复用同一个 ByteBuffer 以避免每次迭代分配——clear() 重置 position/limit。
        final ByteBuffer entryHeaderBuf = ByteBuffer.allocate(ENTRY_HEADER_BYTES);
        entryHeaderBuf.order(ByteOrder.LITTLE_ENDIAN);

        while (cursor < entriesEnd) {

            // ── 边界预检：剩余空间必须能容纳完整的条目头部。
            final long remaining = entriesEnd - cursor;
            if (remaining < ENTRY_HEADER_BYTES) {
                throw new ApkParseException(
                        ApkParseException.Reason.MALFORMED_STRUCTURE,
                        "Signing Block entry at 0x" + Long.toHexString(cursor)
                        + " is truncated: only " + remaining
                        + " B remain before entries region end (0x"
                        + Long.toHexString(entriesEnd) + ")");
            }

            // ── 读取条目头部：entryLen(8B) + id(4B)。
            entryHeaderBuf.clear();
            channel.position(cursor);
            readFully(channel, entryHeaderBuf);

            final long entryLen = entryHeaderBuf.getLong(0);
            final int  id       = entryHeaderBuf.getInt(8);

            // ── 验证 entryLen 合法性。

            // uint64 在 Java 中可能溢出为负数（当最高位为 1 时）。
            if (entryLen < 0) {
                throw new ApkParseException(
                        ApkParseException.Reason.MALFORMED_STRUCTURE,
                        "Signing Block entry at 0x" + Long.toHexString(cursor)
                        + " has entryLen=" + Long.toUnsignedString(entryLen)
                        + " (uint64 overflow into signed range — crafted file?)");
            }
            // entryLen 最小为 4（至少包含 id 字段本身）。
            if (entryLen < 4) {
                throw new ApkParseException(
                        ApkParseException.Reason.MALFORMED_STRUCTURE,
                        "Signing Block entry at 0x" + Long.toHexString(cursor)
                        + " has entryLen=" + entryLen + " < 4 (minimum: id field alone)");
            }
            // cursor + 8(entryLen field) + entryLen 必须不超过 entriesEnd。
            // 等价检查：entryLen <= entriesEnd - cursor - 8。
            final long maxAllowedEntryLen = entriesEnd - cursor - UINT64_SIZE;
            if (entryLen > maxAllowedEntryLen) {
                throw new ApkParseException(
                        ApkParseException.Reason.MALFORMED_STRUCTURE,
                        "Signing Block entry at 0x" + Long.toHexString(cursor)
                        + " with entryLen=" + entryLen
                        + " extends beyond entries region end 0x"
                        + Long.toHexString(entriesEnd)
                        + " (maxAllowed=" + maxAllowedEntryLen + ")");
            }

            // ── 按 Block ID 识别签名方案。
            // V2 Block ID 0x7109871A：APK Signature Scheme v2（Android 7.0+）
            if (id == ID_V2) {
                hasV2 = true;
            }
            // V3 Block ID 0xF05368C0：APK Signature Scheme v3（Android 9.0+）
            // V3.1 Block ID 0x1B93AD61：APK Signature Scheme v3.1（轮换密钥扩展）
            else if (id == ID_V3 || id == ID_V3_1) {
                hasV3 = true;
            }
            // 其余 Block ID（如 Verity Padding 0x42726577、Source Stamp 0x2B09189E 等）
            // 无需识别，直接跳过。

            // ── 推进游标：跳过整个条目（8B size字段 + entryLen 字节内容）。
            cursor += UINT64_SIZE + entryLen;
        }

        // 生成人类可读注释。
        final String note;
        if      (hasV2 && hasV3) note = "APK Signing Block parsed: V2 + V3 schemes present";
        else if (hasV3)          note = "APK Signing Block parsed: V3 scheme present";
        else if (hasV2)          note = "APK Signing Block parsed: V2 scheme present";
        else                     note = "APK Signing Block parsed: no V2/V3 scheme Block IDs found";

        return new SigningBlockSummary(hasV2, hasV3, ApkSignatureInfo.Confidence.HIGH, note);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §12  I/O 工具方法
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * 从 {@code channel} 精确读取 {@code buf.remaining()} 字节，然后 {@code flip()}。
     *
     * <p>单次 {@link FileChannel#read} 不保证读满缓冲区，此方法循环直至填满。
     * 遇到 EOF（{@code read == -1}）时抛出 {@link IOException}。</p>
     */
    private static void readFully(
            @NonNull final FileChannel channel,
            @NonNull final ByteBuffer  buf) throws IOException {
        while (buf.hasRemaining()) {
            final int read = channel.read(buf);
            if (read == -1) {
                throw new IOException(
                        "Unexpected EOF: needed " + buf.limit()
                        + " B but only " + (buf.limit() - buf.remaining()) + " B were available");
            }
        }
        buf.flip();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §13  防御性边界检查工具方法
    // ─────────────────────────────────────────────────────────────────────────

    /** 断言文件可读，否则抛出 {@link ApkParseException.Reason#IO_ERROR}。 */
    private static void guardFileAccessible(@NonNull final File file) throws ApkParseException {
        if (!file.exists()) {
            throw new ApkParseException(
                    ApkParseException.Reason.IO_ERROR,
                    "APK file does not exist: " + file.getAbsolutePath());
        }
        if (!file.canRead()) {
            throw new ApkParseException(
                    ApkParseException.Reason.IO_ERROR,
                    "APK file is not readable (permission denied?): " + file.getAbsolutePath());
        }
    }

    /** 断言 {@code fileSize >= EOCD_FIXED_SIZE}，否则文件太小不可能是合法 ZIP。 */
    private static void guardMinFileSize(final long fileSize) throws ApkParseException {
        if (fileSize < EOCD_FIXED_SIZE) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    "File size (" + fileSize + " B) is less than minimum EOCD size ("
                    + EOCD_FIXED_SIZE + " B). Not a valid ZIP/APK.");
        }
    }

    /**
     * 断言 {@code [offset, offset+length)} 完整落在 {@code [0, fileSize)} 范围内。
     *
     * @param message 错误描述前缀，追加实际偏移值后一并写入异常消息。
     */
    private static void guardOffsetRange(
            final long offset,
            final long length,
            final long fileSize,
            @NonNull final String message) throws ApkParseException {
        if (offset < 0 || length < 0 || offset + length > fileSize) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    message + " (offset=0x" + Long.toHexString(offset)
                    + ", length=" + length + ", fileSize=" + fileSize + ")");
        }
    }

    /** 断言 {@code value >= 0}，用于防止偏移量计算溢出为负值。 */
    private static void guardNonNegative(
            final long value,
            @NonNull final String message) throws ApkParseException {
        if (value < 0) {
            throw new ApkParseException(
                    ApkParseException.Reason.MALFORMED_STRUCTURE,
                    message + " (computed value=" + value + ")");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §14  内部传值对象
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * {@link #detectSigningBlock} → {@link #parseBlockEntries} 之间的内部传值对象。
     * 不对外暴露，仅用于在流水线各阶段间传递中间结果。
     */
    private static final class SigningBlockSummary {

        final boolean                  hasV2;
        final boolean                  hasV3;
        final ApkSignatureInfo.Confidence confidence;
        final String                   note;

        SigningBlockSummary(
                final boolean hasV2,
                final boolean hasV3,
                final ApkSignatureInfo.Confidence confidence,
                @NonNull final String note) {
            this.hasV2       = hasV2;
            this.hasV3       = hasV3;
            this.confidence  = confidence;
            this.note        = note;
        }

        /** 工厂方法：无 Signing Block 的确定结果（置信度 HIGH，V2/V3 均为 false）。 */
        @NonNull
        static SigningBlockSummary absent(@NonNull final String reason) {
            return new SigningBlockSummary(false, false, ApkSignatureInfo.Confidence.HIGH, reason);
        }
    }
}
