package com.ucas.infocollect.engine.sensor;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 信号处理纯函数集合。
 *
 * 设计原则：
 *   - 完全不依赖 Android 任何 API；可在普通 JVM 单元测试中直接覆盖。
 *   - 不持有状态、不分配除返回值以外的对象，避免 GC 抖动。
 *   - 输入约定：三轴样本以"交错存储"传入（[x0,y0,z0, x1,y1,z1, ...]），
 *     与 {@link SensorSamplingEngine} 内部预分配的录制缓冲布局一致，
 *     从而把整条采集→统计的链路打通而无需任何转置/复制。
 *
 * 注意：方差/标准差使用总体（population）公式，分母为 n 而非 n-1，
 * 以与 Phase 1 旧实现保持指纹哈希向后兼容。
 */
public final class SignalProcessingMath {

    /** 标准重力加速度（m/s²），用于 stripGravity / 残余偏差计算。 */
    public static final float STANDARD_GRAVITY = 9.80665f;

    /** 指纹相似度衰减尺度（约一倍器件级噪声，单位与特征向量一致）。 */
    public static final double SIMILARITY_SIGMA = 0.02;

    /** 分桶量化分辨率：1e-3 对应每轴 σ 的最小可分辨步长，足以吸收浮点尾噪。 */
    public static final double FEATURE_BUCKET_SCALE = 1000.0;

    /** 同一设备的硬阈值；< 此值的最近距离视为 MATCH。 */
    public static final double DIST_THRESHOLD_MATCH    = 0.01;
    public static final double DIST_THRESHOLD_LIKELY   = 0.05;
    public static final double DIST_THRESHOLD_UNLIKELY = 0.20;

    /** 指纹判定结果。 */
    public enum MatchLevel {
        MATCH,    // 同一设备
        LIKELY,   // 很可能是同一设备
        UNLIKELY, // 不太像同一设备
        NEW       // 新设备 / 历史不可比
    }

    private SignalProcessingMath() {}

    /** 三轴交错样本均值。要求 samples.length >= 3 * sampleCount。 */
    public static Vector3 meanXYZ(float[] samples, int sampleCount) {
        if (sampleCount <= 0) return Vector3.ZERO;
        double sx = 0d, sy = 0d, sz = 0d;
        int end = sampleCount * 3;
        for (int i = 0; i < end; i += 3) {
            sx += samples[i];
            sy += samples[i + 1];
            sz += samples[i + 2];
        }
        return new Vector3(
                (float) (sx / sampleCount),
                (float) (sy / sampleCount),
                (float) (sz / sampleCount));
    }

    /** 三轴交错样本的总体方差（分母为 n）。 */
    public static Vector3 varianceXYZ(float[] samples, int sampleCount, Vector3 mean) {
        if (sampleCount <= 0) return Vector3.ZERO;
        double vx = 0d, vy = 0d, vz = 0d;
        int end = sampleCount * 3;
        for (int i = 0; i < end; i += 3) {
            double dx = samples[i]     - mean.x;
            double dy = samples[i + 1] - mean.y;
            double dz = samples[i + 2] - mean.z;
            vx += dx * dx;
            vy += dy * dy;
            vz += dz * dz;
        }
        return new Vector3(
                (float) (vx / sampleCount),
                (float) (vy / sampleCount),
                (float) (vz / sampleCount));
    }

    /** 三轴交错样本的总体标准差。 */
    public static Vector3 stdDevXYZ(float[] samples, int sampleCount, Vector3 mean) {
        Vector3 v = varianceXYZ(samples, sampleCount, mean);
        return new Vector3(
                (float) Math.sqrt(v.x),
                (float) Math.sqrt(v.y),
                (float) Math.sqrt(v.z));
    }

    /** 标量序列均值。 */
    public static double meanScalar(float[] samples, int sampleCount) {
        if (sampleCount <= 0) return 0d;
        double sum = 0d;
        for (int i = 0; i < sampleCount; i++) sum += samples[i];
        return sum / sampleCount;
    }

    /** L2 欧几里得距离。两数组按较短长度比较。 */
    public static double euclideanDistance(double[] a, double[] b) {
        int n = Math.min(a.length, b.length);
        double sum = 0d;
        for (int i = 0; i < n; i++) {
            double d = a[i] - b[i];
            sum += d * d;
        }
        return Math.sqrt(sum);
    }

    // ── 指纹特征工程 ─────────────────────────────────────────────────

    /**
     * 把"含重力的"加速度均值变换为"剔除恒定 1g 后的残余分量"。
     *
     * 返回 {@code (mean.x, mean.y, |mean| - g)}：
     *   - x、y 保留是为了观察恒定 bias 与重力之外的偏移；
     *   - z 维度替换为模长偏差，使该分量与具体姿态无关
     *     （任何方向上都减去同一个 1g）。
     *
     * 注意：本函数只是诊断/单维"残余偏差"特征，姿态完全归一化建议配合
     * {@link #rotationFromTo} + {@link #rotateInterleaved} 使用。
     */
    public static Vector3 stripGravity(Vector3 mean) {
        return new Vector3(mean.x, mean.y, mean.magnitude() - STANDARD_GRAVITY);
    }

    /**
     * 计算"把单位向量 from 旋到单位向量 to"的旋转矩阵（行优先 3x3，长度 9）。
     *
     * 实现来自 Rodrigues 公式：R = I + K + K² · 1/(1+c)，
     * 其中 K 是 v=from×to 的叉乘反对称矩阵、c=from·to。
     *
     * 退化处理：
     *   - {@code from} 模长过小（如自由落体）→ 返回单位矩阵；
     *   - 反向（c ≈ -1）→ 选取一条与 from 大致垂直的轴，做 180° 翻转。
     *
     * @param from 任意非零向量（无需归一化，会内部归一化）
     * @param to   单位向量目标方向
     * @return 行优先 3x3 矩阵（长度 9 的 float 数组）
     */
    public static float[] rotationFromTo(Vector3 from, Vector3 to) {
        float[] R = new float[9];
        float fLen = from.magnitude();
        if (fLen < 1e-6f) {
            R[0] = 1f; R[4] = 1f; R[8] = 1f;
            return R;
        }
        float fx = from.x / fLen, fy = from.y / fLen, fz = from.z / fLen;
        float tLen = to.magnitude();
        if (tLen < 1e-6f) {
            R[0] = 1f; R[4] = 1f; R[8] = 1f;
            return R;
        }
        float tx = to.x / tLen, ty = to.y / tLen, tz = to.z / tLen;

        float vx = fy * tz - fz * ty;
        float vy = fz * tx - fx * tz;
        float vz = fx * ty - fy * tx;
        float c  = fx * tx + fy * ty + fz * tz;

        if (1f + c < 1e-6f) {
            // 反向：选一条与 from 大致垂直的轴做 180° 翻转，保证矩阵确定且数值稳定
            float ax, ay, az;
            if (Math.abs(fx) < 0.9f) { ax = 1f; ay = 0f; az = 0f; }
            else                     { ax = 0f; ay = 1f; az = 0f; }
            // perp = from × axis，归一化后构造绕 perp 的 180° 旋转
            float px = fy * az - fz * ay;
            float py = fz * ax - fx * az;
            float pz = fx * ay - fy * ax;
            float pLen = (float) Math.sqrt(px * px + py * py + pz * pz);
            px /= pLen; py /= pLen; pz /= pLen;
            // R(180°, p) = 2 p p^T - I
            R[0] = 2f * px * px - 1f; R[1] = 2f * px * py;       R[2] = 2f * px * pz;
            R[3] = 2f * py * px;       R[4] = 2f * py * py - 1f; R[5] = 2f * py * pz;
            R[6] = 2f * pz * px;       R[7] = 2f * pz * py;       R[8] = 2f * pz * pz - 1f;
            return R;
        }

        float k = 1f / (1f + c);
        // K
        // [  0  -vz   vy ]
        // [  vz  0   -vx ]
        // [ -vy  vx   0  ]
        // K² 自展开（已合并）
        float kxx = -(vy * vy + vz * vz);
        float kyy = -(vx * vx + vz * vz);
        float kzz = -(vx * vx + vy * vy);
        float kxy = vx * vy;
        float kxz = vx * vz;
        float kyz = vy * vz;

        R[0] = 1f       + 0f  + kxx * k;
        R[1] = 0f - vz  + kxy * k;
        R[2] = 0f + vy  + kxz * k;

        R[3] = 0f + vz  + kxy * k;
        R[4] = 1f       + 0f  + kyy * k;
        R[5] = 0f - vx  + kyz * k;

        R[6] = 0f - vy  + kxz * k;
        R[7] = 0f + vx  + kyz * k;
        R[8] = 1f       + 0f  + kzz * k;
        return R;
    }

    /**
     * 把 3x3 旋转矩阵 R 应用到所有交错样本（[x0,y0,z0, x1,y1,z1, ...]）上，
     * 输出到 {@code out}（必须 ≥ 3*sampleCount 长）。允许 in == out（原地旋转）。
     */
    public static void rotateInterleaved(float[] in, int sampleCount, float[] R, float[] out) {
        int end = sampleCount * 3;
        for (int i = 0; i < end; i += 3) {
            float x = in[i], y = in[i + 1], z = in[i + 2];
            out[i]     = R[0] * x + R[1] * y + R[2] * z;
            out[i + 1] = R[3] * x + R[4] * y + R[5] * z;
            out[i + 2] = R[6] * x + R[7] * y + R[8] * z;
        }
    }

    /**
     * 把单个三维向量经 R 旋转。{@code R} 为行优先 3x3。
     */
    public static Vector3 rotate(Vector3 v, float[] R) {
        float x = R[0] * v.x + R[1] * v.y + R[2] * v.z;
        float y = R[3] * v.x + R[4] * v.y + R[5] * v.z;
        float z = R[6] * v.x + R[7] * v.y + R[8] * v.z;
        return new Vector3(x, y, z);
    }

    // ── 指纹哈希 ─────────────────────────────────────────────────────

    /**
     * 基于 6 维特征 [stdX, stdY, stdZ, gyroX, gyroY, gyroZ] 生成 16 位（8 字节）指纹哈希。
     *
     * 步骤：
     *   1) 每个分量按 {@link #FEATURE_BUCKET_SCALE} 缩放并取整
     *      → 把"对噪声敏感的浮点尾位"压成"对噪声鲁棒的整数桶"；
     *   2) 6 个 long 拼成 48 字节 → SHA-256 → 取前 8 字节十六进制。
     *
     * 不要直接哈希浮点位模式：原始浮点的 IEEE 表达对最后 1ulp 噪声雪崩极强，
     * 同一台静止设备每次采集结果都不同，违背"硬件指纹"的本意。
     */
    public static String fingerprintHash(Vector3 stdAccel, Vector3 gyroMean) {
        long bX = Math.round(stdAccel.x * FEATURE_BUCKET_SCALE);
        long bY = Math.round(stdAccel.y * FEATURE_BUCKET_SCALE);
        long bZ = Math.round(stdAccel.z * FEATURE_BUCKET_SCALE);
        long gX = Math.round(gyroMean.x * FEATURE_BUCKET_SCALE);
        long gY = Math.round(gyroMean.y * FEATURE_BUCKET_SCALE);
        long gZ = Math.round(gyroMean.z * FEATURE_BUCKET_SCALE);

        ByteBuffer buf = ByteBuffer.allocate(48);
        buf.putLong(bX); buf.putLong(bY); buf.putLong(bZ);
        buf.putLong(gX); buf.putLong(gY); buf.putLong(gZ);

        try {
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(buf.array());
            return bytesToHex(sha, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 在 Android 8.0+ 一定存在，这里走 ASCII 降级仅为编译期完整性
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** 把字节数组的 [from, from+len) 子片段按大写十六进制输出。 */
    public static String bytesToHex(byte[] bytes, int from, int len) {
        char[] hex = new char[len * 2];
        for (int i = 0; i < len; i++) {
            int b = bytes[from + i] & 0xFF;
            hex[i * 2]     = HEX[b >>> 4];
            hex[i * 2 + 1] = HEX[b & 0x0F];
        }
        return new String(hex);
    }

    private static final char[] HEX = {
            '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };

    // ── 相似度 / 判定 ────────────────────────────────────────────────

    /**
     * 距离 → 相似度（百分比）。{@code similarity = 100 * exp(-dist / sigma)}。
     *
     * 给出的曲线对小距离友好、对大距离温和：
     *   dist=0       → 100%
     *   dist=σ       → 36.8%
     *   dist=σ/4     → 78%
     *   dist=σ/20    → 95%
     */
    public static double similarityPercent(double minDist, double sigma) {
        if (Double.isNaN(minDist) || Double.isInfinite(minDist)) return 0d;
        return 100.0 * Math.exp(-minDist / sigma);
    }

    /** 距离 → 判定枚举。阈值见 DIST_THRESHOLD_*。 */
    public static MatchLevel classifyMatch(double minDist) {
        if (Double.isNaN(minDist) || Double.isInfinite(minDist)) return MatchLevel.NEW;
        if (minDist < DIST_THRESHOLD_MATCH)    return MatchLevel.MATCH;
        if (minDist < DIST_THRESHOLD_LIKELY)   return MatchLevel.LIKELY;
        if (minDist < DIST_THRESHOLD_UNLIKELY) return MatchLevel.UNLIKELY;
        return MatchLevel.NEW;
    }
}
