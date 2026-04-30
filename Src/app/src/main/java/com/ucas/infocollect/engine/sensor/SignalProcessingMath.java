package com.ucas.infocollect.engine.sensor;

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
}
