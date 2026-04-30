package com.ucas.infocollect.engine.sensor;

/**
 * {@link SensorSamplingEngine} 一次窗口录制的不可变结果。
 *
 * 字段为 final 引用 + final 计数，由引擎在录制结束的瞬间一次性发布到回调线程。
 * 由于发布走 {@code Handler#post}，happens-before 由 Looper 框架保证；
 * 调用方读取时已不再有任何写入者，因此无需对内部数组加任何同步。
 *
 * 三轴数据采用"交错存储"布局（[x0,y0,z0, x1,y1,z1, ...]），
 * 可直接喂给 {@link SignalProcessingMath#meanXYZ} 等 API，避免再做一次转置。
 */
public final class RecordingResult {

    /** 加速度交错缓冲，仅前 {@link #accelCount} 个样本（即前 3*accelCount 个 float）有效。 */
    public final float[] accelXYZ;
    public final int accelCount;

    public final float[] gyroXYZ;
    public final int gyroCount;

    public final float[] pressureHpa;
    public final int pressureCount;

    /** 实际录制窗口长度（可能略大于请求时长，因为收尾走 sensorHandler 异步队列）。 */
    public final long durationNanos;

    /** 是否被中途取消（如 onPause 提前 stop）。 */
    public final boolean wasCancelled;

    public RecordingResult(float[] accelXYZ, int accelCount,
                           float[] gyroXYZ, int gyroCount,
                           float[] pressureHpa, int pressureCount,
                           long durationNanos, boolean wasCancelled) {
        this.accelXYZ = accelXYZ;
        this.accelCount = accelCount;
        this.gyroXYZ = gyroXYZ;
        this.gyroCount = gyroCount;
        this.pressureHpa = pressureHpa;
        this.pressureCount = pressureCount;
        this.durationNanos = durationNanos;
        this.wasCancelled = wasCancelled;
    }

    public boolean hasEnoughAccelSamples(int min) {
        return accelCount >= min;
    }
}
