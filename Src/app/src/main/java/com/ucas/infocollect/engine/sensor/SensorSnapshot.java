package com.ucas.infocollect.engine.sensor;

/**
 * 不可变多通道传感器瞬时快照。
 *
 * 包含一次"任意通道更新"之后所有可用传感器的最新值，
 * 通过三个 hasXxx 标志区分"未启用 / 暂未到数 / 已就绪"三种状态，
 * 避免下游用 NaN 或哨兵值做隐式判断。
 *
 * 不可变性是与 {@code AtomicReference<SensorSnapshot>} 配合的关键前提：
 * 写者只能通过 with* 工厂方法生成新实例并 CAS 替换，
 * 读者拿到的引用永远指向一个完整一致的快照，无需任何锁。
 */
public final class SensorSnapshot {

    public static final SensorSnapshot EMPTY = new SensorSnapshot(
            Vector3.ZERO, Vector3.ZERO, Float.NaN,
            false, false, false,
            0L);

    public final Vector3 accel;
    public final Vector3 gyro;
    public final float pressureHpa;

    public final boolean hasAccel;
    public final boolean hasGyro;
    public final boolean hasPressure;

    /**
     * 最近一次任意通道被更新的时间戳，基于 SystemClock#elapsedRealtimeNanos。
     * 表示"该快照新鲜度"，并不代表所有通道都在该时刻有数据。
     */
    public final long timestampNanos;

    public SensorSnapshot(Vector3 accel, Vector3 gyro, float pressureHpa,
                          boolean hasAccel, boolean hasGyro, boolean hasPressure,
                          long timestampNanos) {
        this.accel = accel;
        this.gyro = gyro;
        this.pressureHpa = pressureHpa;
        this.hasAccel = hasAccel;
        this.hasGyro = hasGyro;
        this.hasPressure = hasPressure;
        this.timestampNanos = timestampNanos;
    }

    public SensorSnapshot withAccel(Vector3 newAccel, long newTimestampNanos) {
        return new SensorSnapshot(newAccel, gyro, pressureHpa,
                true, hasGyro, hasPressure, newTimestampNanos);
    }

    public SensorSnapshot withGyro(Vector3 newGyro, long newTimestampNanos) {
        return new SensorSnapshot(accel, newGyro, pressureHpa,
                hasAccel, true, hasPressure, newTimestampNanos);
    }

    public SensorSnapshot withPressure(float newPressureHpa, long newTimestampNanos) {
        return new SensorSnapshot(accel, gyro, newPressureHpa,
                hasAccel, hasGyro, true, newTimestampNanos);
    }
}
