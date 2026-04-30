package com.ucas.infocollect.engine.sensor;

/**
 * 不可变三维向量（基础物理量）。
 *
 * 设计说明：
 *   - final 字段 + 无 setter：天然线程安全，可在 AtomicReference 中作为快照值传递。
 *   - 单实例约 24 字节（对象头 16 + 3*float），高频路径每事件分配 1 个，
 *     在 50–200Hz 的传感器回调下总分配速率 < 10KB/s，远低于 ART 的 GC 触发阈值。
 *   - 与 Android 框架完全解耦，可用纯 JUnit 单元测试。
 */
public final class Vector3 {

    public static final Vector3 ZERO = new Vector3(0f, 0f, 0f);

    public final float x;
    public final float y;
    public final float z;

    public Vector3(float x, float y, float z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    /** 从三元素浮点数组（如 SensorEvent#values）按值拷贝。 */
    public static Vector3 of(float[] xyz) {
        return new Vector3(xyz[0], xyz[1], xyz[2]);
    }

    /** 欧几里得模长。 */
    public float magnitude() {
        return (float) Math.sqrt((double) x * x + (double) y * y + (double) z * z);
    }

    /** 模长平方。仅需比较强度而无需开方时使用。 */
    public float magnitudeSquared() {
        return x * x + y * y + z * z;
    }

    public Vector3 subtract(Vector3 other) {
        return new Vector3(x - other.x, y - other.y, z - other.z);
    }

    public Vector3 scale(float k) {
        return new Vector3(x * k, y * k, z * k);
    }

    @Override
    public String toString() {
        return "Vector3(" + x + ", " + y + ", " + z + ")";
    }
}
