package com.ucas.infocollect.engine.sensor;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Process;
import android.os.SystemClock;

import androidx.annotation.AnyThread;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 高频物理采样引擎。
 *
 * 职责：
 *   1) 拥有 {@link SensorManager} 注册/注销的全部生命周期；
 *   2) 在专用 {@link HandlerThread} 上接收 {@code onSensorChanged}，
 *      使主线程不会被 50–200Hz 的传感器中断打断；
 *   3) 通过 {@code AtomicReference<SensorSnapshot>} 暴露最新瞬时值，
 *      任意线程可无锁、无屏障读取；
 *   4) 通过预分配的交错 {@code float[]} 缓冲提供"零分配"的窗口录制，
 *      录制结束时通过调用方提供的 {@link Handler} 一次性发布 {@link RecordingResult}。
 *
 * 并发不变量（critical invariants）：
 *   - <b>单写者</b>：所有传感器事件、录制状态机的写入都发生在 {@code sensorThread} 上；
 *     {@link SensorManager#registerListener(SensorEventListener, Sensor, int, Handler)}
 *     传入的 Handler 决定了回调线程。
 *   - <b>无锁热路径</b>：{@code onSensorChanged} 只做以下事：分配两个小对象
 *     （Vector3 + SensorSnapshot，合计 ≈ 56 字节）→ 写 AtomicReference → 追加到预分配数组。
 *     完全没有 {@code synchronized} 块、没有 lock、没有 volatile 字段争用。
 *   - <b>录制零增长</b>：录制缓冲在 {@link RecordingSession} 构造时一次性分配，
 *     之后只做下标自增写入，不会随事件次数发生 GC。
 *   - <b>跨线程发布</b>：{@code RecordingResult} 经 {@code Handler#post} 投递，
 *     happens-before 由 Looper 保证，调用方无需任何同步即可读取数组内容。
 *
 * 引擎不持有任何 UI 对象，与 Fragment 生命周期完全解耦——Fragment 只通过
 * {@link #start()} / {@link #stop()} / {@link #getCurrentSnapshot()} / {@link #startRecording}
 * 这四个 API 与之交互。
 */
public final class SensorSamplingEngine {

    /** 录制完成回调；保证在调用方提供的 callbackHandler 线程上分发。 */
    public interface RecordingListener {
        @MainThread void onRecordingComplete(@NonNull RecordingResult result);
    }

    /** 引擎运行参数；按需修改后传入构造器。 */
    public static final class Config {
        public int accelDelay = SensorManager.SENSOR_DELAY_GAME;
        public int gyroDelay = SensorManager.SENSOR_DELAY_GAME;
        public int pressureDelay = SensorManager.SENSOR_DELAY_NORMAL;
        /** 单次录制最多保留的样本条数，决定了预分配缓冲的大小。 */
        public int maxRecordingSamples = 1000;
    }

    private final Context appContext;
    private final Config config;

    @Nullable private SensorManager sensorManager;
    @Nullable private Sensor accelSensor;
    @Nullable private Sensor gyroSensor;
    @Nullable private Sensor pressureSensor;

    @Nullable private HandlerThread sensorThread;
    @Nullable private Handler sensorHandler;

    /** 任意线程读、单线程（sensorThread）写。读路径完全无锁。 */
    private final AtomicReference<SensorSnapshot> latestSnapshot =
            new AtomicReference<>(SensorSnapshot.EMPTY);

    /** 用户视角的"是否正在录制"标志；CAS 用于防止重复 startRecording。 */
    private final AtomicBoolean recording = new AtomicBoolean(false);

    /**
     * 当前活动录制会话。仅由 {@code sensorThread} 上的代码读写
     * （主线程通过 {@link Handler#post(Runnable)} 间接修改），
     * 因此无需 volatile/锁。
     */
    @Nullable private RecordingSession activeRecording;

    private boolean started;

    public SensorSamplingEngine(@NonNull Context context, @NonNull Config config) {
        this.appContext = context.getApplicationContext();
        this.config = config;
    }

    // ── 生命周期 ──────────────────────────────────────────────────────

    @MainThread
    public void start() {
        if (started) return;

        SensorManager sm = (SensorManager) appContext.getSystemService(Context.SENSOR_SERVICE);
        if (sm == null) return;
        sensorManager = sm;

        accelSensor = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
        gyroSensor = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE);
        pressureSensor = sm.getDefaultSensor(Sensor.TYPE_PRESSURE);

        HandlerThread t = new HandlerThread("sensor-engine", Process.THREAD_PRIORITY_FOREGROUND);
        t.start();
        sensorThread = t;
        sensorHandler = new Handler(t.getLooper());

        if (accelSensor != null) {
            sm.registerListener(eventListener, accelSensor, config.accelDelay, sensorHandler);
        }
        if (gyroSensor != null) {
            sm.registerListener(eventListener, gyroSensor, config.gyroDelay, sensorHandler);
        }
        if (pressureSensor != null) {
            sm.registerListener(eventListener, pressureSensor, config.pressureDelay, sensorHandler);
        }

        started = true;
    }

    @MainThread
    public void stop() {
        if (!started) return;
        started = false;

        // 1) 切断硬件回调；之后不再有新的 onSensorChanged 入队
        if (sensorManager != null) sensorManager.unregisterListener(eventListener);

        // 2) 让 sensorThread 自己取消进行中的录制，保持"单写者"不变量
        Handler h = sensorHandler;
        if (h != null) {
            h.post(() -> {
                if (activeRecording != null && !activeRecording.delivered) {
                    activeRecording.cancel();
                }
            });
        }
        // 用户视角立刻反映"已停止"
        recording.set(false);

        // 3) quitSafely 会处理完队列中已 post 的工作（包括上面的取消），
        //    但会丢弃尚未到期的 postDelayed（finish），因此必须在第 2 步显式取消。
        if (sensorThread != null) {
            sensorThread.quitSafely();
            sensorThread = null;
        }
        sensorHandler = null;
    }

    // ── 状态查询（任意线程安全） ─────────────────────────────────────

    @AnyThread public boolean hasAccelerometer() { return accelSensor != null; }
    @AnyThread public boolean hasGyroscope()      { return gyroSensor != null; }
    @AnyThread public boolean hasPressureSensor() { return pressureSensor != null; }

    /** 获取最新瞬时快照。无锁、无屏障，可在 UI 线程的 10–60Hz 定时器中安全调用。 */
    @AnyThread
    public @NonNull SensorSnapshot getCurrentSnapshot() {
        return latestSnapshot.get();
    }

    @AnyThread
    public boolean isRecording() {
        return recording.get();
    }

    /** 设备传感器清单（仅诊断用途，与高频路径无关）。 */
    @AnyThread
    public @NonNull List<Sensor> listAvailableSensors() {
        if (sensorManager == null) return Collections.emptyList();
        return sensorManager.getSensorList(Sensor.TYPE_ALL);
    }

    // ── 录制控制 ──────────────────────────────────────────────────────

    /**
     * 启动一次窗口录制。{@code durationMillis} 之后 {@link RecordingResult}
     * 会被 post 到 {@code callbackHandler} 上分发。
     *
     * @return true 表示已开始；false 表示引擎未启动或已有录制在进行。
     */
    @MainThread
    public boolean startRecording(long durationMillis,
                                  @NonNull Handler callbackHandler,
                                  @NonNull RecordingListener listener) {
        Handler h = sensorHandler;
        if (!started || h == null) return false;
        if (!recording.compareAndSet(false, true)) return false;

        RecordingSession session = new RecordingSession(
                config.maxRecordingSamples, callbackHandler, listener);

        // 在 sensorThread 上发布 activeRecording，与 onSensorChanged 同线程，无竞争
        h.post(() -> activeRecording = session);
        h.postDelayed(session::finish, durationMillis);
        return true;
    }

    @MainThread
    public void cancelRecording() {
        Handler h = sensorHandler;
        if (h == null) return;
        h.post(() -> {
            if (activeRecording != null && !activeRecording.delivered) {
                activeRecording.cancel();
            }
        });
    }

    // ── 高频回调（运行于 sensorThread） ─────────────────────────────

    private final SensorEventListener eventListener = new SensorEventListener() {
        @Override public void onSensorChanged(SensorEvent event) { handleEvent(event); }
        @Override public void onAccuracyChanged(Sensor sensor, int accuracy) { /* no-op */ }
    };

    /**
     * 单线程热路径。允许的开销上限：
     *   - 2 次小对象分配（Vector3 + SensorSnapshot）
     *   - 1 次 AtomicReference#set（写一次内存屏障）
     *   - 0–3 次 float[] 下标写（仅录制中）
     */
    private void handleEvent(SensorEvent event) {
        long ts = SystemClock.elapsedRealtimeNanos();
        int type = event.sensor.getType();
        float[] v = event.values;

        SensorSnapshot prev = latestSnapshot.get();
        SensorSnapshot next;
        switch (type) {
            case Sensor.TYPE_ACCELEROMETER:
                next = prev.withAccel(new Vector3(v[0], v[1], v[2]), ts);
                break;
            case Sensor.TYPE_GYROSCOPE:
                next = prev.withGyro(new Vector3(v[0], v[1], v[2]), ts);
                break;
            case Sensor.TYPE_PRESSURE:
                next = prev.withPressure(v[0], ts);
                break;
            default:
                return;
        }
        latestSnapshot.set(next);

        RecordingSession s = activeRecording;
        if (s != null && !s.delivered) {
            s.appendEvent(type, v);
        }
    }

    /**
     * 录制状态机。所有字段仅在 {@code sensorThread} 上访问，
     * 因此无需任何同步原语，纯单线程语义。
     */
    private final class RecordingSession {
        final float[] accelXYZ;
        final float[] gyroXYZ;
        final float[] pressure;
        final long startNanos;
        final Handler callbackHandler;
        final RecordingListener listener;

        int accelCount;
        int gyroCount;
        int pressureCount;
        boolean delivered;

        RecordingSession(int maxSamples, Handler callbackHandler, RecordingListener listener) {
            this.accelXYZ = new float[maxSamples * 3];
            this.gyroXYZ = new float[maxSamples * 3];
            this.pressure = new float[maxSamples];
            this.startNanos = SystemClock.elapsedRealtimeNanos();
            this.callbackHandler = callbackHandler;
            this.listener = listener;
        }

        void appendEvent(int type, float[] values) {
            switch (type) {
                case Sensor.TYPE_ACCELEROMETER: {
                    int idx = accelCount * 3;
                    if (idx < accelXYZ.length) {
                        accelXYZ[idx]     = values[0];
                        accelXYZ[idx + 1] = values[1];
                        accelXYZ[idx + 2] = values[2];
                        accelCount++;
                    }
                    break;
                }
                case Sensor.TYPE_GYROSCOPE: {
                    int idx = gyroCount * 3;
                    if (idx < gyroXYZ.length) {
                        gyroXYZ[idx]     = values[0];
                        gyroXYZ[idx + 1] = values[1];
                        gyroXYZ[idx + 2] = values[2];
                        gyroCount++;
                    }
                    break;
                }
                case Sensor.TYPE_PRESSURE:
                    if (pressureCount < pressure.length) {
                        pressure[pressureCount++] = values[0];
                    }
                    break;
                default:
                    break;
            }
        }

        void finish() { deliver(false); }
        void cancel() { deliver(true); }

        private void deliver(boolean cancelled) {
            if (delivered) return;
            delivered = true;
            recording.set(false);
            if (activeRecording == this) activeRecording = null;

            long durationNanos = SystemClock.elapsedRealtimeNanos() - startNanos;
            RecordingResult result = new RecordingResult(
                    accelXYZ, accelCount,
                    gyroXYZ, gyroCount,
                    pressure, pressureCount,
                    durationNanos, cancelled);
            // Handler#post 提供 happens-before：listener 那一侧读到的字段值与本线程写入一致
            callbackHandler.post(() -> listener.onRecordingComplete(result));
        }
    }
}
