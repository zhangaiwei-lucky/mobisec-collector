package com.ucas.infocollect.fragment;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.ucas.infocollect.R;
import com.ucas.infocollect.engine.sensor.RecordingResult;
import com.ucas.infocollect.engine.sensor.SensorSamplingEngine;
import com.ucas.infocollect.engine.sensor.SensorSnapshot;
import com.ucas.infocollect.engine.sensor.SignalProcessingMath;
import com.ucas.infocollect.engine.sensor.Vector3;

import java.util.List;
import java.util.Locale;

/**
 * 传感器侧信道分析 UI（Phase 2 薄壳化版本）。
 *
 * 本类不再持有任何 {@code SensorManager} / {@code SensorEventListener} 引用，
 * 也不再做任何方差/标准差/均值计算。所有硬件 I/O 与并发都封装在
 * {@link SensorSamplingEngine}，所有数学运算都封装在 {@link SignalProcessingMath}。
 *
 * Fragment 的职责被压缩为三件事：
 *   1) onResume/onPause 启停引擎；
 *   2) 用 10Hz 的低频 {@link Handler} 定时器把 {@link SensorSnapshot} 渲染到 TextView；
 *   3) 触发一次窗口录制并把 {@link RecordingResult} 解读为人类可读文本。
 */
public class SensorFragment extends Fragment {

    private static final long SAMPLE_DURATION_MS = 5000L;
    private static final int  MAX_RECORDING_SAMPLES = 1000;
    /** UI 显示刷新周期（10Hz 足够人眼感知，但远低于硬件回调频率，避免 setText 抖动）。 */
    private static final long UI_TICK_MS = 100L;

    private static final String PREFS_SENSOR = "sensor_fingerprints";
    private static final String KEY_HISTORY  = "fp_history";
    private static final int    MAX_HISTORY  = 5;
    /**
     * 历史持久化格式版本号。v1（无前缀，旧版以 "%s|%.8f|..."  开头）的特征向量含
     * 重力 / 姿态敏感分量，与 v2 不可比较；遇到 v1 直接忽略让用户重建基线。
     */
    private static final String HISTORY_FORMAT_TAG = "v2";
    private static final String HISTORY_FORMAT_PREFIX = HISTORY_FORMAT_TAG + "|";
    /** 静止度阈值（采集期间总方差 > 该值时给出可靠性警告）。 */
    private static final double STATIC_VAR_WARN = 0.05;

    private TextView tvSensorList, tvAccel, tvGyro, tvActivity, tvFingerprint, tvPressure;
    private Button btnSnap;
    private ProgressBar progressBar;

    private SensorSamplingEngine engine;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    /** 10Hz 拉取定时器：自我重投的低频轮询，等价于一个简单的 Throttle。 */
    private final Runnable uiTick = new Runnable() {
        @Override public void run() {
            if (engine == null || tvAccel == null) return;
            renderSnapshot(engine.getCurrentSnapshot());
            mainHandler.postDelayed(this, UI_TICK_MS);
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
            @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_sensor, container, false);

        tvSensorList  = view.findViewById(R.id.tv_sensor_list);
        tvAccel       = view.findViewById(R.id.tv_realtime_accel);
        tvGyro        = view.findViewById(R.id.tv_realtime_gyro);
        tvActivity    = view.findViewById(R.id.tv_activity);
        tvFingerprint = view.findViewById(R.id.tv_fingerprint);
        tvPressure    = view.findViewById(R.id.tv_realtime_pressure);
        btnSnap       = view.findViewById(R.id.btn_start_sample);
        progressBar   = view.findViewById(R.id.progress_sampling);

        SensorSamplingEngine.Config cfg = new SensorSamplingEngine.Config();
        cfg.maxRecordingSamples = MAX_RECORDING_SAMPLES;
        engine = new SensorSamplingEngine(requireContext(), cfg);

        btnSnap.setOnClickListener(v -> startRecording());
        tvFingerprint.setText("点击下方按钮采集实验性传感器指纹\n建议先将手机静置 5 秒后再采集");
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        engine.start();
        renderSensorInventory();
        renderSnapshot(engine.getCurrentSnapshot()); // 立刻刷一次首屏
        mainHandler.postDelayed(uiTick, UI_TICK_MS);
    }

    @Override
    public void onPause() {
        super.onPause();
        mainHandler.removeCallbacks(uiTick);
        engine.stop(); // 引擎内部会自行取消进行中的录制
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        mainHandler.removeCallbacksAndMessages(null);
        tvAccel = tvGyro = tvActivity = tvFingerprint = tvSensorList = tvPressure = null;
        progressBar = null;
        btnSnap = null;
    }

    // ── 实时渲染（10Hz 拉取） ────────────────────────────────────────

    private void renderSnapshot(@NonNull SensorSnapshot s) {
        if (tvAccel == null) return;

        Vector3 a = s.accel;
        tvAccel.setText(String.format(Locale.getDefault(),
                "加速度 (m/s²)  X=%+6.3f  Y=%+6.3f  Z=%+6.3f",
                a.x, a.y, a.z));

        Vector3 g = s.gyro;
        tvGyro.setText(String.format(Locale.getDefault(),
                "角速度 (rad/s) X=%+7.4f  Y=%+7.4f  Z=%+7.4f",
                g.x, g.y, g.z));

        if (tvPressure == null) return;
        if (!engine.hasPressureSensor()) {
            tvPressure.setText("气压计：本设备无气压计（TYPE_PRESSURE 传感器不存在）");
        } else if (!s.hasPressure) {
            tvPressure.setText("气压计：暂未收到气压数据（传感器存在，等待回调）");
        } else {
            float altitude = SensorManager.getAltitude(
                    SensorManager.PRESSURE_STANDARD_ATMOSPHERE, s.pressureHpa);
            tvPressure.setText(String.format(Locale.getDefault(),
                    "气压: %.2f hPa  |  估算海拔: %.1f m  |  ≈楼层: %d",
                    s.pressureHpa, altitude, Math.round(altitude / 3.0)));
        }
    }

    private void renderSensorInventory() {
        if (tvSensorList == null) return;
        List<Sensor> all = engine.listAvailableSensors();
        StringBuilder sb = new StringBuilder();
        sb.append("⚠ 以下传感器均无需任何权限\n");
        sb.append("────────────────────────\n");
        for (Sensor s : all) {
            sb.append(String.format(Locale.getDefault(),
                    "• %-16s [%s]  功耗:%.1fmA\n",
                    sensorName(s.getType()),
                    s.getVendor() != null ? s.getVendor() : "?",
                    s.getPower()));
        }
        sb.append("\n共 ").append(all.size()).append(" 个传感器");
        tvSensorList.setText(sb.toString());
    }

    private static String sensorName(int type) {
        switch (type) {
            case Sensor.TYPE_ACCELEROMETER:       return "加速度计";
            case Sensor.TYPE_GYROSCOPE:           return "陀螺仪";
            case Sensor.TYPE_MAGNETIC_FIELD:      return "磁力计";
            case Sensor.TYPE_PRESSURE:            return "气压计";
            case Sensor.TYPE_LIGHT:               return "光线传感器";
            case Sensor.TYPE_PROXIMITY:           return "接近传感器";
            case Sensor.TYPE_GRAVITY:             return "重力传感器";
            case Sensor.TYPE_LINEAR_ACCELERATION: return "线性加速度";
            case Sensor.TYPE_ROTATION_VECTOR:     return "旋转矢量";
            case Sensor.TYPE_STEP_COUNTER:        return "计步器";
            case Sensor.TYPE_HEART_RATE:          return "心率";
            default:                              return "传感器#" + type;
        }
    }

    // ── 录制 + 分析 ─────────────────────────────────────────────────

    private void startRecording() {
        if (engine.isRecording()) return;

        boolean started = engine.startRecording(
                SAMPLE_DURATION_MS, mainHandler, this::onRecordingComplete);
        if (!started) return;

        btnSnap.setEnabled(false);
        btnSnap.setText("采集中... (5s)");
        progressBar.setVisibility(View.VISIBLE);
        tvFingerprint.setText("正在采集传感器噪声数据...\n请保持手机静置，勿晃动");
        tvActivity.setText("分析中...");
    }

    private void onRecordingComplete(@NonNull RecordingResult result) {
        if (tvFingerprint == null) return; // view 已销毁

        progressBar.setVisibility(View.GONE);
        btnSnap.setEnabled(true);
        btnSnap.setText("重新采集分析");

        if (result.wasCancelled || !result.hasEnoughAccelSamples(10)) {
            tvFingerprint.setText("采样数据不足（" + result.accelCount + "条），请重试");
            return;
        }

        try {
            renderActivity(result);
            renderFingerprint(result);
        } catch (Exception e) {
            tvFingerprint.setText("分析出错: " + e.getMessage());
        }
    }

    private void renderActivity(@NonNull RecordingResult r) {
        Vector3 mean = SignalProcessingMath.meanXYZ(r.accelXYZ, r.accelCount);
        Vector3 var  = SignalProcessingMath.varianceXYZ(r.accelXYZ, r.accelCount, mean);
        double total = (double) var.x + var.y + var.z;

        String activity;
        int color;
        if (total < 0.05) {
            activity = "静止（桌面放置）";
            color = ContextCompat.getColor(requireContext(), R.color.sensor_activity_static);
        } else if (total < 0.5) {
            activity = "轻微移动（手持待机）";
            color = ContextCompat.getColor(requireContext(), R.color.sensor_activity_idle_move);
        } else if (total < 3.0) {
            activity = "步行";
            color = ContextCompat.getColor(requireContext(), R.color.sensor_activity_walk);
        } else if (total < 10.0) {
            activity = "快走/慢跑";
            color = ContextCompat.getColor(requireContext(), R.color.sensor_activity_jog);
        } else {
            activity = "奔跑/乘车";
            color = ContextCompat.getColor(requireContext(), R.color.sensor_activity_fast_move);
        }

        tvActivity.setTextColor(color);
        tvActivity.setText(String.format(Locale.getDefault(),
                "识别结果：%s\n方差 X=%.5f Y=%.5f Z=%.5f\n总方差=%.5f  样本=%d",
                activity, var.x, var.y, var.z, total, r.accelCount));
    }

    private void renderFingerprint(@NonNull RecordingResult r) {
        // ── 1) 姿态归一化：把 aMean 的方向旋到 (0,0,-1) ──────────
        // 这样不同姿态（手放桌上、握持、轻微倾斜）下采集的同一台设备
        // 都会被映射到统一坐标系，std 与 gyro mean 才会真正"对硬件个体敏感"。
        Vector3 aMeanRaw = SignalProcessingMath.meanXYZ(r.accelXYZ, r.accelCount);
        float[] R = SignalProcessingMath.rotationFromTo(aMeanRaw, new Vector3(0f, 0f, -1f));

        float[] rotAccel = new float[r.accelCount * 3];
        SignalProcessingMath.rotateInterleaved(r.accelXYZ, r.accelCount, R, rotAccel);
        Vector3 aMean = SignalProcessingMath.meanXYZ(rotAccel, r.accelCount);
        Vector3 aVar  = SignalProcessingMath.varianceXYZ(rotAccel, r.accelCount, aMean);
        Vector3 aStd  = new Vector3(
                (float) Math.sqrt(aVar.x), (float) Math.sqrt(aVar.y), (float) Math.sqrt(aVar.z));

        boolean hasGyro = r.gyroCount > 0;
        Vector3 gMean, gStd;
        if (hasGyro) {
            float[] rotGyro = new float[r.gyroCount * 3];
            SignalProcessingMath.rotateInterleaved(r.gyroXYZ, r.gyroCount, R, rotGyro);
            gMean = SignalProcessingMath.meanXYZ(rotGyro, r.gyroCount);
            gStd  = SignalProcessingMath.stdDevXYZ(rotGyro, r.gyroCount, gMean);
        } else {
            gMean = Vector3.ZERO;
            gStd  = Vector3.ZERO;
        }

        // 静止度诊断：rotateInterleaved 只是正交变换，方差和与原始等价
        double sigmaTotal = (double) aVar.x + aVar.y + aVar.z;
        Vector3 residual = SignalProcessingMath.stripGravity(aMeanRaw);

        // ── 2) 6D 特征向量 + SHA-256 哈希 ──────────────────────
        // [stdAccelX, stdAccelY, stdAccelZ, gyroMeanX, gyroMeanY, gyroMeanZ]
        // 加速度标准差 ≈ 器件噪声底；陀螺仪零漂 ≈ ZRO（Zero-Rate Output），都是
        // 公认的传感器侧信道指纹来源，且与姿态无关（前提是已做姿态归一化）。
        String hashStr = SignalProcessingMath.fingerprintHash(aStd, gMean);

        // ── 3) UI 文本 ────────────────────────────────────────
        StringBuilder sb = new StringBuilder();
        sb.append("═══ 实验性传感器指纹 ═══\n");
        sb.append("⚠ 稳定性需在静止、多轮、多设备条件下验证\n");
        sb.append(String.format(Locale.US, "本次指纹哈希: %s\n\n", hashStr));

        sb.append(String.format(Locale.US,
                "静止度判定：σ_total=%.6f  (样本=%d)\n", sigmaTotal, r.accelCount));
        if (sigmaTotal > STATIC_VAR_WARN) {
            sb.append("  ⚠ 采集期间手机不够稳定，结果可能不可信。\n");
            sb.append("  建议把手机放在桌面后再点采集，避免握持/触碰。\n");
        } else {
            sb.append("  ✓ 采集稳定。\n");
        }
        sb.append("\n");

        sb.append("加速度计 σ（姿态归一化后，每轴噪声底）:\n");
        sb.append(String.format(Locale.US, "  σx=%.6f  σy=%.6f  σz=%.6f\n", aStd.x, aStd.y, aStd.z));
        sb.append(String.format(Locale.US,
                "  残余偏差 (x,y,|a|-g): %+.4f, %+.4f, %+.4f\n",
                residual.x, residual.y, residual.z));

        if (hasGyro) {
            sb.append("\n陀螺仪零漂（旋至同一坐标系后的 mean）:\n");
            sb.append(String.format(Locale.US, "  μx=%+.6f  μy=%+.6f  μz=%+.6f\n",
                    gMean.x, gMean.y, gMean.z));
            sb.append(String.format(Locale.US, "  σx=%.6f  σy=%.6f  σz=%.6f\n",
                    gStd.x, gStd.y, gStd.z));
        }

        if (r.pressureCount > 0) {
            double pMean = SignalProcessingMath.meanScalar(r.pressureHpa, r.pressureCount);
            float altitude = SensorManager.getAltitude(
                    SensorManager.PRESSURE_STANDARD_ATMOSPHERE, (float) pMean);
            sb.append("\n气压计 (TYPE_PRESSURE):\n");
            sb.append(String.format(Locale.US, "  平均气压: %.2f hPa\n", pMean));
            sb.append(String.format(Locale.US, "  估算海拔: %.1f m（约 %d 楼）\n",
                    altitude, Math.round(altitude / 3.0)));
            sb.append("  侧信道价值: 可推断所在楼层变化（电梯场景）\n");
        } else if (engine.hasPressureSensor()) {
            sb.append("\n气压计 (TYPE_PRESSURE): 传感器存在，采集期间暂未收到数据\n");
        } else {
            sb.append("\n气压计 (TYPE_PRESSURE): 本设备无气压计\n");
        }

        // ── 4) 历史对比 + 判定 ───────────────────────────────────
        sb.append("\n── 历史指纹对比（向量距离） ──\n");
        SharedPreferences prefs = requireContext().getSharedPreferences(
                PREFS_SENSOR, Context.MODE_PRIVATE);
        String history = prefs.getString(KEY_HISTORY, "");
        String[] histEntries = history == null || history.isEmpty()
                ? new String[0] : history.split(",");

        double[] curVec = { aStd.x, aStd.y, aStd.z, gMean.x, gMean.y, gMean.z };
        double minDist = Double.MAX_VALUE;
        int validCount = 0;
        int legacyCount = 0;
        for (String entry : histEntries) {
            if (entry != null && !entry.isEmpty() && !entry.startsWith(HISTORY_FORMAT_PREFIX)) {
                legacyCount++;
                continue;
            }
            double[] vec = parseHistoryEntry(entry);
            if (vec != null) {
                validCount++;
                double dist = SignalProcessingMath.euclideanDistance(curVec, vec);
                if (dist < minDist) minDist = dist;
            }
        }

        if (validCount == 0) {
            sb.append("  首次采集，暂无历史数据\n");
            if (legacyCount > 0) {
                sb.append(String.format(Locale.US,
                        "  （已忽略 %d 条旧版 v1 历史，特征向量与新算法不可比，需重建基线）\n",
                        legacyCount));
            }
        } else {
            double sim = SignalProcessingMath.similarityPercent(
                    minDist, SignalProcessingMath.SIMILARITY_SIGMA);
            SignalProcessingMath.MatchLevel level =
                    SignalProcessingMath.classifyMatch(minDist);
            sb.append(String.format(Locale.US, "  历史记录数: %d\n", validCount));
            sb.append(String.format(Locale.US, "  最近距离: %.6f\n", minDist));
            sb.append(String.format(Locale.US, "  估算相似度: %.1f%%\n", sim));
            sb.append("  判定: ").append(matchLevelLabel(level)).append("\n");
            if (legacyCount > 0) {
                sb.append(String.format(Locale.US,
                        "  （已忽略 %d 条旧版 v1 历史）\n", legacyCount));
            }
        }

        // ── 5) 持久化（v2 格式） ────────────────────────────────
        String newEntry = String.format(Locale.US,
                "%s%s|%.8f|%.8f|%.8f|%.8f|%.8f|%.8f",
                HISTORY_FORMAT_PREFIX, hashStr,
                aStd.x, aStd.y, aStd.z, gMean.x, gMean.y, gMean.z);
        // 写回时仅保留 v2 条目，主动淘汰旧版
        String[] cleaned = filterValidEntries(histEntries);
        String[] newHistory;
        if (cleaned.length >= MAX_HISTORY) {
            newHistory = new String[MAX_HISTORY];
            System.arraycopy(cleaned, cleaned.length - MAX_HISTORY + 1,
                    newHistory, 0, MAX_HISTORY - 1);
            newHistory[MAX_HISTORY - 1] = newEntry;
        } else {
            newHistory = new String[cleaned.length + 1];
            System.arraycopy(cleaned, 0, newHistory, 0, cleaned.length);
            newHistory[cleaned.length] = newEntry;
        }
        prefs.edit().putString(KEY_HISTORY, String.join(",", newHistory)).apply();

        sb.append("\n⚠ 无需任何权限 · 实验性传感器侧信道指纹原型\n");
        sb.append("（稳定性需在静止状态、多轮采集、多设备间交叉验证）");

        tvFingerprint.setTextColor(ContextCompat.getColor(requireContext(), R.color.risk_high_text));
        tvFingerprint.setText(sb.toString());
    }

    private static String matchLevelLabel(SignalProcessingMath.MatchLevel level) {
        switch (level) {
            case MATCH:    return "MATCH（同一设备）";
            case LIKELY:   return "LIKELY（很可能同一设备）";
            case UNLIKELY: return "UNLIKELY（不太像同一设备）";
            case NEW:
            default:       return "NEW（新设备 / 不可比）";
        }
    }

    private static String[] filterValidEntries(String[] entries) {
        int kept = 0;
        for (String e : entries) {
            if (e != null && e.startsWith(HISTORY_FORMAT_PREFIX)) kept++;
        }
        String[] out = new String[kept];
        int idx = 0;
        for (String e : entries) {
            if (e != null && e.startsWith(HISTORY_FORMAT_PREFIX)) out[idx++] = e;
        }
        return out;
    }

    /**
     * 解析 v2 历史条目 → 6D 特征向量。格式：
     *   v2|HASH|stdX|stdY|stdZ|gyroX|gyroY|gyroZ
     *
     * 旧版 v1（无 "v2|" 前缀，含重力分量）特征向量与新算法完全不可比，
     * 这里直接返回 null 让上层忽略；下次采集会自动写入 v2 形成新基线。
     */
    @Nullable
    private static double[] parseHistoryEntry(String entry) {
        if (entry == null) return null;
        if (!entry.startsWith(HISTORY_FORMAT_PREFIX)) return null;
        String[] parts = entry.split("\\|");
        if (parts.length != 8) return null;
        try {
            return new double[] {
                    Double.parseDouble(parts[2]),
                    Double.parseDouble(parts[3]),
                    Double.parseDouble(parts[4]),
                    Double.parseDouble(parts[5]),
                    Double.parseDouble(parts[6]),
                    Double.parseDouble(parts[7])
            };
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
