package com.ucas.infocollect.fragment;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 传感器侧信道分析界面
 *
 * 实时模式：onResume 注册传感器，onPause 取消，数据持续更新
 * 分析模式：点击按钮采集 5 秒快照，生成硬件指纹和活动识别结果
 */
public class SensorFragment extends Fragment implements SensorEventListener {

    private static final int SAMPLE_MS   = 5000;
    private static final int MAX_SAMPLES = 1000;
    private static final int UI_SKIP     = 10; // 每 10 个事件刷一次 UI（约 5Hz）

    private static final String PREFS_SENSOR  = "sensor_fingerprints";
    private static final String KEY_HISTORY   = "fp_history";
    private static final int    MAX_HISTORY   = 5;

    private SensorManager sensorManager;
    private Sensor accelSensor, gyroSensor, pressureSensor;

    // 实时值
    private float[] liveAccel    = new float[3];
    private float[] liveGyro     = new float[3];
    private float   livePressure = 0f;
    private int eventCount = 0;

    // 采集快照数据
    private final List<float[]>  accelSnap    = new ArrayList<>();
    private final List<float[]>  gyroSnap     = new ArrayList<>();
    private final List<Float>    pressureSnap = new ArrayList<>();
    private boolean isSnapping = false;

    // UI
    private TextView tvSensorList, tvAccel, tvGyro, tvActivity, tvFingerprint, tvPressure;
    private Button   btnSnap;
    private ProgressBar progressBar;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable stopSnapRunnable;

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

        try {
            sensorManager = (SensorManager) requireContext()
                .getSystemService(Context.SENSOR_SERVICE);
            accelSensor    = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
            gyroSensor     = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE);
            pressureSensor = sensorManager.getDefaultSensor(Sensor.TYPE_PRESSURE);
            displaySensorInventory();
        } catch (Exception e) {
            tvSensorList.setText("传感器初始化失败: " + e.getMessage());
        }

        btnSnap.setOnClickListener(v -> { if (!isSnapping) startSnapshot(); });
        return view;
    }

    // ── 生命周期：可见时注册传感器，不可见时取消 ──────────────────

    @Override
    public void onResume() {
        super.onResume();
        if (sensorManager != null) {
            if (accelSensor != null)
                sensorManager.registerListener(this, accelSensor, SensorManager.SENSOR_DELAY_GAME);
            if (gyroSensor != null)
                sensorManager.registerListener(this, gyroSensor, SensorManager.SENSOR_DELAY_GAME);
            if (pressureSensor != null)
                sensorManager.registerListener(this, pressureSensor, SensorManager.SENSOR_DELAY_NORMAL);
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        // 离开 tab 时停止实时采集（不影响已采集的快照数据）
        if (sensorManager != null) sensorManager.unregisterListener(this);
        if (isSnapping) cancelSnapshot();
    }

    // ── 传感器回调 ─────────────────────────────────────────────────

    @Override
    public void onSensorChanged(SensorEvent event) {
        int type = event.sensor.getType();
        if (type == Sensor.TYPE_ACCELEROMETER) {
            liveAccel = event.values.clone();
            if (isSnapping && accelSnap.size() < MAX_SAMPLES)
                accelSnap.add(event.values.clone());
        } else if (type == Sensor.TYPE_GYROSCOPE) {
            liveGyro = event.values.clone();
            if (isSnapping && gyroSnap.size() < MAX_SAMPLES)
                gyroSnap.add(event.values.clone());
        } else if (type == Sensor.TYPE_PRESSURE) {
            livePressure = event.values[0];
            if (isSnapping && pressureSnap.size() < MAX_SAMPLES)
                pressureSnap.add(event.values[0]);
        }

        // 限速 UI 更新
        if (++eventCount % UI_SKIP == 0) updateLiveDisplay();
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {}

    private void updateLiveDisplay() {
        if (tvAccel == null) return;
        tvAccel.setText(String.format(Locale.getDefault(),
            "加速度 (m/s²)  X=%+6.3f  Y=%+6.3f  Z=%+6.3f",
            liveAccel[0], liveAccel[1], liveAccel[2]));
        tvGyro.setText(String.format(Locale.getDefault(),
            "角速度 (rad/s) X=%+7.4f  Y=%+7.4f  Z=%+7.4f",
            liveGyro[0], liveGyro[1], liveGyro[2]));
        if (tvPressure != null && pressureSensor != null) {
            float altitude = SensorManager.getAltitude(
                SensorManager.PRESSURE_STANDARD_ATMOSPHERE, livePressure);
            tvPressure.setText(String.format(Locale.getDefault(),
                "气压: %.2f hPa  |  估算海拔: %.1f m  |  ≈楼层: %d",
                livePressure, altitude, Math.round(altitude / 3.0)));
        }
    }

    // ── 快照采集与分析 ─────────────────────────────────────────────

    private void startSnapshot() {
        isSnapping = true;
        accelSnap.clear();
        gyroSnap.clear();
        pressureSnap.clear();
        btnSnap.setEnabled(false);
        btnSnap.setText("采集中... (5s)");
        progressBar.setVisibility(View.VISIBLE);
        tvFingerprint.setText("正在采集传感器噪声数据...");
        tvActivity.setText("分析中...");

        stopSnapRunnable = this::finishSnapshot;
        handler.postDelayed(stopSnapRunnable, SAMPLE_MS);
    }

    private void finishSnapshot() {
        isSnapping = false;
        progressBar.setVisibility(View.GONE);
        btnSnap.setEnabled(true);
        btnSnap.setText("重新采集分析");

        if (accelSnap.size() < 10) {
            tvFingerprint.setText("采样数据不足（" + accelSnap.size() + "条），请重试");
            return;
        }
        try {
            analyzeActivity();
            generateFingerprint();
        } catch (Exception e) {
            tvFingerprint.setText("分析出错: " + e.getMessage());
        }
    }

    private void cancelSnapshot() {
        isSnapping = false;
        if (stopSnapRunnable != null) handler.removeCallbacks(stopSnapRunnable);
        progressBar.setVisibility(View.GONE);
        btnSnap.setEnabled(true);
        btnSnap.setText("重新采集分析");
    }

    // ── 活动识别 ───────────────────────────────────────────────────

    private void analyzeActivity() {
        double[] var = variance(accelSnap);
        double total = var[0] + var[1] + var[2];

        String activity; int color;
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
            activity, var[0], var[1], var[2], total, accelSnap.size()));
    }

    // ── 硬件指纹 ───────────────────────────────────────────────────

    private void generateFingerprint() {
        double[] aMean = mean(accelSnap);
        double[] aStd  = std(accelSnap, aMean);
        double[] gMean = gyroSnap.isEmpty() ? new double[3] : mean(gyroSnap);
        double[] gStd  = gyroSnap.isEmpty() ? new double[3] : std(gyroSnap, gMean);

        long hash = 0;
        hash ^= (long)(aMean[0] * 1e6) & 0xFFFFL;
        hash ^= ((long)(aMean[1] * 1e6) & 0xFFFFL) << 16;
        hash ^= ((long)(aMean[2] * 1e6) & 0xFFFFL) << 32;
        hash ^= ((long)(gMean[0] * 1e8) & 0xFFFFL) << 48;
        String hashStr = String.format("%016X", hash);

        StringBuilder sb = new StringBuilder();
        sb.append("═══ 传感器硬件指纹 ═══\n");
        sb.append(String.format("本次指纹哈希: %s\n\n", hashStr));

        sb.append("加速度计 Bias（静态偏差）:\n");
        sb.append(String.format("  X: %+.6f  σ=%.6f\n", aMean[0], aStd[0]));
        sb.append(String.format("  Y: %+.6f  σ=%.6f\n", aMean[1], aStd[1]));
        sb.append(String.format("  Z: %+.6f  σ=%.6f\n", aMean[2], aStd[2]));

        if (!gyroSnap.isEmpty()) {
            sb.append("\n陀螺仪零漂（Zero-Rate Output）:\n");
            sb.append(String.format("  X: %+.6f  σ=%.6f\n", gMean[0], gStd[0]));
            sb.append(String.format("  Y: %+.6f  σ=%.6f\n", gMean[1], gStd[1]));
            sb.append(String.format("  Z: %+.6f  σ=%.6f\n", gMean[2], gStd[2]));
        }

        // 气压计数据
        if (!pressureSnap.isEmpty()) {
            double pMean = 0;
            for (float p : pressureSnap) pMean += p;
            pMean /= pressureSnap.size();
            float altitude = SensorManager.getAltitude(
                SensorManager.PRESSURE_STANDARD_ATMOSPHERE, (float) pMean);
            sb.append(String.format("\n气压计 (TYPE_PRESSURE):\n"));
            sb.append(String.format("  平均气压: %.2f hPa\n", pMean));
            sb.append(String.format("  估算海拔: %.1f m（约 %d 楼）\n",
                altitude, Math.round(altitude / 3.0)));
            sb.append("  侧信道价值: 可推断所在楼层变化（电梯场景）\n");
        }

        // 历史指纹对比
        sb.append("\n── 历史指纹对比 ──\n");
        SharedPreferences prefs = requireContext().getSharedPreferences(PREFS_SENSOR, Context.MODE_PRIVATE);
        String history = prefs.getString(KEY_HISTORY, "");
        String[] histList = history.isEmpty() ? new String[0] : history.split(",");
        int matchCount = 0;
        for (String h : histList) {
            if (h.equals(hashStr)) matchCount++;
        }
        if (histList.length == 0) {
            sb.append("  首次采集，暂无历史数据\n");
        } else {
            sb.append(String.format("  历史记录数: %d\n", histList.length));
            sb.append(String.format("  与历史匹配次数: %d/%d\n", matchCount, histList.length));
            sb.append(histList.length > 0
                ? "  最近历史: " + histList[histList.length - 1] + "\n" : "");
            double similarity = histList.length > 0
                ? (double) matchCount / histList.length * 100 : 0;
            sb.append(String.format("  相似度: %.0f%% ", similarity));
            sb.append(similarity > 60 ? "（指纹稳定，可用于追踪）\n" : "（差异较大，可能受环境影响）\n");
        }

        // 保存到历史
        String[] newHistory;
        if (histList.length >= MAX_HISTORY) {
            newHistory = new String[MAX_HISTORY];
            System.arraycopy(histList, histList.length - MAX_HISTORY + 1, newHistory, 0, MAX_HISTORY - 1);
            newHistory[MAX_HISTORY - 1] = hashStr;
        } else {
            newHistory = new String[histList.length + 1];
            System.arraycopy(histList, 0, newHistory, 0, histList.length);
            newHistory[histList.length] = hashStr;
        }
        prefs.edit().putString(KEY_HISTORY, String.join(",", newHistory)).apply();

        sb.append("\n⚠ 无需任何权限 · 实验性指纹（稳定性需多设备多次验证）");

        tvFingerprint.setTextColor(ContextCompat.getColor(requireContext(), R.color.risk_high_text));
        tvFingerprint.setText(sb.toString());
    }

    // ── 传感器清单 ─────────────────────────────────────────────────

    private void displaySensorInventory() {
        List<Sensor> all = sensorManager.getSensorList(Sensor.TYPE_ALL);
        StringBuilder sb = new StringBuilder();
        sb.append("⚠ 以下传感器均无需任何权限\n");
        sb.append("────────────────────────\n");
        for (Sensor s : all) {
            sb.append(String.format("• %-16s [%s]  功耗:%.1fmA\n",
                getSensorName(s.getType()),
                s.getVendor() != null ? s.getVendor() : "?",
                s.getPower()));
        }
        sb.append("\n共 ").append(all.size()).append(" 个传感器");
        tvSensorList.setText(sb.toString());
    }

    // ── 统计工具 ───────────────────────────────────────────────────

    private double[] mean(List<float[]> s) {
        double[] m = new double[3];
        for (float[] v : s) { m[0]+=v[0]; m[1]+=v[1]; m[2]+=v[2]; }
        int n = s.size(); m[0]/=n; m[1]/=n; m[2]/=n;
        return m;
    }
    private double[] std(List<float[]> s, double[] m) {
        double[] v = new double[3];
        for (float[] x : s) {
            v[0]+=(x[0]-m[0])*(x[0]-m[0]);
            v[1]+=(x[1]-m[1])*(x[1]-m[1]);
            v[2]+=(x[2]-m[2])*(x[2]-m[2]);
        }
        int n = s.size();
        return new double[]{ Math.sqrt(v[0]/n), Math.sqrt(v[1]/n), Math.sqrt(v[2]/n) };
    }
    private double[] variance(List<float[]> s) {
        double[] m = mean(s);
        double[] v = new double[3];
        for (float[] x : s) {
            v[0]+=(x[0]-m[0])*(x[0]-m[0]);
            v[1]+=(x[1]-m[1])*(x[1]-m[1]);
            v[2]+=(x[2]-m[2])*(x[2]-m[2]);
        }
        int n = s.size(); v[0]/=n; v[1]/=n; v[2]/=n;
        return v;
    }

    private String getSensorName(int type) {
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

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (stopSnapRunnable != null) handler.removeCallbacks(stopSnapRunnable);
        tvAccel = tvGyro = tvActivity = tvFingerprint = tvSensorList = tvPressure = null;
        progressBar = null; btnSnap = null;
    }
}
