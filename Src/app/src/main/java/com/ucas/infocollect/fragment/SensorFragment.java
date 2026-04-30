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
import android.os.SystemClock;
import android.util.Log;
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

public class SensorFragment extends Fragment implements SensorEventListener {

    private static final String TAG = "SensorFragment";

    private static final int SAMPLE_MS   = 5000;
    private static final int MAX_SAMPLES = 1000;
    private static final int UI_SKIP     = 10;

    private static final String PREFS_SENSOR  = "sensor_fingerprints";
    private static final String KEY_HISTORY   = "fp_history";
    private static final int    MAX_HISTORY   = 5;
    private static final String FP_VERSION_TAG = "FPv2";
    private static final double FP_QUANTIZE_STEP = 0.01;
    private static final double FP_MATCH_DIST   = 0.05;
    private static final double FP_SIMILAR_DIST = 0.5;
    private static final long   PRESSURE_TIMEOUT_MS = 3000L;

    private SensorManager sensorManager;
    private Sensor accelSensor, gyroSensor, pressureSensor;

    private float[] liveAccel    = new float[3];
    private float[] liveGyro     = new float[3];
    private float   livePressure = 0f;
    private int eventCount = 0;

    private final List<float[]>  accelSnap    = new ArrayList<>();
    private final List<float[]>  gyroSnap     = new ArrayList<>();
    private final List<Float>    pressureSnap = new ArrayList<>();
    private boolean isSnapping = false;
    private boolean pressureDataReceived = false;

    private boolean pressureRegistered = false;
    private long    pressureRegisterAt = 0L;
    private long    pressureFirstCbAt  = 0L;
    private int     pressureAccuracy   = -1;
    private int     pressureCbCount    = 0;
    private Runnable pressureTimeoutRunnable;

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
            logBarometerInventory();
            displaySensorInventory();
        } catch (Exception e) {
            Log.e(TAG, "Sensor init failed", e);
            tvSensorList.setText("传感器初始化失败: " + e.getMessage());
        }

        btnSnap.setOnClickListener(v -> { if (!isSnapping) startSnapshot(); });
        return view;
    }


    @Override
    public void onResume() {
        super.onResume();
        if (sensorManager == null) return;

        if (accelSensor != null) {
            boolean ok = sensorManager.registerListener(this, accelSensor, SensorManager.SENSOR_DELAY_GAME);
            Log.d(TAG, "registerListener[ACCEL] ok=" + ok);
        }
        if (gyroSensor != null) {
            boolean ok = sensorManager.registerListener(this, gyroSensor, SensorManager.SENSOR_DELAY_GAME);
            Log.d(TAG, "registerListener[GYRO] ok=" + ok);
        }
        registerPressureListener();
    }

    private void registerPressureListener() {
        if (sensorManager == null) return;
        if (pressureSensor == null) {
            Log.w(TAG, "[BARO] 设备无 TYPE_PRESSURE 传感器，跳过注册");
            updateLiveDisplay();
            return;
        }
        boolean ok = sensorManager.registerListener(this, pressureSensor, SensorManager.SENSOR_DELAY_NORMAL);
        pressureRegistered = ok;
        pressureRegisterAt = SystemClock.elapsedRealtime();
        pressureFirstCbAt  = 0L;
        pressureCbCount    = 0;
        Log.i(TAG, "[BARO] registerListener ok=" + ok
            + " sensor=" + pressureSensor.getName()
            + " vendor=" + pressureSensor.getVendor()
            + " power=" + pressureSensor.getPower() + "mA"
            + " minDelayUs=" + pressureSensor.getMinDelay()
            + " maxRange=" + pressureSensor.getMaximumRange() + "hPa"
            + " resolution=" + pressureSensor.getResolution());

        if (pressureTimeoutRunnable != null) handler.removeCallbacks(pressureTimeoutRunnable);
        pressureTimeoutRunnable = () -> {
            if (!pressureDataReceived) {
                Log.w(TAG, "[BARO] 注册 " + PRESSURE_TIMEOUT_MS
                    + "ms 后仍无回调（registered=" + pressureRegistered + "）");
            }
            updateLiveDisplay();
        };
        handler.postDelayed(pressureTimeoutRunnable, PRESSURE_TIMEOUT_MS);

        updateLiveDisplay();
    }

    @Override
    public void onPause() {
        super.onPause();
        if (sensorManager != null) sensorManager.unregisterListener(this);
        if (pressureTimeoutRunnable != null) handler.removeCallbacks(pressureTimeoutRunnable);
        Log.d(TAG, "[BARO] unregister @ onPause; cbCount=" + pressureCbCount
            + " firstCbDelay=" + (pressureFirstCbAt > 0 ? (pressureFirstCbAt - pressureRegisterAt) + "ms" : "N/A"));
        pressureRegistered = false;
        if (isSnapping) cancelSnapshot();
    }


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
            pressureCbCount++;
            if (!pressureDataReceived) {
                pressureDataReceived = true;
                pressureFirstCbAt = SystemClock.elapsedRealtime();
                long delay = pressureFirstCbAt - pressureRegisterAt;
                Log.i(TAG, "[BARO] 首次回调 delay=" + delay + "ms"
                    + " pressure=" + livePressure + "hPa"
                    + " accuracy=" + pressureAccuracy);
            }
            if (isSnapping && pressureSnap.size() < MAX_SAMPLES)
                pressureSnap.add(event.values[0]);
        }

        if (++eventCount % UI_SKIP == 0) updateLiveDisplay();
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
        if (sensor != null && sensor.getType() == Sensor.TYPE_PRESSURE) {
            pressureAccuracy = accuracy;
            Log.d(TAG, "[BARO] onAccuracyChanged accuracy=" + accuracy
                + " (" + describeAccuracy(accuracy) + ")");
        }
    }

    private static String describeAccuracy(int accuracy) {
        switch (accuracy) {
            case SensorManager.SENSOR_STATUS_NO_CONTACT:        return "NO_CONTACT";
            case SensorManager.SENSOR_STATUS_UNRELIABLE:        return "UNRELIABLE";
            case SensorManager.SENSOR_STATUS_ACCURACY_LOW:      return "LOW";
            case SensorManager.SENSOR_STATUS_ACCURACY_MEDIUM:   return "MEDIUM";
            case SensorManager.SENSOR_STATUS_ACCURACY_HIGH:     return "HIGH";
            default:                                            return "UNKNOWN(" + accuracy + ")";
        }
    }

    private void updateLiveDisplay() {
        if (tvAccel == null) return;
        tvAccel.setText(String.format(Locale.getDefault(),
            "加速度 (m/s²)  X=%+6.3f  Y=%+6.3f  Z=%+6.3f",
            liveAccel[0], liveAccel[1], liveAccel[2]));
        tvGyro.setText(String.format(Locale.getDefault(),
            "角速度 (rad/s) X=%+7.4f  Y=%+7.4f  Z=%+7.4f",
            liveGyro[0], liveGyro[1], liveGyro[2]));
        if (tvPressure != null) {
            tvPressure.setText(buildPressureStatus());
        }
    }

    private String buildPressureStatus() {
        if (pressureSensor == null) {
            return "气压计：本设备无气压计（TYPE_PRESSURE 传感器不存在）";
        }
        if (!pressureRegistered) {
            return "气压计：注册失败（registerListener 返回 false，可能被系统/省电策略拦截）";
        }
        long now = SystemClock.elapsedRealtime();
        if (!pressureDataReceived) {
            long waited = now - pressureRegisterAt;
            String prefix = waited > PRESSURE_TIMEOUT_MS
                ? "气压计：⚠ 超时未响应（注册成功但 " + waited + "ms 内无回调）"
                : "气压计：等待首个回调中（已等待 " + waited + "ms）";
            return prefix + "\n  传感器: " + pressureSensor.getName()
                + " · vendor=" + pressureSensor.getVendor();
        }
        float altitude = SensorManager.getAltitude(
            SensorManager.PRESSURE_STANDARD_ATMOSPHERE, livePressure);
        long firstDelay = pressureFirstCbAt - pressureRegisterAt;
        return String.format(Locale.getDefault(),
            "气压: %.2f hPa  |  估算海拔: %.1f m  |  ≈楼层: %d\n  状态: 已响应（首回调 %dms · 累计 %d 次 · accuracy=%s）",
            livePressure, altitude, Math.round(altitude / 3.0),
            firstDelay, pressureCbCount, describeAccuracy(pressureAccuracy));
    }


    private void startSnapshot() {
        isSnapping = true;
        accelSnap.clear();
        gyroSnap.clear();
        pressureSnap.clear();
        btnSnap.setEnabled(false);
        btnSnap.setText("采集中... (5s)");
        progressBar.setVisibility(View.VISIBLE);
        tvFingerprint.setText("正在采集传感器噪声数据...\n请保持手机静置，勿晃动");
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


    private void generateFingerprint() {
        double[] aMean = mean(accelSnap);
        double[] aStd  = std(accelSnap, aMean);
        double[] gMean = gyroSnap.isEmpty() ? new double[3] : mean(gyroSnap);
        double[] gStd  = gyroSnap.isEmpty() ? new double[3] : std(gyroSnap, gMean);

        long hash = 0;
        hash ^= (quantize(aMean[0]) & 0xFFFFL);
        hash ^= (quantize(aMean[1]) & 0xFFFFL) << 16;
        hash ^= (quantize(aMean[2]) & 0xFFFFL) << 32;
        hash ^= (quantize(gMean[0]) & 0xFFFFL) << 48;
        String hashStr = String.format("%016X", hash);
        Log.d(TAG, "[FP] generated hash=" + hashStr
            + " aMean=(" + aMean[0] + "," + aMean[1] + "," + aMean[2] + ")"
            + " gMean=(" + gMean[0] + "," + gMean[1] + "," + gMean[2] + ")");

        StringBuilder sb = new StringBuilder();
        sb.append("═══ 实验性传感器指纹 ═══\n");
        sb.append("⚠ 稳定性需在静止、多轮、多设备条件下验证\n");
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
        } else if (pressureSensor != null) {
            sb.append("\n气压计 (TYPE_PRESSURE): 传感器存在，采集期间暂未收到数据\n");
        } else {
            sb.append("\n气压计 (TYPE_PRESSURE): 本设备无气压计\n");
        }

        sb.append("\n── 历史指纹对比（向量距离） ──\n");
        SharedPreferences prefs = requireContext().getSharedPreferences(PREFS_SENSOR, Context.MODE_PRIVATE);
        String history = prefs.getString(KEY_HISTORY, "");
        String[] rawEntries = history.isEmpty() ? new String[0] : history.split(",");

        List<String>   validEntries = new ArrayList<>();
        List<double[]> validVectors = new ArrayList<>();
        List<String>   validHashes  = new ArrayList<>();
        int legacyCount = 0;
        for (String entry : rawEntries) {
            ParsedFingerprint pf = parseHistoryEntry(entry);
            if (pf == null) {
                legacyCount++;
                continue;
            }
            validEntries.add(entry);
            validVectors.add(pf.vector);
            validHashes.add(pf.hash);
        }
        Log.i(TAG, "[FP] history loaded raw=" + rawEntries.length
            + " valid=" + validEntries.size() + " legacyDropped=" + legacyCount);

        double[] curVec = { aMean[0], aMean[1], aMean[2], gMean[0], gMean[1], gMean[2] };
        double minDist = Double.MAX_VALUE;
        int matchedIdx = -1;
        for (int i = 0; i < validVectors.size(); i++) {
            double dist = vectorDistance(curVec, validVectors.get(i));
            if (dist < minDist) { minDist = dist; matchedIdx = i; }
        }

        if (validEntries.isEmpty()) {
            sb.append("  首次采集，暂无历史数据");
            if (legacyCount > 0) sb.append(String.format("（已丢弃 %d 条旧格式遗留）", legacyCount));
            sb.append("\n");
        } else {
            sb.append(String.format("  历史记录数: %d", validEntries.size()));
            if (legacyCount > 0) sb.append(String.format("（另丢弃 %d 条旧格式遗留）", legacyCount));
            sb.append("\n");
            sb.append(String.format("  本次哈希: %s\n", hashStr));
            String matchedHash = matchedIdx >= 0 ? validHashes.get(matchedIdx) : "?";
            sb.append(String.format("  最近邻哈希: %s%s\n", matchedHash,
                hashStr.equals(matchedHash) ? "（与本次完全一致）" : ""));
            sb.append(String.format("  最近邻向量距离: %.6f\n", minDist));
            String verdict;
            if (minDist < FP_MATCH_DIST) {
                verdict = "✓ 匹配（极可能为同一设备同姿态）";
            } else if (minDist < FP_SIMILAR_DIST) {
                verdict = "≈ 相似（可能同一设备但姿态/温度有变化）";
            } else {
                verdict = "✗ 不同（首次见到这个特征向量）";
            }
            double similarity = 100.0 / (1.0 + minDist * 50.0);
            sb.append(String.format("  判定: %s\n", verdict));
            sb.append(String.format("  估算相似度: %.1f%%（仅供参考）\n", similarity));
            sb.append("  注：受温度、姿态、运动影响；请静置多次采集以评估稳定性\n");
            Log.i(TAG, "[FP] match minDist=" + minDist + " verdict=" + verdict);
        }

        String newEntry = String.format(Locale.US, "%s|%s|%.8f|%.8f|%.8f|%.8f|%.8f|%.8f",
            FP_VERSION_TAG, hashStr,
            aMean[0], aMean[1], aMean[2], gMean[0], gMean[1], gMean[2]);
        validEntries.add(newEntry);
        int from = Math.max(0, validEntries.size() - MAX_HISTORY);
        List<String> persisted = validEntries.subList(from, validEntries.size());
        prefs.edit().putString(KEY_HISTORY, String.join(",", persisted)).apply();
        Log.d(TAG, "[FP] history persisted size=" + persisted.size());

        sb.append("\n⚠ 无需任何权限 · 实验性传感器侧信道指纹原型\n");
        sb.append("（稳定性需在静止状态、多轮采集、多设备间交叉验证）");

        tvFingerprint.setTextColor(ContextCompat.getColor(requireContext(), R.color.risk_high_text));
        tvFingerprint.setText(sb.toString());
    }

    private static final class ParsedFingerprint {
        final String   hash;
        final double[] vector;
        ParsedFingerprint(String hash, double[] vector) {
            this.hash   = hash;
            this.vector = vector;
        }
    }

    private ParsedFingerprint parseHistoryEntry(String entry) {
        if (entry == null) return null;
        String[] parts = entry.split("\\|");
        if (parts.length != 8) return null;
        if (!FP_VERSION_TAG.equals(parts[0])) return null;
        try {
            double[] vec = new double[]{
                Double.parseDouble(parts[2]),
                Double.parseDouble(parts[3]),
                Double.parseDouble(parts[4]),
                Double.parseDouble(parts[5]),
                Double.parseDouble(parts[6]),
                Double.parseDouble(parts[7])
            };
            return new ParsedFingerprint(parts[1], vec);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private long quantize(double v) {
        return (long) Math.round(v / FP_QUANTIZE_STEP);
    }

    private double vectorDistance(double[] a, double[] b) {
        double sum = 0;
        int len = Math.min(a.length, b.length);
        for (int i = 0; i < len; i++) {
            double d = a[i] - b[i];
            sum += d * d;
        }
        return Math.sqrt(sum);
    }


    private void logBarometerInventory() {
        if (sensorManager == null) {
            Log.e(TAG, "[BARO] SensorManager == null");
            return;
        }
        List<Sensor> all = sensorManager.getSensorList(Sensor.TYPE_PRESSURE);
        Log.i(TAG, "[BARO] getSensorList(TYPE_PRESSURE) size=" + (all == null ? -1 : all.size())
            + " defaultSensor=" + (pressureSensor == null ? "null" : pressureSensor.getName()));
        if (all != null) {
            int idx = 0;
            for (Sensor s : all) {
                Log.i(TAG, "[BARO]   #" + (idx++) + " name=" + s.getName()
                    + " vendor=" + s.getVendor()
                    + " type=" + s.getType()
                    + " power=" + s.getPower() + "mA"
                    + " minDelayUs=" + s.getMinDelay()
                    + " range=" + s.getMaximumRange() + "hPa"
                    + " resolution=" + s.getResolution());
            }
        }
    }

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

        if (tvPressure != null) {
            tvPressure.setText(buildPressureStatus());
        }

        if (tvFingerprint != null) {
            tvFingerprint.setText("点击下方按钮采集实验性传感器指纹\n建议先将手机静置 5 秒后再采集");
        }
    }


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
        if (pressureTimeoutRunnable != null) handler.removeCallbacks(pressureTimeoutRunnable);
        tvAccel = tvGyro = tvActivity = tvFingerprint = tvSensorList = tvPressure = null;
        progressBar = null; btnSnap = null;
    }
}
