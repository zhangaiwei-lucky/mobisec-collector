package com.ucas.infocollect.collector;

import android.Manifest;
import android.app.ActivityManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.view.WindowManager;
import android.util.DisplayMetrics;

import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 设备与系统信息收集器（Phase 1 架构纯化版）。
 *
 * <p><b>重构变更（相较原版）：</b></p>
 * <ul>
 *   <li>彻底移除 {@code android.content.Context}：所有系统资源通过
 *       {@link SystemEnvironment} 注入，类内无任何 Context 引用。</li>
 *   <li>权限抽离：{@code ContextCompat.checkSelfPermission} 调用已删除，
 *       所需权限通过 {@link #getRequiredPermissions()} 显式声明，由应用层统一申请。</li>
 *   <li>消除静默降级：所有原 {@code CollectorUtils.addDegrade()} 调用均替换为
 *       {@code result.addDegrade()}，降级事件写入 {@link CollectionResult#getDegrades()}
 *       而非混入数据行。</li>
 *   <li>采集逻辑本身（读取方式、字段名称、风险标记）与原版保持一致。</li>
 * </ul>
 *
 * <p>覆盖范围：</p>
 * <ul>
 *   <li>硬件标识（品牌、型号、序列号、Android ID）</li>
 *   <li>系统版本与安全补丁</li>
 *   <li>CPU / 内存 / 存储规格</li>
 *   <li>屏幕参数</li>
 *   <li>运营商与 IMEI（需 READ_PHONE_STATE）</li>
 *   <li>Root / 开发者选项 / ADB 状态</li>
 * </ul>
 */
public final class DeviceCollector implements InfoCollectorV2 {

    private static final List<String> REQUIRED_PERMISSIONS =
            Collections.unmodifiableList(Arrays.asList(
                    Manifest.permission.READ_PHONE_STATE
            ));

    // ─────────────────────────────────────────────────────────────────────────
    // 契约实现
    // ─────────────────────────────────────────────────────────────────────────

    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        return REQUIRED_PERMISSIONS;
    }

    @NonNull
    @Override
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder result = CollectionResult.builder();

        collectBasicInfo(result);
        collectSystemVersion(result);
        collectIdentifiers(env, result);
        collectCpuInfo(result);
        collectMemoryAndStorage(env, result);
        collectDisplayInfo(env, result);
        collectSecurityStatus(env, result);

        return result.build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 分段采集（私有，各自职责单一）
    // ─────────────────────────────────────────────────────────────────────────

    private void collectBasicInfo(@NonNull final CollectionResult.Builder result) {
        result.addHeader("基本设备信息");
        result.add("品牌",     Build.BRAND);
        result.add("厂商",     Build.MANUFACTURER);
        result.add("型号",     Build.MODEL);
        result.add("设备名",   Build.DEVICE);
        result.add("产品名",   Build.PRODUCT);
        result.add("硬件版本", Build.HARDWARE);
        result.add("主板",     Build.BOARD);
    }

    private void collectSystemVersion(@NonNull final CollectionResult.Builder result) {
        result.addHeader("系统版本与安全");
        result.add("Android 版本", Build.VERSION.RELEASE);
        result.add("API Level",    String.valueOf(Build.VERSION.SDK_INT));
        result.add("安全补丁日期", Build.VERSION.SECURITY_PATCH);
        result.add("Build 指纹",   Build.FINGERPRINT);
        result.add("Build 类型",   Build.TYPE);
        result.add("Build 标签",   Build.TAGS);
    }

    /**
     * 采集设备标识符。
     *
     * <p>IMEI 读取不再内部检查权限：若权限未授予，Android 会抛出
     * {@link SecurityException}，此处捕获并记录为降级事件。</p>
     */
    private void collectIdentifiers(
            @NonNull final SystemEnvironment env,
            @NonNull final CollectionResult.Builder result) {

        result.addHeader("设备标识符");

        // Android ID 无需权限，但可追踪用户，标记为高风险
        final String androidId = env.getSecureStringSetting(Settings.Secure.ANDROID_ID);
        result.addHighRisk("Android ID", androidId);

        final TelephonyManager tm = env.getSystemService(TelephonyManager.class);
        if (tm == null) {
            result.addDegrade(
                    "电话信息",
                    DegradeReason.SERVICE_UNAVAILABLE,
                    "TelephonyManager 不可用");
            return;
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                result.addHighRisk("IMEI", tm.getImei());
            }
            result.add("运营商", tm.getNetworkOperatorName());
            final String simIso = tm.getSimCountryIso();
            result.add("SIM 国家代码", simIso != null ? simIso.toUpperCase() : "N/A");
            result.addHighRisk("电话号码", tm.getLine1Number());
            result.addNullable("设备 SoftwareVersion", tm.getDeviceSoftwareVersion());

        } catch (final SecurityException e) {
            // READ_PHONE_STATE 未在运行时授予（权限申请由应用层负责）
            result.addDegrade(
                    "IMEI / 运营商",
                    DegradeReason.PERMISSION_DENIED,
                    "运行时权限未授予: READ_PHONE_STATE");
        } catch (final Exception e) {
            result.addDegrade(
                    "电话信息",
                    DegradeReason.READ_FAILED,
                    "读取失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectCpuInfo(@NonNull final CollectionResult.Builder result) {
        result.addHeader("处理器信息");
        result.add("CPU ABI(s)",  Build.SUPPORTED_ABIS[0]);
        result.add("CPU 核心数",  String.valueOf(Runtime.getRuntime().availableProcessors()));
        final String hardware = readCpuInfo("Hardware");
        final String model    = readCpuInfo("model name");
        result.add("CPU Hardware", hardware.isEmpty() ? "N/A" : hardware);
        result.add("CPU 型号",     model.isEmpty()    ? "N/A" : model);
    }

    private void collectMemoryAndStorage(
            @NonNull final SystemEnvironment env,
            @NonNull final CollectionResult.Builder result) {

        result.addHeader("内存与存储");

        final ActivityManager am = env.getSystemService(ActivityManager.class);
        if (am == null) {
            result.addDegrade(
                    "内存信息",
                    DegradeReason.SERVICE_UNAVAILABLE,
                    "ActivityManager 不可用");
        } else {
            try {
                final ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(memInfo);
                result.add("总内存",     formatBytes(memInfo.totalMem));
                result.add("可用内存",   formatBytes(memInfo.availMem));
                result.add("低内存阈值", formatBytes(memInfo.threshold));
                result.add("当前低内存", String.valueOf(memInfo.lowMemory));
            } catch (final Exception e) {
                result.addDegrade(
                        "内存信息",
                        DegradeReason.READ_FAILED,
                        "读取失败: " + e.getClass().getSimpleName());
            }
        }

        try {
            final StatFs stat      = new StatFs(Environment.getDataDirectory().getPath());
            final long   blockSize = stat.getBlockSizeLong();
            result.add("内部存储总量", formatBytes(blockSize * stat.getBlockCountLong()));
            result.add("内部存储可用", formatBytes(blockSize * stat.getAvailableBlocksLong()));
        } catch (final Exception e) {
            result.addDegrade(
                    "内部存储",
                    DegradeReason.READ_FAILED,
                    "读取失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectDisplayInfo(
            @NonNull final SystemEnvironment env,
            @NonNull final CollectionResult.Builder result) {

        result.addHeader("屏幕参数");

        final WindowManager wm = env.getSystemService(WindowManager.class);
        if (wm == null) {
            result.addDegrade(
                    "屏幕参数",
                    DegradeReason.SERVICE_UNAVAILABLE,
                    "WindowManager 不可用");
            return;
        }

        try {
            final DisplayMetrics dm = new DisplayMetrics();
            wm.getDefaultDisplay().getRealMetrics(dm);
            result.add("分辨率", dm.widthPixels + " x " + dm.heightPixels);
            result.add("DPI",   String.valueOf(dm.densityDpi));
            result.add("密度",  String.valueOf(dm.density));
            result.add("刷新率", wm.getDefaultDisplay().getRefreshRate() + " Hz");
        } catch (final Exception e) {
            result.addDegrade(
                    "屏幕参数",
                    DegradeReason.READ_FAILED,
                    "读取失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectSecurityStatus(
            @NonNull final SystemEnvironment env,
            @NonNull final CollectionResult.Builder result) {

        result.addHeader("安全状态");

        if (isRooted()) {
            result.addHighRisk("是否 Root", "是");
        } else {
            result.add("是否 Root", "否");
        }

        final boolean devOptions =
                env.getGlobalIntSetting(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1;
        if (devOptions) {
            result.addHighRisk("开发者选项", "已开启");
        } else {
            result.add("开发者选项", "未开启");
        }

        final boolean adbEnabled =
                env.getGlobalIntSetting(Settings.Global.ADB_ENABLED, 0) == 1;
        if (adbEnabled) {
            result.addHighRisk("ADB 调试", "已开启");
        } else {
            result.add("ADB 调试", "未开启");
        }

        final boolean unknownSources =
                env.getSecureIntSetting(Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1;
        if (unknownSources) {
            result.addHighRisk("安装未知来源", "已允许");
        } else {
            result.add("安装未知来源", "不允许");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 纯逻辑辅助方法（无 I/O 依赖 Android 框架，测试友好）
    // ─────────────────────────────────────────────────────────────────────────

    /** 检测设备是否已 Root（检查常见的 su 路径）。 */
    private boolean isRooted() {
        final String[] paths = {
            "/system/app/Superuser.apk", "/sbin/su",      "/system/bin/su",
            "/system/xbin/su",           "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su",        "/system/bin/failsafe/su",
            "/data/local/su",            "/su/bin/su"
        };
        for (final String path : paths) {
            if (new java.io.File(path).exists()) return true;
        }
        return false;
    }

    /** 读取 {@code /proc/cpuinfo} 中指定字段的值；失败时返回空字符串。 */
    @NonNull
    private String readCpuInfo(@NonNull final String key) {
        try (final BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(key)) {
                    final String[] parts = line.split(":\\s*", 2);
                    return parts.length > 1 ? parts[1].trim() : "";
                }
            }
        } catch (final IOException ignored) {}
        return "";
    }

    @NonNull
    private String formatBytes(final long bytes) {
        if (bytes < 1024L)        return bytes + " B";
        final double kb = bytes / 1024.0;
        if (kb    < 1024.0)       return String.format("%.1f KB", kb);
        final double mb = kb / 1024.0;
        if (mb    < 1024.0)       return String.format("%.1f MB", mb);
        return String.format("%.2f GB", mb / 1024.0);
    }
}
