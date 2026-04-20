package com.ucas.infocollect.collector;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import androidx.core.content.ContextCompat;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 设备与系统信息收集器
 *
 * 覆盖范围：
 * - 硬件标识（型号、序列号、Android ID）
 * - 系统版本与安全补丁
 * - CPU / 内存 / 存储规格
 * - 屏幕参数
 * - 运营商与 IMEI（需 READ_PHONE_STATE）
 * - Root / 开发者选项状态
 */
public class DeviceCollector {

    private final Context context;

    public DeviceCollector(Context context) {
        this.context = context;
    }

    public List<Map.Entry<String, String>> collect() {
        List<Map.Entry<String, String>> items = new ArrayList<>();

        // ── 基本硬件信息（无需权限）──────────────────────────────
        CollectorUtils.addHeader(items, "基本设备信息");
        CollectorUtils.add(items, "品牌",        Build.BRAND);
        CollectorUtils.add(items, "厂商",        Build.MANUFACTURER);
        CollectorUtils.add(items, "型号",        Build.MODEL);
        CollectorUtils.add(items, "设备名",      Build.DEVICE);
        CollectorUtils.add(items, "产品名",      Build.PRODUCT);
        CollectorUtils.add(items, "硬件版本",    Build.HARDWARE);
        CollectorUtils.add(items, "主板",        Build.BOARD);

        // ── Android 版本与安全信息（无需权限）──────────────────────
        CollectorUtils.addHeader(items, "系统版本与安全");
        CollectorUtils.add(items, "Android 版本", Build.VERSION.RELEASE);
        CollectorUtils.add(items, "API Level",    String.valueOf(Build.VERSION.SDK_INT));
        CollectorUtils.add(items, "安全补丁日期", Build.VERSION.SECURITY_PATCH);
        CollectorUtils.add(items, "Build 指纹",   Build.FINGERPRINT);
        CollectorUtils.add(items, "Build 类型",   Build.TYPE);       // user/userdebug/eng
        CollectorUtils.add(items, "Build 标签",   Build.TAGS);       // release-keys/test-keys

        // ── Android ID（可用于设备追踪，无需权限）──────────────────
        CollectorUtils.addHeader(items, "设备标识符");
        @SuppressLint("HardwareIds")
        String androidId = Settings.Secure.getString(
            context.getContentResolver(), Settings.Secure.ANDROID_ID);
        CollectorUtils.add(items, "Android ID", "[HIGH]" + androidId);  // 设备唯一 ID，可追踪用户

        // IMEI（需 READ_PHONE_STATE 权限）
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE)
                == PackageManager.PERMISSION_GRANTED) {
            try {
                TelephonyManager tm =
                    (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    String imei = tm.getImei();
                    CollectorUtils.add(items, "IMEI", "[HIGH]" + (imei != null ? imei : "不可用"));
                }
                CollectorUtils.add(items, "运营商",       tm.getNetworkOperatorName());
                CollectorUtils.add(items, "SIM 国家代码", tm.getSimCountryIso().toUpperCase());
                CollectorUtils.add(items, "电话号码",     "[HIGH]" + tm.getLine1Number());
                CollectorUtils.add(items, "设备 SoftwareVersion", tm.getDeviceSoftwareVersion());
            } catch (Exception e) {
                CollectorUtils.add(items, "电话信息", "读取失败: " + e.getMessage());
            }
        } else {
            CollectorUtils.add(items, "IMEI / 运营商", "未授予 READ_PHONE_STATE 权限");
        }

        // ── CPU 信息（无需权限，读取 /proc/cpuinfo）──────────────────
        CollectorUtils.addHeader(items, "处理器信息");
        CollectorUtils.add(items, "CPU ABI(s)",    Build.SUPPORTED_ABIS[0]);
        CollectorUtils.add(items, "CPU 核心数",    String.valueOf(Runtime.getRuntime().availableProcessors()));
        String cpuHardware = readCpuInfo("Hardware");
        String cpuModel    = readCpuInfo("model name");
        CollectorUtils.add(items, "CPU Hardware", cpuHardware.isEmpty() ? "N/A" : cpuHardware);
        CollectorUtils.add(items, "CPU 型号",     cpuModel.isEmpty()    ? "N/A" : cpuModel);

        // ── 内存信息（无需权限）──────────────────────────────────
        CollectorUtils.addHeader(items, "内存与存储");
        ActivityManager am =
            (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(memInfo);
        CollectorUtils.add(items, "总内存",     formatBytes(memInfo.totalMem));
        CollectorUtils.add(items, "可用内存",   formatBytes(memInfo.availMem));
        CollectorUtils.add(items, "低内存阈值", formatBytes(memInfo.threshold));
        CollectorUtils.add(items, "当前低内存", String.valueOf(memInfo.lowMemory));

        // 内部存储
        StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
        long blockSize  = stat.getBlockSizeLong();
        long totalBlocks = stat.getBlockCountLong();
        long availBlocks = stat.getAvailableBlocksLong();
        CollectorUtils.add(items, "内部存储总量", formatBytes(blockSize * totalBlocks));
        CollectorUtils.add(items, "内部存储可用", formatBytes(blockSize * availBlocks));

        // ── 屏幕信息（无需权限）──────────────────────────────────
        CollectorUtils.addHeader(items, "屏幕参数");
        WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        DisplayMetrics dm = new DisplayMetrics();
        wm.getDefaultDisplay().getRealMetrics(dm);
        CollectorUtils.add(items, "分辨率",   dm.widthPixels + " x " + dm.heightPixels);
        CollectorUtils.add(items, "DPI",     String.valueOf(dm.densityDpi));
        CollectorUtils.add(items, "密度",    String.valueOf(dm.density));
        CollectorUtils.add(items, "刷新率",  String.valueOf(wm.getDefaultDisplay().getRefreshRate()) + " Hz");

        // ── Root / 安全状态（无需权限）───────────────────────────
        CollectorUtils.addHeader(items, "安全状态");
        CollectorUtils.add(items, "是否 Root",         isRooted() ? "[HIGH]是" : "否");
        CollectorUtils.add(items, "开发者选项",
            Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
            ? "[HIGH]已开启" : "未开启");
        CollectorUtils.add(items, "ADB 调试",
            Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.ADB_ENABLED, 0) == 1
            ? "[HIGH]已开启" : "未开启");
        CollectorUtils.add(items, "安装未知来源",
            Settings.Secure.getInt(context.getContentResolver(),
                Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            ? "[HIGH]已允许" : "不允许");

        return items;
    }

    /** 检测设备是否已 Root（检查常见的 su 路径）*/
    private boolean isRooted() {
        String[] paths = {
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
            "/su/bin/su"
        };
        for (String path : paths) {
            if (new java.io.File(path).exists()) return true;
        }
        return false;
    }

    /** 读取 /proc/cpuinfo 中指定字段的值 */
    private String readCpuInfo(String key) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(key)) {
                    return line.split(":\\s*", 2)[1].trim();
                }
            }
        } catch (IOException ignored) {}
        return "";
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return String.format("%.1f KB", kb);
        double mb = kb / 1024.0;
        if (mb < 1024) return String.format("%.1f MB", mb);
        return String.format("%.2f GB", mb / 1024.0);
    }

}
