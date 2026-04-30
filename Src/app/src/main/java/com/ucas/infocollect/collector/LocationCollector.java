package com.ucas.infocollect.collector;

import android.Manifest;
import android.location.Location;
import android.location.LocationManager;

import androidx.annotation.NonNull;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 位置信息收集器（V2 无 Context 版）。
 *
 * <p>隐私价值分析：</p>
 * <ul>
 *   <li>精确 GPS 坐标可定位用户所在地（精度 &lt; 10m）</li>
 *   <li>可推断住所、工作地点、行动轨迹</li>
 *   <li>结合时间可构建用户作息规律画像</li>
 *   <li>Android 10+ 后台定位需要 ACCESS_BACKGROUND_LOCATION（本 App 未申请）</li>
 * </ul>
 *
 * <p>本模块展示"哪些信息能收集、哪些不能收集"，体现权限机制的保护作用。</p>
 */
public class LocationCollector implements InfoCollectorV2 {

    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        return Arrays.asList(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        );
    }

    @NonNull
    @Override
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder result = CollectionResult.builder();

        result.addHeader("位置权限状态");
        result.add("ACCESS_FINE_LOCATION (GPS精确)",
            "（由系统权限层管控，收集器运行时权限已声明在 getRequiredPermissions()）");
        result.add("ACCESS_COARSE_LOCATION (基站粗略)",
            "（由系统权限层管控，收集器运行时权限已声明在 getRequiredPermissions()）");
        result.add("隐私说明",
            "Android 要求用户明确授权位置权限。\n"
            + "即使授权，Android 10+ 也限制后台静默位置读取。\n"
            + "ACCESS_BACKGROUND_LOCATION 需单独申请（本应用未申请）。");

        result.addHeader("最近已知位置");
        collectLastKnownLocation(env, result);

        addLocationPrivacyAnalysis(result);
        return result.build();
    }

    private void collectLastKnownLocation(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        final LocationManager lm = env.getSystemService(LocationManager.class);
        if (lm == null) {
            result.addDegrade("LocationManager", DegradeReason.SERVICE_UNAVAILABLE, "定位服务不可用");
            return;
        }

        Location loc      = null;
        String   provider = "无";
        try {
            loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
            if (loc != null) {
                provider = "GPS";
            } else {
                loc = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                if (loc != null) provider = "Network (基站/WiFi)";
            }
            if (loc == null) {
                loc = lm.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER);
                if (loc != null) provider = "Passive";
            }
        } catch (final SecurityException e) {
            result.addDegrade("位置", DegradeReason.PERMISSION_DENIED,
                "缺少位置权限: " + e.getMessage());
            return;
        } catch (final Exception e) {
            result.addDegrade("位置", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName());
            return;
        }

        if (loc == null) {
            result.add("最近位置",
                "暂无缓存位置（设备可能从未开启过 GPS 或位置服务已关闭）");
            result.add("建议", "开启 GPS 后返回刷新即可获取");
            return;
        }

        result.addHighRisk("定位来源", provider);
        result.addHighRisk("纬度  (Latitude)",
            String.format(Locale.getDefault(), "%.6f°", loc.getLatitude()));
        result.addHighRisk("经度  (Longitude)",
            String.format(Locale.getDefault(), "%.6f°", loc.getLongitude()));
        result.add("精度 (Accuracy)",
            String.format(Locale.getDefault(), "±%.1f 米", loc.getAccuracy()));

        if (loc.hasAltitude()) {
            result.add("海拔 (Altitude)",
                String.format(Locale.getDefault(), "%.1f 米", loc.getAltitude()));
        }
        if (loc.hasSpeed()) {
            result.add("速度",
                String.format(Locale.getDefault(), "%.1f m/s  (%.1f km/h)",
                    loc.getSpeed(), loc.getSpeed() * 3.6));
        }

        final SimpleDateFormat sdf =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        result.add("时间戳", sdf.format(new Date(loc.getTime())));

        // Geocoder 构造函数需要 android.content.Context（仅用于 locale 路由），
        // 在防腐层架构下无法直接传入，坐标数据已在上方完整显示，逆地理编码作降级处理。
        result.add("地址解析 (Geocoder)", "V2 架构：坐标已显示，逆地理编码需 Context，已降级");


        result.addHeader("可用定位 Provider");
        for (final String p : lm.getAllProviders()) {
            try {
                result.add(p, lm.isProviderEnabled(p) ? "已启用" : "已禁用");
            } catch (final Exception ignored) {}
        }
    }

    private void addLocationPrivacyAnalysis(
            @NonNull final CollectionResult.Builder result) {
        result.addHeader("位置隐私价值分析");
        result.addHighRisk("攻击价值",   "精确坐标可定位用户实时位置（隐私 Top 1）");
        result.add("住所推断",          "夜间高频位置 → 推断家庭住址");
        result.add("工作推断",          "工作日 9-18 时高频位置 → 推断工作单位");
        result.add("行为分析",          "位置轨迹结合时间 → 社交习惯、出行规律");
        result.add("Android 保护机制",
            "运行时权限（用户授权）+ 后台限制 + 精确/粗略位置分级\n"
            + "→ 恶意 App 在未获权限时无法读取位置数据");
    }
}
