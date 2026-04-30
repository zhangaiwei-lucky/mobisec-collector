package com.ucas.infocollect.collector;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Address;
import android.location.Geocoder;
import android.location.Location;
import android.location.LocationManager;

import androidx.core.content.ContextCompat;

import com.ucas.infocollect.model.InfoRow;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class LocationCollector implements InfoCollector {

    @Override
    public List<InfoRow> collect(Context context) {
        List<InfoRow> items = new ArrayList<>();

        CollectorUtils.addHeader(items, "位置权限状态");
        boolean hasFine   = ContextCompat.checkSelfPermission(context,
            Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        boolean hasCoarse = ContextCompat.checkSelfPermission(context,
            Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;

        CollectorUtils.add(items, "ACCESS_FINE_LOCATION (GPS精确)",
            hasFine ? "✓ 已授予" : "✗ 未授予（精确位置不可读）");
        CollectorUtils.add(items, "ACCESS_COARSE_LOCATION (基站粗略)",
            hasCoarse ? "✓ 已授予" : "✗ 未授予");
        CollectorUtils.add(items, "隐私说明",
            "Android 要求用户明确授权位置权限。\n"
            + "即使授权，Android 10+ 也限制后台静默位置读取。\n"
            + "ACCESS_BACKGROUND_LOCATION 需单独申请（本应用未申请）。");

        if (!hasFine && !hasCoarse) {
            CollectorUtils.addHeader(items, "位置数据");
            CollectorUtils.add(items, "无法读取位置",
                "未获得任何位置权限 —— 体现 Android 权限保护机制。\n"
                + "攻击者如未获授权，同样无法读取位置数据。");
            addLocationPrivacyAnalysis(items);
            return items;
        }

        CollectorUtils.addHeader(items, "最近已知位置");
        collectLastKnownLocation(context, items, hasFine);

        addLocationPrivacyAnalysis(items);
        return items;
    }

    private void collectLastKnownLocation(Context context, List<InfoRow> items, boolean hasFine) {
        LocationManager lm = CollectorUtils.safeService(
            context, Context.LOCATION_SERVICE, LocationManager.class,
            items, "LocationManager", "定位服务不可用");
        if (lm == null) return;

        Location loc = null;
        String provider = "无";
        try {
            if (hasFine) {
                loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                if (loc != null) provider = "GPS";
            }
            if (loc == null) {
                loc = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                if (loc != null) provider = "Network (基站/WiFi)";
            }
            if (loc == null) {
                loc = lm.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER);
                if (loc != null) provider = "Passive";
            }
        } catch (SecurityException e) {
            CollectorUtils.addDegrade(items, "位置", CollectorUtils.DegradeReason.PERMISSION_DENIED,
                "SecurityException: " + e.getMessage());
            return;
        } catch (Exception e) {
            CollectorUtils.addDegrade(items, "位置", CollectorUtils.DegradeReason.READ_FAILED,
                e.getClass().getSimpleName());
            return;
        }

        if (loc == null) {
            CollectorUtils.add(items, "最近位置",
                "暂无缓存位置（设备可能从未开启过 GPS 或位置服务已关闭）");
            CollectorUtils.add(items, "建议", "开启 GPS 后返回刷新即可获取");
            return;
        }

        CollectorUtils.addHighRisk(items, "定位来源", provider);
        CollectorUtils.addHighRisk(items, "纬度  (Latitude)",
            String.format(Locale.getDefault(), "%.6f°", loc.getLatitude()));
        CollectorUtils.addHighRisk(items, "经度  (Longitude)",
            String.format(Locale.getDefault(), "%.6f°", loc.getLongitude()));
        CollectorUtils.add(items, "精度 (Accuracy)",
            String.format(Locale.getDefault(), "±%.1f 米", loc.getAccuracy()));

        if (loc.hasAltitude()) {
            CollectorUtils.add(items, "海拔 (Altitude)",
                String.format(Locale.getDefault(), "%.1f 米", loc.getAltitude()));
        }
        if (loc.hasSpeed()) {
            CollectorUtils.add(items, "速度",
                String.format(Locale.getDefault(), "%.1f m/s  (%.1f km/h)",
                    loc.getSpeed(), loc.getSpeed() * 3.6));
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        CollectorUtils.add(items, "时间戳", sdf.format(new Date(loc.getTime())));

        try {
            if (Geocoder.isPresent()) {
                Geocoder gc = new Geocoder(context, Locale.getDefault());
                List<Address> addresses = gc.getFromLocation(
                    loc.getLatitude(), loc.getLongitude(), 1);
                if (addresses != null && !addresses.isEmpty()) {
                    Address addr = addresses.get(0);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i <= addr.getMaxAddressLineIndex(); i++) {
                        sb.append(addr.getAddressLine(i)).append('\n');
                    }
                    CollectorUtils.addHighRisk(items, "地址解析 (Geocoder)",
                        sb.toString().trim());
                }
            }
        } catch (Exception ignored) {
            CollectorUtils.add(items, "地址解析", "网络不可用或 Geocoder 异常");
        }

        CollectorUtils.addHeader(items, "可用定位 Provider");
        for (String p : lm.getAllProviders()) {
            boolean enabled = lm.isProviderEnabled(p);
            CollectorUtils.add(items, p, enabled ? "已启用" : "已禁用");
        }
    }

    private void addLocationPrivacyAnalysis(List<InfoRow> items) {
        CollectorUtils.addHeader(items, "位置隐私价值分析");
        CollectorUtils.addHighRisk(items, "攻击价值",
            "精确坐标可定位用户实时位置（隐私 Top 1）");
        CollectorUtils.add(items, "住所推断",
            "夜间高频位置 → 推断家庭住址");
        CollectorUtils.add(items, "工作推断",
            "工作日 9-18 时高频位置 → 推断工作单位");
        CollectorUtils.add(items, "行为分析",
            "位置轨迹结合时间 → 社交习惯、出行规律");
        CollectorUtils.add(items, "Android 保护机制",
            "运行时权限（用户授权）+ 后台限制 + 精确/粗略位置分级\n"
            + "→ 恶意 App 在未获权限时无法读取位置数据");
    }
}
