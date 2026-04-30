package com.ucas.infocollect.collector;

import android.Manifest;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;

import androidx.core.content.ContextCompat;
import androidx.exifinterface.media.ExifInterface;

import com.ucas.infocollect.model.InfoRow;

import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MediaCollector implements InfoCollector {

    private static final int MAX_EXIF_SAMPLE = 5;

    @Override
    public List<InfoRow> collect(Context context) {
        List<InfoRow> items = new ArrayList<>();

        boolean hasPerm = hasMediaPermission(context);
        CollectorUtils.addHeader(items, "媒体存储权限状态");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            boolean img = ContextCompat.checkSelfPermission(context,
                Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED;
            boolean vid = ContextCompat.checkSelfPermission(context,
                Manifest.permission.READ_MEDIA_VIDEO) == PackageManager.PERMISSION_GRANTED;
            CollectorUtils.add(items, "READ_MEDIA_IMAGES", img ? "✓ 已授予" : "✗ 未授予");
            CollectorUtils.add(items, "READ_MEDIA_VIDEO",  vid ? "✓ 已授予" : "✗ 未授予");
        } else {
            boolean storage = ContextCompat.checkSelfPermission(context,
                Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
            CollectorUtils.add(items, "READ_EXTERNAL_STORAGE", storage ? "✓ 已授予" : "✗ 未授予");
        }

        if (!hasPerm) {
            CollectorUtils.addHeader(items, "媒体数据");
            CollectorUtils.add(items, "无法读取媒体元数据",
                "未获得存储/媒体权限 —— Android 权限保护机制生效。\n"
                + "攻击者同样无法读取用户照片和视频元数据。");
            addMediaPrivacyAnalysis(items);
            return items;
        }

        CollectorUtils.addHeader(items, "图片统计（MediaStore）");
        collectImageStats(context, items);

        CollectorUtils.addHeader(items, "EXIF 元数据分析（前 " + MAX_EXIF_SAMPLE + " 张含 GPS 的照片）");
        collectExifGps(context, items);

        CollectorUtils.addHeader(items, "视频统计（MediaStore）");
        collectVideoStats(context, items);

        addMediaPrivacyAnalysis(items);
        return items;
    }

    private boolean hasMediaPermission(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return ContextCompat.checkSelfPermission(context,
                Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(context,
                Manifest.permission.READ_MEDIA_VIDEO) == PackageManager.PERMISSION_GRANTED;
        } else {
            return ContextCompat.checkSelfPermission(context,
                Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
        }
    }

    private void collectImageStats(Context context, List<InfoRow> items) {
        Uri uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
        String[] proj = {
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DATE_TAKEN,
            MediaStore.Images.Media.SIZE,
            MediaStore.Images.Media.MIME_TYPE
        };
        try (Cursor c = context.getContentResolver().query(
                uri, proj, null, null,
                MediaStore.Images.Media.DATE_TAKEN + " DESC")) {
            if (c == null) {
                CollectorUtils.add(items, "图片", "MediaStore 返回 null");
                return;
            }
            int total = c.getCount();
            CollectorUtils.addHighRisk(items, "图片总数", total + " 张");

            if (total == 0) return;

            if (c.moveToFirst()) {
                long dateTaken = c.getLong(1);
                if (dateTaken > 0) {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
                    CollectorUtils.addHighRisk(items, "最新照片时间",
                        sdf.format(new Date(dateTaken)));
                }
            }

            int[] yearBuckets = new int[10];
            int currentYear = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR);
            long totalSize = 0;
            c.moveToFirst();
            do {
                long dateTaken = c.getLong(1);
                totalSize += c.getLong(2);
                if (dateTaken > 0) {
                    java.util.Calendar cal = java.util.Calendar.getInstance();
                    cal.setTimeInMillis(dateTaken);
                    int year = cal.get(java.util.Calendar.YEAR);
                    int diff = currentYear - year;
                    if (diff >= 0 && diff < 10) yearBuckets[diff]++;
                }
            } while (c.moveToNext());

            CollectorUtils.add(items, "图片总大小",
                String.format(Locale.getDefault(), "%.1f MB", totalSize / 1024.0 / 1024.0));

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 5; i++) {
                if (yearBuckets[i] > 0)
                    sb.append(currentYear - i).append("年: ").append(yearBuckets[i]).append("张  ");
            }
            if (sb.length() > 0)
                CollectorUtils.add(items, "年份分布", sb.toString().trim());

        } catch (Exception e) {
            CollectorUtils.add(items, "图片统计失败", e.getClass().getSimpleName());
        }
    }

    private void collectExifGps(Context context, List<InfoRow> items) {
        Uri uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
        String[] proj = { MediaStore.Images.Media._ID, MediaStore.Images.Media.DISPLAY_NAME };
        ContentResolver cr = context.getContentResolver();

        try (Cursor c = cr.query(uri, proj, null, null,
                MediaStore.Images.Media.DATE_TAKEN + " DESC")) {
            if (c == null || c.getCount() == 0) {
                CollectorUtils.add(items, "EXIF", "无图片数据");
                return;
            }

            int gpsFound = 0;
            int scanned  = 0;
            CollectorUtils.add(items, "说明",
                "EXIF GPS 坐标记录了照片拍摄地点，泄露后可还原用户活动轨迹。\n"
                + "Android 10+ MediaStore 已自动从 EXIF 中剔除 GPS（隐私保护）。\n"
                + "以下为实际可读取到的 GPS 元数据（Android 9 及以下设备影响更大）。");

            while (c.moveToNext() && gpsFound < MAX_EXIF_SAMPLE) {
                scanned++;
                if (scanned > 200) break;

                long id   = c.getLong(0);
                String name = c.getString(1);
                Uri imgUri = Uri.withAppendedPath(
                    MediaStore.Images.Media.EXTERNAL_CONTENT_URI, String.valueOf(id));
                try (InputStream is = cr.openInputStream(imgUri)) {
                    if (is == null) continue;
                    ExifInterface exif = new ExifInterface(is);
                    float[] latLon = new float[2];
                    if (exif.getLatLong(latLon)) {
                        gpsFound++;
                        String cam = exif.getAttribute(ExifInterface.TAG_MAKE);
                        String model = exif.getAttribute(ExifInterface.TAG_MODEL);
                        String dateTime = exif.getAttribute(ExifInterface.TAG_DATETIME);
                        CollectorUtils.addHighRisk(items, "GPS照片: " + name,
                            String.format(Locale.getDefault(),
                                "纬度:%.5f° 经度:%.5f°\n拍摄:%s  相机:%s %s",
                                latLon[0], latLon[1],
                                dateTime != null ? dateTime : "未知",
                                cam != null ? cam : "",
                                model != null ? model : ""));
                    }
                } catch (IOException ignored) {}
            }

            if (gpsFound == 0) {
                CollectorUtils.add(items, "未找到含 GPS 的照片",
                    "已扫描 " + scanned + " 张，未读取到 GPS 坐标。\n"
                    + "（Android 10+ 已自动剔除 EXIF GPS —— 有效保护用户位置隐私）");
            } else {
                CollectorUtils.addHighRisk(items, "含 GPS 照片数",
                    "发现 " + gpsFound + " 张含 GPS 坐标的照片（已扫描前 " + scanned + " 张）");
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "EXIF 扫描失败", e.getClass().getSimpleName());
        }
    }

    private void collectVideoStats(Context context, List<InfoRow> items) {
        Uri uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
        String[] proj = {
            MediaStore.Video.Media._ID,
            MediaStore.Video.Media.DATE_TAKEN,
            MediaStore.Video.Media.DURATION,
            MediaStore.Video.Media.SIZE
        };
        try (Cursor c = context.getContentResolver().query(
                uri, proj, null, null, MediaStore.Video.Media.DATE_TAKEN + " DESC")) {
            if (c == null) {
                CollectorUtils.add(items, "视频", "MediaStore 返回 null");
                return;
            }
            int total = c.getCount();
            CollectorUtils.addHighRisk(items, "视频总数", total + " 个");
            if (total == 0) return;

            long totalSize = 0;
            long totalDur  = 0;
            while (c.moveToNext()) {
                totalSize += c.getLong(3);
                totalDur  += c.getLong(2);
            }
            CollectorUtils.add(items, "视频总大小",
                String.format(Locale.getDefault(), "%.1f MB", totalSize / 1024.0 / 1024.0));
            CollectorUtils.add(items, "视频总时长",
                formatDuration(totalDur));

            if (c.moveToFirst()) {
                long dateTaken = c.getLong(1);
                if (dateTaken > 0) {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
                    CollectorUtils.addHighRisk(items, "最新视频时间",
                        sdf.format(new Date(dateTaken)));
                }
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "视频统计失败", e.getClass().getSimpleName());
        }
    }

    private void addMediaPrivacyAnalysis(List<InfoRow> items) {
        CollectorUtils.addHeader(items, "媒体隐私价值分析");
        CollectorUtils.addHighRisk(items, "EXIF GPS 风险",
            "照片 EXIF 含拍摄 GPS 坐标 → 暴露用户历史位置轨迹");
        CollectorUtils.add(items, "相机型号",
            "EXIF TAG_MODEL 可辅助设备指纹（区分不同用户）");
        CollectorUtils.add(items, "拍摄时间",
            "时间戳分布可分析用户作息规律");
        CollectorUtils.add(items, "视频内容",
            "视频缩略图 / 元数据可能包含用户脸部、家庭环境等敏感信息");
        CollectorUtils.add(items, "Android 保护机制",
            "Android 10+ 自动从 MediaStore 查询结果中剔除 GPS EXIF，\n"
            + "需要 ACCESS_MEDIA_LOCATION 权限才能读取含位置的照片。");
    }

    private String formatDuration(long ms) {
        long sec  = ms / 1000;
        long min  = sec / 60;
        long hour = min / 60;
        if (hour > 0) return hour + "时" + (min % 60) + "分";
        if (min  > 0) return min + "分" + (sec % 60) + "秒";
        return sec + "秒";
    }
}
