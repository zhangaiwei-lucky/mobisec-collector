package com.ucas.infocollect.collector;

import android.Manifest;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;

import androidx.annotation.NonNull;
import androidx.exifinterface.media.ExifInterface;

import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 媒体文件元数据收集器（V2 无 Context 版）。
 *
 * <p>不读取图片/视频内容，只读取元数据（MediaStore + EXIF），
 * 展示媒体数据的隐私泄露潜力：</p>
 * <ul>
 *   <li>照片数量、拍摄时间分布</li>
 *   <li>EXIF 中的 GPS 坐标（拍摄位置）</li>
 *   <li>相机型号、软件信息</li>
 *   <li>视频/音频统计</li>
 * </ul>
 */
public class MediaCollector implements InfoCollectorV2 {

    private static final int MAX_EXIF_SAMPLE = 5;

    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return Arrays.asList(
                Manifest.permission.READ_MEDIA_IMAGES,
                Manifest.permission.READ_MEDIA_VIDEO
            );
        } else {
            return Collections.singletonList(Manifest.permission.READ_EXTERNAL_STORAGE);
        }
    }

    @NonNull
    @Override
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder result = CollectionResult.builder();
        final ContentResolver cr = env.getContentResolver();

        // ── 权限状态说明 ────────────────────────────────────────────
        result.addHeader("媒体存储权限状态");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            result.add("READ_MEDIA_IMAGES", "（权限声明已在 getRequiredPermissions()，运行时由系统授权弹窗管控）");
            result.add("READ_MEDIA_VIDEO",  "（权限声明已在 getRequiredPermissions()，运行时由系统授权弹窗管控）");
        } else {
            result.add("READ_EXTERNAL_STORAGE", "（权限声明已在 getRequiredPermissions()，运行时由系统授权弹窗管控）");
        }

        // ── 图片统计 ─────────────────────────────────────────────────
        result.addHeader("图片统计（MediaStore）");
        collectImageStats(cr, result);

        // ── EXIF GPS 分析 ─────────────────────────────────────────────
        result.addHeader("EXIF 元数据分析（前 " + MAX_EXIF_SAMPLE + " 张含 GPS 的照片）");
        collectExifGps(cr, result);

        // ── 视频统计 ─────────────────────────────────────────────────
        result.addHeader("视频统计（MediaStore）");
        collectVideoStats(cr, result);

        addMediaPrivacyAnalysis(result);
        return result.build();
    }

    private void collectImageStats(
            @NonNull final ContentResolver         cr,
            @NonNull final CollectionResult.Builder result) {
        final Uri uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
        final String[] proj = {
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DATE_TAKEN,
            MediaStore.Images.Media.SIZE,
            MediaStore.Images.Media.MIME_TYPE
        };
        try (final Cursor c = cr.query(
                uri, proj, null, null,
                MediaStore.Images.Media.DATE_TAKEN + " DESC")) {
            if (c == null) {
                result.addDegrade("图片", DegradeReason.NO_DATA, "MediaStore 返回 null");
                return;
            }
            final int total = c.getCount();
            result.addHighRisk("图片总数", total + " 张");
            if (total == 0) return;

            if (c.moveToFirst()) {
                final long dateTaken = c.getLong(1);
                if (dateTaken > 0) {
                    final SimpleDateFormat sdf =
                        new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
                    result.addHighRisk("最新照片时间", sdf.format(new Date(dateTaken)));
                }
            }

            final int[] yearBuckets = new int[10];
            final int currentYear   = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR);
            long totalSize = 0;
            c.moveToFirst();
            do {
                final long dateTaken = c.getLong(1);
                totalSize += c.getLong(2);
                if (dateTaken > 0) {
                    final java.util.Calendar cal = java.util.Calendar.getInstance();
                    cal.setTimeInMillis(dateTaken);
                    final int diff = currentYear - cal.get(java.util.Calendar.YEAR);
                    if (diff >= 0 && diff < 10) yearBuckets[diff]++;
                }
            } while (c.moveToNext());

            result.add("图片总大小",
                String.format(Locale.getDefault(), "%.1f MB", totalSize / 1024.0 / 1024.0));

            final StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 5; i++) {
                if (yearBuckets[i] > 0)
                    sb.append(currentYear - i).append("年: ").append(yearBuckets[i]).append("张  ");
            }
            if (sb.length() > 0) result.add("年份分布", sb.toString().trim());

        } catch (final SecurityException e) {
            result.addDegrade("图片统计", DegradeReason.PERMISSION_DENIED,
                "缺少存储/媒体权限");
        } catch (final Exception e) {
            result.addDegrade("图片统计", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName());
        }
    }

    private void collectExifGps(
            @NonNull final ContentResolver         cr,
            @NonNull final CollectionResult.Builder result) {
        final Uri uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
        final String[] proj = {
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DISPLAY_NAME
        };

        try (final Cursor c = cr.query(uri, proj, null, null,
                MediaStore.Images.Media.DATE_TAKEN + " DESC")) {
            if (c == null || c.getCount() == 0) {
                result.addDegrade("EXIF", DegradeReason.NO_DATA, "无图片数据");
                return;
            }

            result.add("说明",
                "EXIF GPS 坐标记录了照片拍摄地点，泄露后可还原用户活动轨迹。\n"
                + "Android 10+ MediaStore 已自动从 EXIF 中剔除 GPS（隐私保护）。\n"
                + "以下为实际可读取到的 GPS 元数据（Android 9 及以下设备影响更大）。");

            int gpsFound = 0;
            int scanned  = 0;
            while (c.moveToNext() && gpsFound < MAX_EXIF_SAMPLE) {
                scanned++;
                if (scanned > 200) break;

                final long   id    = c.getLong(0);
                final String name  = c.getString(1);
                final Uri imgUri   = Uri.withAppendedPath(
                    MediaStore.Images.Media.EXTERNAL_CONTENT_URI, String.valueOf(id));
                try (final InputStream is = cr.openInputStream(imgUri)) {
                    if (is == null) continue;
                    final ExifInterface exif    = new ExifInterface(is);
                    final float[]       latLon  = new float[2];
                    if (exif.getLatLong(latLon)) {
                        gpsFound++;
                        final String cam      = exif.getAttribute(ExifInterface.TAG_MAKE);
                        final String model    = exif.getAttribute(ExifInterface.TAG_MODEL);
                        final String dateTime = exif.getAttribute(ExifInterface.TAG_DATETIME);
                        result.addHighRisk("GPS照片: " + name,
                            String.format(Locale.getDefault(),
                                "纬度:%.5f° 经度:%.5f°\n拍摄:%s  相机:%s %s",
                                latLon[0], latLon[1],
                                dateTime != null ? dateTime : "未知",
                                cam   != null ? cam   : "",
                                model != null ? model : ""));
                    }
                } catch (final IOException ignored) {}
            }

            if (gpsFound == 0) {
                result.add("未找到含 GPS 的照片",
                    "已扫描 " + scanned + " 张，未读取到 GPS 坐标。\n"
                    + "（Android 10+ 已自动剔除 EXIF GPS —— 有效保护用户位置隐私）");
            } else {
                result.addHighRisk("含 GPS 照片数",
                    "发现 " + gpsFound + " 张含 GPS 坐标的照片（已扫描前 " + scanned + " 张）");
            }
        } catch (final SecurityException e) {
            result.addDegrade("EXIF 扫描", DegradeReason.PERMISSION_DENIED,
                "缺少存储/媒体权限");
        } catch (final Exception e) {
            result.addDegrade("EXIF 扫描", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName());
        }
    }

    private void collectVideoStats(
            @NonNull final ContentResolver         cr,
            @NonNull final CollectionResult.Builder result) {
        final Uri uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
        final String[] proj = {
            MediaStore.Video.Media._ID,
            MediaStore.Video.Media.DATE_TAKEN,
            MediaStore.Video.Media.DURATION,
            MediaStore.Video.Media.SIZE
        };
        try (final Cursor c = cr.query(
                uri, proj, null, null,
                MediaStore.Video.Media.DATE_TAKEN + " DESC")) {
            if (c == null) {
                result.addDegrade("视频", DegradeReason.NO_DATA, "MediaStore 返回 null");
                return;
            }
            final int total = c.getCount();
            result.addHighRisk("视频总数", total + " 个");
            if (total == 0) return;

            long totalSize = 0;
            long totalDur  = 0;
            while (c.moveToNext()) {
                totalSize += c.getLong(3);
                totalDur  += c.getLong(2);
            }
            result.add("视频总大小",
                String.format(Locale.getDefault(), "%.1f MB", totalSize / 1024.0 / 1024.0));
            result.add("视频总时长", formatDuration(totalDur));

            if (c.moveToFirst()) {
                final long dateTaken = c.getLong(1);
                if (dateTaken > 0) {
                    final SimpleDateFormat sdf =
                        new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
                    result.addHighRisk("最新视频时间", sdf.format(new Date(dateTaken)));
                }
            }
        } catch (final SecurityException e) {
            result.addDegrade("视频统计", DegradeReason.PERMISSION_DENIED,
                "缺少存储/媒体权限");
        } catch (final Exception e) {
            result.addDegrade("视频统计", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName());
        }
    }

    private void addMediaPrivacyAnalysis(
            @NonNull final CollectionResult.Builder result) {
        result.addHeader("媒体隐私价值分析");
        result.addHighRisk("EXIF GPS 风险",   "照片 EXIF 含拍摄 GPS 坐标 → 暴露用户历史位置轨迹");
        result.add("相机型号",               "EXIF TAG_MODEL 可辅助设备指纹（区分不同用户）");
        result.add("拍摄时间",               "时间戳分布可分析用户作息规律");
        result.add("视频内容",
            "视频缩略图 / 元数据可能包含用户脸部、家庭环境等敏感信息");
        result.add("Android 保护机制",
            "Android 10+ 自动从 MediaStore 查询结果中剔除 GPS EXIF，\n"
            + "需要 ACCESS_MEDIA_LOCATION 权限才能读取含位置的照片。");
    }

    private String formatDuration(final long ms) {
        final long sec  = ms / 1000;
        final long min  = sec / 60;
        final long hour = min / 60;
        if (hour > 0) return hour + "时" + (min % 60) + "分";
        if (min  > 0) return min  + "分" + (sec % 60) + "秒";
        return sec + "秒";
    }
}
