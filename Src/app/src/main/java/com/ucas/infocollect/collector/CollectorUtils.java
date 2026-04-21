package com.ucas.infocollect.collector;

import android.content.Context;

import androidx.annotation.Nullable;

import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.util.List;

public final class CollectorUtils {

    public static final String HEADER_PREFIX = "##";
    public static final String HIGH_RISK_PREFIX = "[HIGH]";
    private static final String DEFAULT_NA = "N/A";

    private CollectorUtils() {
        // Utility class
    }

    public static void add(List<InfoRow> list, String key, String value) {
        String safeValue = value != null ? value : "N/A";
        if (safeValue.startsWith(HIGH_RISK_PREFIX)) {
            addHighRisk(list, key, safeValue.substring(HIGH_RISK_PREFIX.length()));
            return;
        }
        list.add(InfoRow.item(key, safeValue, RiskLevel.NORMAL));
    }

    public static void addHighRisk(List<InfoRow> list, String key, String value) {
        String safeValue = value != null ? value : DEFAULT_NA;
        if (safeValue.startsWith(HIGH_RISK_PREFIX)) {
            safeValue = safeValue.substring(HIGH_RISK_PREFIX.length());
        }
        list.add(InfoRow.item(key, safeValue, RiskLevel.HIGH));
    }

    public static void addHeader(List<InfoRow> list, String title) {
        String safeTitle = title != null ? title : "";
        if (safeTitle.startsWith(HEADER_PREFIX)) {
            safeTitle = safeTitle.substring(HEADER_PREFIX.length());
        }
        list.add(InfoRow.header(safeTitle));
    }

    public static void safeAdd(List<InfoRow> list, String key, @Nullable String value) {
        safeAdd(list, key, value, DEFAULT_NA);
    }

    public static void safeAdd(List<InfoRow> list, String key, @Nullable String value, String fallbackValue) {
        add(list, key, value != null ? value : fallbackValue);
    }

    @Nullable
    public static <T> T safeService(
            Context context,
            String serviceName,
            Class<T> serviceType,
            List<InfoRow> items,
            String label,
            String unavailableMessage
    ) {
        try {
            Object service = context.getSystemService(serviceName);
            if (serviceType.isInstance(service)) {
                return serviceType.cast(service);
            }
            addDegrade(items, label, DegradeReason.SERVICE_UNAVAILABLE, unavailableMessage);
            return null;
        } catch (Exception e) {
            addDegrade(items, label, DegradeReason.SERVICE_UNAVAILABLE,
                    unavailableMessage + " (" + e.getClass().getSimpleName() + ")");
            return null;
        }
    }

    public static void addDegrade(List<InfoRow> list, String key, DegradeReason reason, String detail) {
        String explain = detail != null && !detail.isEmpty() ? detail : "无额外信息";
        add(list, key, "原因类别: " + reason.name() + " - " + reason.desc + "；" + explain);
    }

    public enum DegradeReason {
        PERMISSION_DENIED("权限不足"),
        SERVICE_UNAVAILABLE("系统服务不可用"),
        SYSTEM_RESTRICTED("系统限制"),
        NO_DATA("暂无数据"),
        READ_FAILED("读取失败");

        final String desc;

        DegradeReason(String desc) {
            this.desc = desc;
        }
    }
}
