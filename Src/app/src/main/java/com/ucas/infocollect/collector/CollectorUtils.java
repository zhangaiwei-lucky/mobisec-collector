package com.ucas.infocollect.collector;

import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.util.List;

public final class CollectorUtils {

    public static final String HEADER_PREFIX = "##";
    public static final String HIGH_RISK_PREFIX = "[HIGH]";

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
        String safeValue = value != null ? value : "N/A";
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
}
