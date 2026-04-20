package com.ucas.infocollect.collector;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

public final class CollectorUtils {

    public static final String HEADER_PREFIX = "##";

    private CollectorUtils() {
        // Utility class
    }

    public static void add(List<Map.Entry<String, String>> list, String key, String value) {
        list.add(new AbstractMap.SimpleEntry<>(key, value != null ? value : "N/A"));
    }

    public static void addHeader(List<Map.Entry<String, String>> list, String title) {
        list.add(new AbstractMap.SimpleEntry<>(HEADER_PREFIX + title, ""));
    }
}
