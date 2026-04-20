package com.ucas.infocollect.collector;

import android.content.Context;

import java.util.List;
import java.util.Map;

public interface InfoCollector {
    List<Map.Entry<String, String>> collect(Context context);
}
