package com.ucas.infocollect.collector;

import android.content.Context;

import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public interface InfoCollector {
    List<InfoRow> collect(Context context);
}
