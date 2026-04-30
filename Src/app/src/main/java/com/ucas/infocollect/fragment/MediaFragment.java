package com.ucas.infocollect.fragment;

import android.util.Log;

import com.ucas.infocollect.collector.AndroidSystemEnvironment;
import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.DegradeEntry;
import com.ucas.infocollect.collector.MediaCollector;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public class MediaFragment extends BaseInfoFragment {

    private static final String TAG = "MediaFragment";

    @Override
    protected List<InfoRow> collectInfo() {
        final CollectionResult result =
            new MediaCollector().collect(new AndroidSystemEnvironment(requireContext()));
        for (final DegradeEntry degrade : result.getDegrades()) {
            Log.w(TAG, degrade.toString());
        }
        return result.getRows();
    }
}
