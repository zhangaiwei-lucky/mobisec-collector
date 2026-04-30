package com.ucas.infocollect.fragment;

import android.util.Log;

import com.ucas.infocollect.collector.AndroidSystemEnvironment;
import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.DegradeEntry;
import com.ucas.infocollect.collector.NetworkCollector;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public class NetworkFragment extends BaseInfoFragment {

    private static final String TAG = "NetworkFragment";

    @Override
    protected List<InfoRow> collectInfo() {
        final CollectionResult result =
            new NetworkCollector().collect(new AndroidSystemEnvironment(requireContext()));
        for (final DegradeEntry degrade : result.getDegrades()) {
            Log.w(TAG, degrade.toString());
        }
        return result.getRows();
    }
}
