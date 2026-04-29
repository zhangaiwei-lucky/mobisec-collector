package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.MediaCollector;
import com.ucas.infocollect.collector.InfoCollector;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public class MediaFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new MediaCollector();
        return collector.collect(requireContext());
    }
}
