package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.NetworkCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;

import com.ucas.infocollect.model.InfoRow;

public class NetworkFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new NetworkCollector();
        return collector.collect(requireContext());
    }
}
