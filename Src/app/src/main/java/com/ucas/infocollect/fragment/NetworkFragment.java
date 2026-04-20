package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.NetworkCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;
import java.util.Map;

public class NetworkFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        InfoCollector collector = new NetworkCollector();
        return collector.collect(requireContext());
    }
}
