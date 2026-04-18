package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.NetworkCollector;

import java.util.List;
import java.util.Map;

public class NetworkFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        return new NetworkCollector(requireContext()).collect();
    }
}
