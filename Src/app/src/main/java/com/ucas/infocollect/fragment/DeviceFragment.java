package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.DeviceCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;
import java.util.Map;

public class DeviceFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        InfoCollector collector = new DeviceCollector();
        return collector.collect(requireContext());
    }
}
