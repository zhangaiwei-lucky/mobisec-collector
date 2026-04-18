package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.DeviceCollector;

import java.util.List;
import java.util.Map;

public class DeviceFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        return new DeviceCollector(requireContext()).collect();
    }
}
