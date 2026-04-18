package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.AppCollector;

import java.util.List;
import java.util.Map;

public class AppsFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        return new AppCollector(requireContext()).collect();
    }
}
