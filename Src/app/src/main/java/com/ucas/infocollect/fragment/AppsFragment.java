package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.AppCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;
import java.util.Map;

public class AppsFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        InfoCollector collector = new AppCollector();
        return collector.collect(requireContext());
    }
}
