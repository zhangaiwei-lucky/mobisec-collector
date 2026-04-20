package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.SecurityCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;
import java.util.Map;

public class SecurityFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        InfoCollector collector = new SecurityCollector();
        return collector.collect(requireContext());
    }
}
