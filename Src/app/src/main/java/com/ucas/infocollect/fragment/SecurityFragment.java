package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.SecurityCollector;

import java.util.List;
import java.util.Map;

public class SecurityFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        return new SecurityCollector(requireContext()).collect();
    }
}
