package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.UserDataCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;
import java.util.Map;

public class UserFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        InfoCollector collector = new UserDataCollector();
        return collector.collect(requireContext());
    }
}
