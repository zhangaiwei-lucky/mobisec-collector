package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.UserDataCollector;

import java.util.List;
import java.util.Map;

public class UserFragment extends BaseInfoFragment {
    @Override
    protected List<Map.Entry<String, String>> collectInfo() {
        return new UserDataCollector(requireContext()).collect();
    }
}
