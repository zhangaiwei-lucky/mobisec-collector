package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.UserDataCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;

import com.ucas.infocollect.model.InfoRow;

public class UserFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new UserDataCollector();
        return collector.collect(requireContext());
    }
}
