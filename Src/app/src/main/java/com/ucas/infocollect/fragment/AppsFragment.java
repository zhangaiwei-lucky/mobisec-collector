package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.AppCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;

import com.ucas.infocollect.model.InfoRow;

public class AppsFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new AppCollector();
        return collector.collect(requireContext());
    }
}
