package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.SecurityCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;

import com.ucas.infocollect.model.InfoRow;

public class SecurityFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new SecurityCollector();
        return collector.collect(requireContext());
    }
}
