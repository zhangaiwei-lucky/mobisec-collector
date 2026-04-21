package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.DeviceCollector;
import com.ucas.infocollect.collector.InfoCollector;

import java.util.List;

import com.ucas.infocollect.model.InfoRow;

public class DeviceFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new DeviceCollector();
        return collector.collect(requireContext());
    }
}
