package com.ucas.infocollect.fragment;

import com.ucas.infocollect.collector.LocationCollector;
import com.ucas.infocollect.collector.InfoCollector;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public class LocationFragment extends BaseInfoFragment {
    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new LocationCollector();
        return collector.collect(requireContext());
    }
}
