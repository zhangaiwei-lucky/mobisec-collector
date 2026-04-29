package com.ucas.infocollect.fragment;

import android.content.Intent;

import androidx.annotation.NonNull;

import com.ucas.infocollect.AppDetailActivity;
import com.ucas.infocollect.adapter.InfoAdapter;
import com.ucas.infocollect.collector.AppCollector;
import com.ucas.infocollect.collector.InfoCollector;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public class AppsFragment extends BaseInfoFragment {

    @Override
    protected List<InfoRow> collectInfo() {
        InfoCollector collector = new AppCollector();
        return collector.collect(requireContext());
    }

    @Override
    protected void onAdapterReady(@NonNull InfoAdapter adapter) {
        adapter.setOnItemClickListener(packageName -> {
            Intent intent = new Intent(requireContext(), AppDetailActivity.class);
            intent.putExtra(AppDetailActivity.EXTRA_PACKAGE, packageName);
            startActivity(intent);
        });
    }
}
