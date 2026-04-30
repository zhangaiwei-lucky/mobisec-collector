package com.ucas.infocollect.fragment;

import android.content.Intent;

import androidx.annotation.NonNull;

import com.ucas.infocollect.AppDetailActivity;
import com.ucas.infocollect.adapter.InfoAdapter;
import com.ucas.infocollect.collector.AppCollector;
import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.SystemEnvironment;

public class AppsFragment extends BaseInfoFragment {

    @NonNull
    @Override
    protected CollectionResult collectInfo(@NonNull final SystemEnvironment env) {
        return new AppCollector().collect(env);
    }

    @Override
    protected void onAdapterReady(@NonNull final InfoAdapter adapter) {
        adapter.setOnItemClickListener(packageName -> {
            final Intent intent = new Intent(requireContext(), AppDetailActivity.class);
            intent.putExtra(AppDetailActivity.EXTRA_PACKAGE, packageName);
            startActivity(intent);
        });
    }
}
