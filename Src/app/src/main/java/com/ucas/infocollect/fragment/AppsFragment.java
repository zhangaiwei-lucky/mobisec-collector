package com.ucas.infocollect.fragment;

import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;

import com.ucas.infocollect.AppDetailActivity;
import com.ucas.infocollect.adapter.InfoAdapter;
import com.ucas.infocollect.collector.AndroidSystemEnvironment;
import com.ucas.infocollect.collector.AppCollector;
import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.DegradeEntry;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

public class AppsFragment extends BaseInfoFragment {

    private static final String TAG = "AppsFragment";

    @Override
    protected List<InfoRow> collectInfo() {
        final CollectionResult result =
            new AppCollector().collect(new AndroidSystemEnvironment(requireContext()));
        for (final DegradeEntry degrade : result.getDegrades()) {
            Log.w(TAG, degrade.toString());
        }
        return result.getRows();
    }

    @Override
    protected void onAdapterReady(@NonNull final InfoAdapter adapter) {
        adapter.setOnItemClickListener(packageName -> {
            final Intent intent =
                new Intent(requireContext(), AppDetailActivity.class);
            intent.putExtra(AppDetailActivity.EXTRA_PACKAGE, packageName);
            startActivity(intent);
        });
    }
}
