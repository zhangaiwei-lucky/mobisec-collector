package com.ucas.infocollect.fragment;

import androidx.annotation.NonNull;

import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.MediaCollector;
import com.ucas.infocollect.collector.SystemEnvironment;

public class MediaFragment extends BaseInfoFragment {

    @NonNull
    @Override
    protected CollectionResult collectInfo(@NonNull final SystemEnvironment env) {
        return new MediaCollector().collect(env);
    }
}
