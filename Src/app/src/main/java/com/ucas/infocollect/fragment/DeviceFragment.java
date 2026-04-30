package com.ucas.infocollect.fragment;

import androidx.annotation.NonNull;

import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.DeviceCollector;
import com.ucas.infocollect.collector.SystemEnvironment;

/**
 * 设备信息 Fragment。
 *
 * <p>{@link BaseInfoFragment} 已在 Phase 2 接管：
 * 系统环境构造、worker 调度、降级日志沉淀、生命周期安全。
 * 本类只剩"指定哪个 collector"这一职责。</p>
 */
public class DeviceFragment extends BaseInfoFragment {

    @NonNull
    @Override
    protected CollectionResult collectInfo(@NonNull final SystemEnvironment env) {
        return new DeviceCollector().collect(env);
    }
}
