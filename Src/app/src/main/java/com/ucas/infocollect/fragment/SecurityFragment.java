package com.ucas.infocollect.fragment;

import androidx.annotation.NonNull;

import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.SecurityCollectorV2;
import com.ucas.infocollect.collector.SystemEnvironment;

/**
 * 安全信息 Fragment。
 *
 * <p>旧 {@code SecurityCollector}（800+ 行 God Object）在 Phase 1 已被替换为
 * {@link SecurityCollectorV2}；Phase 2 又把环境构造与生命周期安全下沉到
 * {@link BaseInfoFragment}，此处仅指明 collector。</p>
 */
public class SecurityFragment extends BaseInfoFragment {

    @NonNull
    @Override
    protected CollectionResult collectInfo(@NonNull final SystemEnvironment env) {
        return new SecurityCollectorV2().collect(env);
    }
}
