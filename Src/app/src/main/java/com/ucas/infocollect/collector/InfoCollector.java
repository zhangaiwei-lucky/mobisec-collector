package com.ucas.infocollect.collector;

import android.content.Context;

import com.ucas.infocollect.model.InfoRow;

import java.util.List;

/**
 * 信息收集器旧版契约（绞杀者模式过渡期保留）。
 *
 * <p>已迁移的 Collector 请改用 {@link InfoCollectorV2}。
 * 本接口在全部 Collector 完成 Phase 迁移后将被移除。</p>
 *
 * @deprecated 迁移路径：实现 {@link InfoCollectorV2}，
 *             并将 Context 依赖替换为 {@link SystemEnvironment}。
 */
@Deprecated
public interface InfoCollector {
    List<InfoRow> collect(Context context);
}
