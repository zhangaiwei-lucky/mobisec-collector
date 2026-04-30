package com.ucas.infocollect.fragment;

import android.util.Log;

import com.ucas.infocollect.collector.AndroidSystemEnvironment;
import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.DegradeEntry;
import com.ucas.infocollect.collector.SecurityCollectorV2;
import com.ucas.infocollect.model.InfoRow;

import java.util.List;

/**
 * 安全信息 Fragment（绞杀者模式切流版）。
 *
 * <p>旧 {@code SecurityCollector}（800+ 行 God Object）已被删除。
 * 本类作为 V1 UI 框架（{@link BaseInfoFragment}）与 V2 Collector 契约之间的桥接层：</p>
 * <ol>
 *   <li>在 UI 层持有 Context，构造 {@link AndroidSystemEnvironment} 实例，
 *       将其传入 {@link SecurityCollectorV2#collect}。</li>
 *   <li>从 {@link CollectionResult#getRows()} 取出纯净数据行，
 *       返回给父类用于 RecyclerView 渲染，签名保持 {@code List<InfoRow>} 不变。</li>
 *   <li>降级事件暂通过 {@code Log.w} 输出到 Logcat；
 *       Phase 2 再决策是否在 UI 层聚合展示。</li>
 * </ol>
 *
 * <p>Context 仅在本类（UI 层）被使用，不向下穿透到 Collector 层。</p>
 */
public class SecurityFragment extends BaseInfoFragment {

    private static final String TAG = "SecurityFragment";

    @Override
    protected List<InfoRow> collectInfo() {
        final CollectionResult result = new SecurityCollectorV2().collect(
                new AndroidSystemEnvironment(requireContext()));

        for (final DegradeEntry degrade : result.getDegrades()) {
            Log.w(TAG, degrade.toString());
        }

        return result.getRows();
    }
}
