package com.ucas.infocollect.collector;

import androidx.annotation.NonNull;

import java.util.List;

/**
 * 信息收集器新一代契约（Phase 1 架构纯化版，绞杀者模式过渡期专用）。
 *
 * <p>与旧版 {@link InfoCollector} 的三项关键差异：</p>
 * <ol>
 *   <li>{@link #collect} 不再接受 {@code android.content.Context}，
 *       改为接受 {@link SystemEnvironment} 防腐接口，实现与 Android 运行时解耦。</li>
 *   <li>权限声明通过 {@link #getRequiredPermissions()} 集中描述，
 *       由应用层统一申请，Collector 内部不得执行任何权限检查。</li>
 *   <li>返回类型升级为 {@link CollectionResult}，降级事件从数据行显式剥离。</li>
 * </ol>
 *
 * <p><b>迁移路径：</b>新重构的 Collector 直接实现本接口。
 * UI 层通过 {@code V2Bridge} 将 {@link CollectionResult} 适配为
 * {@code List<InfoRow>}，与 {@link BaseInfoFragment} 保持兼容。
 * 待全部 Collector 完成迁移后，本接口将替换 {@link InfoCollector} 成为唯一契约。</p>
 */
public interface InfoCollectorV2 {

    /**
     * 执行信息采集。
     *
     * <p>调用方须在调用前确认 {@link #getRequiredPermissions()} 中列出的权限
     * 均已获得授予。未授予时产生的 {@link SecurityException} 将被捕获并作为
     * {@link DegradeEntry} 记录，不会导致方法抛出异常。</p>
     *
     * @param env 系统环境代理；实现类内部禁止穿透访问 {@code android.content.Context}
     * @return 结构化采集结果，包含纯净数据行与显式降级列表
     */
    @NonNull
    CollectionResult collect(@NonNull SystemEnvironment env);

    /**
     * 声明本 Collector 正常工作所需的 Android 危险权限列表。
     *
     * <p>返回值应与 {@code android.Manifest.permission} 中的常量保持一致。
     * 无额外权限要求时返回空列表。</p>
     *
     * @return 不可变的权限字符串列表
     */
    @NonNull
    List<String> getRequiredPermissions();
}
