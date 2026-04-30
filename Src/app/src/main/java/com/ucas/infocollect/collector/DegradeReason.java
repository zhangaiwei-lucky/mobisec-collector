package com.ucas.infocollect.collector;

/**
 * 采集降级原因分类枚举。
 *
 * <p>由 {@link DegradeEntry} 持有，标注一条降级事件的根因，
 * 供上层做分类展示、告警过滤或遥测聚合使用。</p>
 */
public enum DegradeReason {

    /** 所需的 Android 运行时危险权限未获得授予。 */
    PERMISSION_DENIED("权限不足"),

    /** 目标系统服务不可用（设备不支持、ROM 限制或服务未启动）。 */
    SERVICE_UNAVAILABLE("系统服务不可用"),

    /** 系统主动限制了数据访问（SELinux、厂商策略、Android 版本限制等）。 */
    SYSTEM_RESTRICTED("系统限制"),

    /** 数据源存在但当前无有效数据（如 GPS 从未定位、WiFi 未连接等）。 */
    NO_DATA("暂无数据"),

    /** 读取过程中发生 I/O 异常或意外的运行时错误。 */
    READ_FAILED("读取失败");

    /** 供 UI 展示的简短中文描述。 */
    public final String desc;

    DegradeReason(final String desc) {
        this.desc = desc;
    }
}
