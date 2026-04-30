package com.ucas.infocollect.collector;

import androidx.annotation.NonNull;

import java.util.Objects;

/**
 * 采集降级记录。
 *
 * <p>当某字段因权限缺失、系统服务不可用或底层读取异常而无法获取时，
 * 收集器将生成一条 {@code DegradeEntry} 而非向 {@code InfoRow} 列表塞入
 * 含错误描述的伪数据行。这使展示层与错误诊断层彻底分离。</p>
 *
 * <p>实例不可变，线程安全。</p>
 */
public final class DegradeEntry {

    /** 发生降级的字段或功能域名称，例如 "IMEI / 运营商" */
    @NonNull
    public final String field;

    /** 降级原因分类 */
    @NonNull
    public final DegradeReason reason;

    /** 降级补充说明，含异常类型或拒绝权限名等可溯源信息 */
    @NonNull
    public final String detail;

    public DegradeEntry(
            @NonNull final String field,
            @NonNull final DegradeReason reason,
            @NonNull final String detail) {
        this.field  = Objects.requireNonNull(field,  "field must not be null");
        this.reason = Objects.requireNonNull(reason, "reason must not be null");
        this.detail = Objects.requireNonNull(detail, "detail must not be null");
    }

    @NonNull
    @Override
    public String toString() {
        return "[" + reason.name() + "][" + field + "] " + detail;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof DegradeEntry)) return false;
        final DegradeEntry that = (DegradeEntry) o;
        return field.equals(that.field)
                && reason == that.reason
                && detail.equals(that.detail);
    }

    @Override
    public int hashCode() {
        return Objects.hash(field, reason, detail);
    }
}
