package com.ucas.infocollect.collector;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Collector 的结构化输出容器。
 *
 * <p>将原本混杂在单一 {@code List<InfoRow>} 中的两类数据显式拆分：</p>
 * <ul>
 *   <li>{@link #getRows()} — 可直接送往 UI 渲染的纯净数据行，不含任何降级伪行。</li>
 *   <li>{@link #getDegrades()} — 本次采集中所有降级事件的显式列表，
 *       供调用层审计、告警或聚合展示。</li>
 * </ul>
 *
 * <p>实例通过 {@link Builder} 构造，完成后不可变，线程安全。</p>
 */
public final class CollectionResult {

    @NonNull
    private final List<InfoRow>      rows;
    @NonNull
    private final List<DegradeEntry> degrades;

    private CollectionResult(
            @NonNull final List<InfoRow>      rows,
            @NonNull final List<DegradeEntry> degrades) {
        this.rows     = Collections.unmodifiableList(new ArrayList<>(rows));
        this.degrades = Collections.unmodifiableList(new ArrayList<>(degrades));
    }

    /** 可渲染数据行（保证不含降级伪行）。 */
    @NonNull
    public List<InfoRow> getRows() {
        return rows;
    }

    /** 本次采集的降级事件列表。 */
    @NonNull
    public List<DegradeEntry> getDegrades() {
        return degrades;
    }

    /** 本次采集是否存在至少一条降级事件。 */
    public boolean hasDegrade() {
        return !degrades.isEmpty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Builder
    // ─────────────────────────────────────────────────────────────────────────

    @NonNull
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 流式构建器，提供与 {@link CollectorUtils} 对应的便捷方法，
     * 同时将降级事件路由到独立列表。
     */
    public static final class Builder {

        private final List<InfoRow>      rows     = new ArrayList<>();
        private final List<DegradeEntry> degrades = new ArrayList<>();

        private Builder() {}

        /** 添加分组标题行。 */
        @NonNull
        public Builder addHeader(@NonNull final String title) {
            rows.add(InfoRow.header(title));
            return this;
        }

        /** 添加普通风险数据行。{@code value} 不得为 null，调用方须先解析默认值。 */
        @NonNull
        public Builder add(@NonNull final String key, @NonNull final String value) {
            rows.add(InfoRow.item(key, value, RiskLevel.NORMAL));
            return this;
        }

        /**
         * 添加普通风险数据行，允许 {@code value} 为 null。
         * null 值会被替换为 {@code "N/A"} 展示。
         */
        @NonNull
        public Builder addNullable(@NonNull final String key, @Nullable final String value) {
            rows.add(InfoRow.item(key, value != null ? value : "N/A", RiskLevel.NORMAL));
            return this;
        }

        /**
         * 添加高风险数据行，在 UI 层以醒目样式呈现。
         * null 值会被替换为 {@code "N/A"}。
         */
        @NonNull
        public Builder addHighRisk(@NonNull final String key, @Nullable final String value) {
            rows.add(InfoRow.item(key, value != null ? value : "N/A", RiskLevel.HIGH));
            return this;
        }

        /**
         * 添加可点击的应用列表行（APP_ITEM 类型），供 {@code AppsFragment} 使用。
         *
         * @param appName     应用显示名称
         * @param permSummary 权限摘要文字（如 "3 项危险权限"）
         * @param risk        风险等级，控制行的高亮颜色
         * @param packageName 应用包名，用于点击跳转至详情页
         */
        @NonNull
        public Builder addAppItem(
                @NonNull final String   appName,
                @NonNull final String   permSummary,
                @NonNull final RiskLevel risk,
                @NonNull final String   packageName) {
            rows.add(InfoRow.appItem(appName, permSummary, risk, packageName));
            return this;
        }

        /**
         * 记录一条降级事件。
         * 降级不产生任何 {@link InfoRow}，仅追加到 {@link #degrades} 列表。
         */
        @NonNull
        public Builder addDegrade(
                @NonNull final String field,
                @NonNull final DegradeReason reason,
                @NonNull final String detail) {
            degrades.add(new DegradeEntry(field, reason, detail));
            return this;
        }

        @NonNull
        public CollectionResult build() {
            return new CollectionResult(rows, degrades);
        }
    }
}
