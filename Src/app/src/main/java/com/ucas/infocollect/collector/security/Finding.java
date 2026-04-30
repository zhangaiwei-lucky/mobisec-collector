package com.ucas.infocollect.collector.security;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 单条安全发现（不可变领域对象）。
 *
 * <p>每条 {@code Finding} 描述一个具体的、可追溯的安全问题或观察项。
 * 它不绑定任何 UI 表示——转换为 {@link com.ucas.infocollect.model.InfoRow}
 * 的职责由展示层（如 {@code SecurityFragment}）承担。</p>
 *
 * <h3>字段语义</h3>
 * <dl>
 *   <dt>{@link #findingType}</dt>
 *   <dd>机器可读的发现类型标识符，例如 {@code "EXPORTED_ACTIVITY_NO_PERMISSION"}、
 *       {@code "APK_V1_ONLY_SIGNATURE"}。用于聚合统计、过滤和测试断言。</dd>
 *   <dt>{@link #title}</dt>
 *   <dd>人类可读的单行标题，用于 UI 列表展示。</dd>
 *   <dt>{@link #description}</dt>
 *   <dd>发现的详细描述，包含攻击路径说明或缓解建议。</dd>
 *   <dt>{@link #severity}</dt>
 *   <dd>严重性等级，控制 UI 高亮和风险聚合排序。</dd>
 *   <dt>{@link #attributes}</dt>
 *   <dd>结构化附加属性，例如 {@code "package"="com.example.app"}、
 *       {@code "component"="com.example.app/.MainActivity"}。
 *       键名由各子 Scanner 自行定义；调用层通过键名取值，不依赖字符串解析。</dd>
 * </dl>
 *
 * <p>通过 {@link Builder} 构造：</p>
 * <pre>
 *   Finding.of("EXPORTED_ACTIVITY_NO_PERMISSION", Severity.HIGH)
 *       .title("无权限保护的导出 Activity")
 *       .description("任意第三方应用可直接启动该组件，存在 Intent 劫持风险")
 *       .attribute("package",   "com.example.app")
 *       .attribute("component", "com.example.app/.VulnerableActivity")
 *       .build();
 * </pre>
 */
public final class Finding {

    @NonNull public final String              findingType;
    @NonNull public final String              title;
    @NonNull public final String              description;
    @NonNull public final Severity            severity;
    @NonNull public final Map<String, String> attributes;

    private Finding(@NonNull final Builder b) {
        this.findingType = b.findingType;
        this.severity    = b.severity;
        this.title       = b.title       != null ? b.title       : b.findingType;
        this.description = b.description != null ? b.description : "";
        this.attributes  = Collections.unmodifiableMap(new LinkedHashMap<>(b.attributes));
    }

    /**
     * 开始构建一条 {@code Finding}，指定类型标识符和严重性。
     *
     * @param findingType 机器可读类型标识符，建议使用大写下划线格式
     * @param severity    严重性等级
     */
    @NonNull
    public static Builder of(@NonNull final String findingType, @NonNull final Severity severity) {
        return new Builder(findingType, severity);
    }

    @Nullable
    public String getAttribute(@NonNull final String key) {
        return attributes.get(key);
    }

    @Override
    @NonNull
    public String toString() {
        return "[" + severity + "][" + findingType + "] " + title;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof Finding)) return false;
        final Finding that = (Finding) o;
        return findingType.equals(that.findingType)
                && severity == that.severity
                && title.equals(that.title)
                && description.equals(that.description)
                && attributes.equals(that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(findingType, severity, title, description, attributes);
    }

    // ─────────────────────────────────────────────────────────────────────────

    public static final class Builder {

        private final String              findingType;
        private final Severity            severity;
        private       String              title;
        private       String              description;
        private final Map<String, String> attributes = new LinkedHashMap<>();

        private Builder(@NonNull final String findingType, @NonNull final Severity severity) {
            this.findingType = Objects.requireNonNull(findingType, "findingType must not be null");
            this.severity    = Objects.requireNonNull(severity,    "severity must not be null");
        }

        @NonNull
        public Builder title(@NonNull final String title) {
            this.title = title;
            return this;
        }

        @NonNull
        public Builder description(@NonNull final String description) {
            this.description = description;
            return this;
        }

        @NonNull
        public Builder attribute(@NonNull final String key, @Nullable final String value) {
            if (value != null) attributes.put(key, value);
            return this;
        }

        @NonNull
        public Finding build() {
            return new Finding(this);
        }
    }
}
