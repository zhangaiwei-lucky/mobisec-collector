package com.ucas.infocollect.model;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Objects;

public final class InfoRow {
    private static final String DEFAULT_VALUE = "N/A";
    private static final long HASH_SEED = 1469598103934665603L;
    private static final long HASH_PRIME = 1099511628211L;

    private final long stableId;
    @NonNull
    private final RowType type;
    @NonNull
    private final String key;
    @NonNull
    private final String value;
    @NonNull
    private final RiskLevel riskLevel;

    private InfoRow(
            @NonNull RowType type,
            @Nullable String key,
            @Nullable String value,
            @NonNull RiskLevel riskLevel
    ) {
        this.type = type;
        this.key = key != null ? key : "";
        this.value = value != null ? value : DEFAULT_VALUE;
        this.riskLevel = riskLevel;
        this.stableId = buildStableId(this.type, this.key, this.value, this.riskLevel);
    }

    @NonNull
    public static InfoRow header(@Nullable String title) {
        return new InfoRow(RowType.HEADER, title, "", RiskLevel.NORMAL);
    }

    @NonNull
    public static InfoRow item(@Nullable String key, @Nullable String value, @NonNull RiskLevel riskLevel) {
        return new InfoRow(RowType.ITEM, key, value, riskLevel);
    }

    public long getStableId() {
        return stableId;
    }

    @NonNull
    public RowType getType() {
        return type;
    }

    @NonNull
    public String getKey() {
        return key;
    }

    @NonNull
    public String getValue() {
        return value;
    }

    @NonNull
    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    private static long buildStableId(
            @NonNull RowType type,
            @NonNull String key,
            @NonNull String value,
            @NonNull RiskLevel riskLevel
    ) {
        long hash = HASH_SEED;
        hash = hashField(hash, type.name());
        hash = hashField(hash, key);
        hash = hashField(hash, value);
        hash = hashField(hash, riskLevel.name());
        return hash;
    }

    private static long hashField(long seed, @Nullable String field) {
        long hash = seed;
        String safeField = field != null ? field : "";
        for (int i = 0; i < safeField.length(); i++) {
            hash ^= safeField.charAt(i);
            hash *= HASH_PRIME;
        }
        return hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof InfoRow)) return false;
        InfoRow infoRow = (InfoRow) o;
        return stableId == infoRow.stableId
                && type == infoRow.type
                && Objects.equals(key, infoRow.key)
                && Objects.equals(value, infoRow.value)
                && riskLevel == infoRow.riskLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(stableId, type, key, value, riskLevel);
    }
}
