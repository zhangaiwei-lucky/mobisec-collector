package com.ucas.infocollect.engine.storage;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 快照（Snapshot）的结构化数据传输对象。
 *
 * <h2>定位</h2>
 * <p>本类是 Phase 2 数据流强化中的"持久化原子单元"：
 * 一次完整的多 Collector 采集会被打包成一个 {@code SnapshotRecord}，
 * 由 {@link SecureStorageManager} 加密落盘。</p>
 *
 * <h2>不变性与线程安全</h2>
 * 所有字段在构造完成后不可变；内部 {@code payloads} Map 经
 * {@link Collections#unmodifiableMap(Map)} 包裹后对外发布，
 * 读取路径完全无锁、可被任意线程并发访问。
 *
 * <h2>序列化</h2>
 * 选择 Android 自带 {@link org.json.JSONObject} 而非 Gson/Moshi：
 * <ul>
 *   <li>无需引入额外依赖，APK 体积/方法数零增长；</li>
 *   <li>JSON 文本经 UTF-8 编码后即可作为 {@code byte[]} 喂给
 *       {@link com.ucas.infocollect.engine.crypto.CipherEngine#encrypt(byte[])}，
 *       与加密容器格式天然解耦；</li>
 *   <li>{@code payloads} 是 {@code Map<String,String>} 形态，
 *       本类无需理解每个 Collector 的具体数据模型，与 Phase 1 的
 *       {@code CollectionResult} 解耦，避免循环依赖。</li>
 * </ul>
 *
 * <h2>字段约定</h2>
 * <ul>
 *   <li>{@link #getCapturedAtMillis()} —— 采集结束时刻的系统时间戳（{@code System#currentTimeMillis}），
 *       用于排序与 UI 展示；不要求与服务器对齐。</li>
 *   <li>{@link #getAppVersionName()} / {@link #getAppVersionCode()} —— 来自
 *       {@code PackageInfo}，便于历史快照与不同应用版本对应。</li>
 *   <li>{@link #getDeviceFingerprint()} —— 由调用方计算，建议至少包含
 *       {@code Build.MANUFACTURER + Build.MODEL + Build.VERSION.SDK_INT}，
 *       避免直接落地 IMEI 等强标识。</li>
 *   <li>{@link #getPayloads()} —— 收集器名称（例如 {@code "device"}, {@code "network"}）
 *       到该收集器序列化文本（通常为 JSON）的映射。键名约定全小写、ASCII。</li>
 * </ul>
 */
public final class SnapshotRecord {

    // ── JSON 字段键（与磁盘格式紧耦合，禁止随意变更） ────────────────

    /** 当前 SnapshotRecord 的版本号；后续若调整 JSON 结构需自增并兼容旧值。 */
    public  static final int    SCHEMA_VERSION = 1;

    private static final String K_SCHEMA       = "schema";
    private static final String K_CAPTURED_AT  = "capturedAtMillis";
    private static final String K_APP_VER_NAME = "appVersionName";
    private static final String K_APP_VER_CODE = "appVersionCode";
    private static final String K_FINGERPRINT  = "deviceFingerprint";
    private static final String K_PAYLOADS     = "payloads";

    // ── 字段 ────────────────────────────────────────────────────────

    private final long              capturedAtMillis;
    @NonNull  private final String              appVersionName;
    private final long              appVersionCode;
    @NonNull  private final String              deviceFingerprint;
    @NonNull  private final Map<String, String> payloads;

    private SnapshotRecord(
            final long              capturedAtMillis,
            @NonNull final String              appVersionName,
            final long              appVersionCode,
            @NonNull final String              deviceFingerprint,
            @NonNull final Map<String, String> payloads) {
        this.capturedAtMillis  = capturedAtMillis;
        this.appVersionName    = appVersionName;
        this.appVersionCode    = appVersionCode;
        this.deviceFingerprint = deviceFingerprint;
        // LinkedHashMap 保留插入顺序，序列化与展示均稳定可重现。
        this.payloads = Collections.unmodifiableMap(new LinkedHashMap<>(payloads));
    }

    // ── 访问器 ──────────────────────────────────────────────────────

    public long              getCapturedAtMillis()  { return capturedAtMillis;  }
    @NonNull public String              getAppVersionName()    { return appVersionName;    }
    public long              getAppVersionCode()    { return appVersionCode;    }
    @NonNull public String              getDeviceFingerprint() { return deviceFingerprint; }
    @NonNull public Map<String, String> getPayloads()          { return payloads;          }

    /** 便捷查询：返回指定 collector 的序列化文本，缺失时为 null。 */
    @Nullable
    public String getPayload(@NonNull final String collectorName) {
        return payloads.get(collectorName);
    }

    // ── 序列化 ──────────────────────────────────────────────────────

    /**
     * 将本记录序列化为紧凑 JSON 字符串。
     *
     * <p>不包含换行/缩进，便于压缩与加密。生成的字符串可直接调用
     * {@code getBytes(StandardCharsets.UTF_8)} 进入加密管线。</p>
     */
    @NonNull
    public String toJson() {
        try {
            final JSONObject root = new JSONObject();
            root.put(K_SCHEMA,        SCHEMA_VERSION);
            root.put(K_CAPTURED_AT,   capturedAtMillis);
            root.put(K_APP_VER_NAME,  appVersionName);
            root.put(K_APP_VER_CODE,  appVersionCode);
            root.put(K_FINGERPRINT,   deviceFingerprint);

            final JSONObject pl = new JSONObject();
            for (final Map.Entry<String, String> e : payloads.entrySet()) {
                pl.put(e.getKey(), e.getValue());
            }
            root.put(K_PAYLOADS, pl);
            return root.toString();
        } catch (JSONException e) {
            // org.json.JSONObject 仅在 NaN/Infinity 时抛 JSONException，
            // 当前所有字段类型都是基础类型，理论不可达。
            throw new AssertionError("SnapshotRecord.toJson must not fail", e);
        }
    }

    /**
     * 反序列化 JSON 字符串为 SnapshotRecord。
     *
     * <p>对未知/缺失字段采取宽松策略（缺省值），但要求 {@code schema} 与
     * {@link #SCHEMA_VERSION} 一致，否则抛出 {@link JSONException}，
     * 由 {@link SecureStorageManager} 统一处理为"跳过损坏文件"。</p>
     *
     * @throws JSONException 当 JSON 结构无法识别时抛出。
     */
    @NonNull
    public static SnapshotRecord fromJson(@NonNull final String json) throws JSONException {
        final JSONObject root = new JSONObject(json);
        final int schema = root.optInt(K_SCHEMA, -1);
        if (schema != SCHEMA_VERSION) {
            throw new JSONException("Unsupported snapshot schema: " + schema);
        }

        final Builder b = builder()
                .capturedAtMillis(root.optLong(K_CAPTURED_AT, 0L))
                .appVersionName  (root.optString(K_APP_VER_NAME, "unknown"))
                .appVersionCode  (root.optLong  (K_APP_VER_CODE, 0L))
                .deviceFingerprint(root.optString(K_FINGERPRINT, "unknown"));

        final JSONObject pl = root.optJSONObject(K_PAYLOADS);
        if (pl != null) {
            final java.util.Iterator<String> it = pl.keys();
            while (it.hasNext()) {
                final String k = it.next();
                b.putPayload(k, pl.optString(k, ""));
            }
        }
        return b.build();
    }

    // ── equals / hashCode / toString ────────────────────────────────

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof SnapshotRecord)) return false;
        final SnapshotRecord that = (SnapshotRecord) o;
        return capturedAtMillis == that.capturedAtMillis
                && appVersionCode == that.appVersionCode
                && appVersionName.equals(that.appVersionName)
                && deviceFingerprint.equals(that.deviceFingerprint)
                && payloads.equals(that.payloads);
    }

    @Override
    public int hashCode() {
        return Objects.hash(capturedAtMillis, appVersionName, appVersionCode,
                deviceFingerprint, payloads);
    }

    @Override
    @NonNull
    public String toString() {
        return "SnapshotRecord{ts=" + capturedAtMillis
                + ", appVer=" + appVersionName + "(" + appVersionCode + ")"
                + ", fp=" + deviceFingerprint
                + ", payloadKeys=" + payloads.keySet()
                + "}";
    }

    // ── Builder ─────────────────────────────────────────────────────

    @NonNull
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 流式构建器。{@code payloads} 的插入顺序会被保留至最终序列化结果。
     */
    public static final class Builder {

        private long              capturedAtMillis  = System.currentTimeMillis();
        @NonNull private String              appVersionName    = "unknown";
        private long              appVersionCode    = 0L;
        @NonNull private String              deviceFingerprint = "unknown";
        @NonNull private final Map<String, String> payloads      = new LinkedHashMap<>();

        private Builder() {}

        @NonNull
        public Builder capturedAtMillis(final long ts) {
            this.capturedAtMillis = ts;
            return this;
        }

        @NonNull
        public Builder appVersionName(@NonNull final String name) {
            this.appVersionName = Objects.requireNonNull(name);
            return this;
        }

        @NonNull
        public Builder appVersionCode(final long code) {
            this.appVersionCode = code;
            return this;
        }

        @NonNull
        public Builder deviceFingerprint(@NonNull final String fingerprint) {
            this.deviceFingerprint = Objects.requireNonNull(fingerprint);
            return this;
        }

        /**
         * 追加一个 collector 的序列化文本。
         *
         * @param collectorName 收集器标识，如 {@code "device"}；不可为空。
         * @param serialized    收集器输出（建议 JSON）；不可为 null，可为空字符串。
         */
        @NonNull
        public Builder putPayload(@NonNull final String collectorName,
                                  @NonNull final String serialized) {
            if (collectorName.isEmpty()) {
                throw new IllegalArgumentException("collectorName must not be empty");
            }
            payloads.put(collectorName, serialized);
            return this;
        }

        @NonNull
        public SnapshotRecord build() {
            return new SnapshotRecord(
                    capturedAtMillis, appVersionName, appVersionCode,
                    deviceFingerprint, payloads);
        }
    }
}
