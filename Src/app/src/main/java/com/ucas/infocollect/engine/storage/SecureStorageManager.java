package com.ucas.infocollect.engine.storage;

import android.content.Context;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.WorkerThread;

import com.ucas.infocollect.engine.crypto.CipherEngine;
import com.ucas.infocollect.engine.crypto.CipherEngine.CryptoException;

import org.json.JSONException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 安全快照存储管线（V1）。
 *
 * <h2>职责</h2>
 * <ol>
 *   <li>把 {@link SnapshotRecord} 序列化为 UTF-8 JSON；</li>
 *   <li>调用 {@link CipherEngine} 加密为自描述容器字节流；</li>
 *   <li>以原子方式写入应用私有目录 {@code getFilesDir()/snapshots/}；</li>
 *   <li>读取目录中的所有 {@code *.bin} 文件并解密，跳过损坏/篡改文件而不让单个错误污染整个列表。</li>
 * </ol>
 *
 * <h2>线程模型</h2>
 * <ul>
 *   <li>所有 I/O 都通过私有的单线程 {@link ExecutorService} 串行化执行，
 *       从根本上规避同名文件并发覆盖、目录扫描与写入的竞态。</li>
 *   <li>API 强制返回 {@link Future}，调用方按需 {@code get()} 或在自己的协程/Handler 中
 *       消费。这避免了"主线程操作 KeyStore"导致的 IPC 卡顿与 ANR。</li>
 *   <li>主线程调用 {@link #saveSnapshot(SnapshotRecord)} / {@link #loadAllSnapshots()}
 *       本身仅入队任务、立即返回，绝不阻塞 UI；但调用方若在主线程对 Future 阻塞 {@code get()}
 *       将会抛出 {@link IllegalStateException}（见 {@link #ensureNotMainThread()}）。</li>
 * </ul>
 *
 * <h2>原子性</h2>
 * 写入路径：
 * <pre>
 *   1) 写 {@code <snapshotDir>/<id>.bin.tmp}
 *   2) {@code File#renameTo} 为 {@code <snapshotDir>/<id>.bin}
 * </pre>
 * 文件系统对 same-FS rename 提供原子语义，断电/进程被杀情况下不会留下半截快照。
 *
 * <h2>故障恢复</h2>
 * <ul>
 *   <li>读取时若遇到 {@link CryptoException#CORRUPTED} 或 {@link CryptoException#TAMPERED}
 *       —— 仅丢弃当前文件并 {@link Log#w(String, String)} 记录，继续读取其它快照。</li>
 *   <li>读取/写入时若遇到 {@link CryptoException#KEY_INVALIDATED}
 *       —— 这表明用户更换了锁屏，所有历史密文已不可恢复：
 *       {@link CipherEngine#deleteKey()} 删除旧密钥，{@link #clearAllSnapshots()} 清空文件，
 *       异常以 {@link KeyInvalidatedException} 上抛让调用方决策。</li>
 *   <li>I/O 异常（磁盘满/权限丢失）不吞没，按 {@link IOException} 经 {@link Future#get()} 暴露给调用方。</li>
 * </ul>
 */
public final class SecureStorageManager {

    private static final String TAG          = "SecureStorageManager";
    /** 子目录名（相对于 {@link Context#getFilesDir()}）。 */
    public  static final String SNAPSHOT_DIR = "snapshots";
    private static final String FILE_EXT     = ".bin";
    private static final String TMP_EXT      = ".tmp";

    @NonNull private final Context         appContext;
    @NonNull private final CipherEngine    cipherEngine;
    @NonNull private final ExecutorService ioExecutor;

    /**
     * 通过应用 Context 构造。建议在 {@code Application#onCreate} 中创建单例并复用。
     */
    public SecureStorageManager(@NonNull final Context context) {
        this(context, new CipherEngine());
    }

    /**
     * 测试可注入的 {@link CipherEngine}（例如使用自定义别名）。
     */
    public SecureStorageManager(@NonNull final Context context,
                                @NonNull final CipherEngine cipherEngine) {
        this.appContext   = context.getApplicationContext();
        this.cipherEngine = cipherEngine;
        this.ioExecutor   = Executors.newSingleThreadExecutor(new NamedThreadFactory());
    }

    // ── 公共 API ────────────────────────────────────────────────────

    /**
     * 异步将 {@code record} 加密落盘。
     *
     * @return 一个 Future，{@link Future#get()} 在成功时返回最终落盘的 {@link File}。
     *         失败时 {@link java.util.concurrent.ExecutionException#getCause()} 可能为：
     *         <ul>
     *           <li>{@link IOException} —— 磁盘 I/O 失败；</li>
     *           <li>{@link CryptoException} —— 密钥/加密失败（{@code code} 字段标识细节）；</li>
     *           <li>{@link KeyInvalidatedException} —— 密钥已失效，旧快照已被清理。</li>
     *         </ul>
     * @throws IllegalStateException 若在主线程上对返回的 Future 同步 {@code get()}。
     */
    @AnyThread
    @NonNull
    public Future<File> saveSnapshot(@NonNull final SnapshotRecord record) {
        return ioExecutor.submit(() -> doSave(record));
    }

    /**
     * 异步加载所有历史快照，按 {@link SnapshotRecord#getCapturedAtMillis()} 升序返回。
     * 损坏/篡改的单个文件会被跳过，不会让一颗烂果毁掉整批。
     *
     * @return Future&lt;List&gt;。永不返回 null；列表本身是不可变快照。
     */
    @AnyThread
    @NonNull
    public Future<List<SnapshotRecord>> loadAllSnapshots() {
        return ioExecutor.submit((Callable<List<SnapshotRecord>>) this::doLoadAll);
    }

    /**
     * 清空所有历史快照文件（不影响 KeyStore 中的密钥）。
     * 主要用于 {@link KeyInvalidatedException} 之后的清理，或用户手动触发"删除全部"。
     */
    @AnyThread
    @NonNull
    public Future<Integer> clearAllSnapshots() {
        return ioExecutor.submit((Callable<Integer>) this::doClearAll);
    }

    /**
     * 同步释放执行线程；通常仅在测试或应用退出时调用。
     */
    @AnyThread
    public void shutdown() {
        ioExecutor.shutdown();
    }

    // ── 实际工作（运行于 ioExecutor） ─────────────────────────────────

    @WorkerThread
    @NonNull
    private File doSave(@NonNull final SnapshotRecord record)
            throws IOException, CryptoException, KeyInvalidatedException {
        ensureNotMainThread();

        final File dir = ensureSnapshotDir();
        final String baseName = buildFileName(record);
        final File   tmp     = new File(dir, baseName + FILE_EXT + TMP_EXT);
        final File   target  = new File(dir, baseName + FILE_EXT);

        final byte[] plaintext;
        try {
            plaintext = record.toJson().getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            // toJson 内部已声明不会抛 JSONException，此处仅为防御。
            throw new IOException("Snapshot serialization failed", e);
        }

        final byte[] ciphertext;
        try {
            ciphertext = cipherEngine.encrypt(plaintext);
        } catch (CryptoException e) {
            if (e.code == CryptoException.KEY_INVALIDATED) {
                handleKeyInvalidated();
                throw new KeyInvalidatedException(e);
            }
            throw e;
        }

        // 写到 .tmp，再原子 rename，断电也不会留半截文件
        try (FileOutputStream fos = new FileOutputStream(tmp)) {
            fos.write(ciphertext);
            fos.getFD().sync(); // 强制 fsync —— 在崩溃/断电下也能保证 rename 时数据已落盘
        } catch (IOException e) {
            // 清理半成品避免目录污染
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw e;
        }

        if (!tmp.renameTo(target)) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw new IOException("Atomic rename failed: " + tmp + " -> " + target);
        }
        return target;
    }

    @WorkerThread
    @NonNull
    private List<SnapshotRecord> doLoadAll() throws IOException, KeyInvalidatedException {
        ensureNotMainThread();

        final File dir = ensureSnapshotDir();
        final File[] files = dir.listFiles((d, name) -> name.endsWith(FILE_EXT));
        if (files == null || files.length == 0) {
            return Collections.emptyList();
        }

        // 顺便清理上次崩溃残留的 .tmp；不抛异常以免阻断主流程。
        cleanupTmpFiles(dir);

        final List<SnapshotRecord> result = new ArrayList<>(files.length);
        for (final File f : files) {
            try {
                result.add(decryptOne(f));
            } catch (KeyInvalidatedException e) {
                // 顶层不可继续：所有历史密文都将无法解密，整体清理。
                throw e;
            } catch (CryptoException e) {
                Log.w(TAG, "Drop corrupted snapshot " + f.getName()
                        + " (code=" + e.code + "): " + e.getMessage());
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            } catch (JSONException e) {
                Log.w(TAG, "Drop snapshot with bad JSON " + f.getName()
                        + ": " + e.getMessage());
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            } catch (IOException e) {
                // 单个文件读取失败不影响其它快照；仅警告。
                Log.w(TAG, "I/O error reading " + f.getName() + ": " + e.getMessage());
            }
        }

        // 升序按 capturedAtMillis 排序，便于 UI 直接渲染时间轴
        Collections.sort(result, (a, b) ->
                Long.compare(a.getCapturedAtMillis(), b.getCapturedAtMillis()));

        return Collections.unmodifiableList(result);
    }

    @WorkerThread
    @NonNull
    private SnapshotRecord decryptOne(@NonNull final File f)
            throws IOException, CryptoException, JSONException, KeyInvalidatedException {

        final byte[] ciphertext = readAll(f);
        final byte[] plaintext;
        try {
            plaintext = cipherEngine.decrypt(ciphertext);
        } catch (CryptoException e) {
            if (e.code == CryptoException.KEY_INVALIDATED) {
                handleKeyInvalidated();
                throw new KeyInvalidatedException(e);
            }
            throw e;
        }
        return SnapshotRecord.fromJson(new String(plaintext, StandardCharsets.UTF_8));
    }

    @WorkerThread
    private int doClearAll() {
        final File dir = new File(appContext.getFilesDir(), SNAPSHOT_DIR);
        if (!dir.isDirectory()) return 0;
        final File[] files = dir.listFiles();
        if (files == null) return 0;
        int deleted = 0;
        for (final File f : files) {
            if (f.isFile() && f.delete()) deleted++;
        }
        return deleted;
    }

    // ── 工具方法 ────────────────────────────────────────────────────

    /**
     * KEY_INVALIDATED 路径的统一恢复动作：删除 KeyStore 密钥 + 清空所有历史密文。
     * 调用方拿到 {@link KeyInvalidatedException} 后直接重新 {@link #saveSnapshot(SnapshotRecord)}
     * 即可，{@link CipherEngine} 会无感知地生成一把新密钥。
     */
    @WorkerThread
    private void handleKeyInvalidated() {
        try {
            cipherEngine.deleteKey();
        } catch (RuntimeException ignored) { /* best-effort */ }
        try {
            doClearAll();
        } catch (RuntimeException ignored) { /* best-effort */ }
    }

    @WorkerThread
    @NonNull
    private File ensureSnapshotDir() throws IOException {
        final File dir = new File(appContext.getFilesDir(), SNAPSHOT_DIR);
        if (dir.isDirectory()) return dir;
        if (!dir.mkdirs() && !dir.isDirectory()) {
            throw new IOException("Cannot create snapshot dir: " + dir);
        }
        return dir;
    }

    private static void cleanupTmpFiles(@NonNull final File dir) {
        final File[] tmps = dir.listFiles((d, name) -> name.endsWith(TMP_EXT));
        if (tmps == null) return;
        for (final File t : tmps) {
            //noinspection ResultOfMethodCallIgnored
            t.delete();
        }
    }

    @NonNull
    private static byte[] readAll(@NonNull final File f) throws IOException {
        // 文件长度可知，避免 ByteArrayOutputStream 多次扩容。
        final long len = f.length();
        if (len > Integer.MAX_VALUE - 8) {
            throw new IOException("Snapshot file too large: " + len);
        }
        final byte[] buf = new byte[(int) len];
        try (FileInputStream fis = new FileInputStream(f)) {
            int off = 0;
            while (off < buf.length) {
                final int n = fis.read(buf, off, buf.length - off);
                if (n < 0) {
                    // 文件被截断
                    final ByteArrayOutputStream bos = new ByteArrayOutputStream(off);
                    bos.write(buf, 0, off);
                    return bos.toByteArray();
                }
                off += n;
            }
            return buf;
        }
    }

    /**
     * 文件名规则：{@code snap_<capturedAtMillis>_<8位随机十六进制>}。
     * 时间戳前缀让目录排序与 UI 时间轴一致；随机后缀保证毫秒同时段批量写入也不会重名。
     */
    @NonNull
    private static String buildFileName(@NonNull final SnapshotRecord r) {
        final String rand = UUID.randomUUID().toString().substring(0, 8);
        return "snap_" + r.getCapturedAtMillis() + "_" + rand;
    }

    private static void ensureNotMainThread() {
        if (Looper.getMainLooper() != null
                && Looper.getMainLooper().getThread() == Thread.currentThread()) {
            throw new IllegalStateException(
                    "SecureStorageManager I/O must not run on the main thread.");
        }
    }

    // ── 嵌套类型 ────────────────────────────────────────────────────

    /**
     * 表示密钥已被系统失效（如用户清除锁屏），所有历史密文已不可恢复。
     * SecureStorageManager 已在抛出本异常前自动清理了 KeyStore 与历史文件，
     * 调用方只需重新触发一次新采集即可恢复。
     */
    public static final class KeyInvalidatedException extends Exception {
        public KeyInvalidatedException(@NonNull final CryptoException cause) {
            super("Snapshot encryption key invalidated; legacy snapshots wiped.", cause);
        }
    }

    /** 给后台线程一个可识别的名字，便于 trace/profiler 区分。 */
    private static final class NamedThreadFactory implements ThreadFactory {
        private final AtomicInteger seq = new AtomicInteger();

        @Override
        public Thread newThread(@NonNull final Runnable r) {
            final Thread t = new Thread(r, "secure-storage-io-" + seq.incrementAndGet());
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY);
            return t;
        }
    }
}
