package com.ucas.infocollect.fragment;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;

import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ucas.infocollect.R;
import com.ucas.infocollect.adapter.InfoAdapter;
import com.ucas.infocollect.collector.AndroidSystemEnvironment;
import com.ucas.infocollect.collector.CollectionResult;
import com.ucas.infocollect.collector.DegradeEntry;
import com.ucas.infocollect.collector.SystemEnvironment;
import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

/**
 * 通用信息列表 Fragment 基类（Phase 2 异步引擎重写版）。
 *
 * <h3>设计要点</h3>
 * <ul>
 *   <li><b>状态机化</b>：用 {@link LoadState} 取代旧的
 *       {@code volatile boolean viewActive} 守卫；状态严格在主线程上读写。</li>
 *   <li><b>生命周期安全的任务投递</b>：worker 线程仅负责执行
 *       {@link #collectInfo(SystemEnvironment)} 并把不可变结果交给一个
 *       小型命名 {@link Runnable}（{@link SuccessDelivery} / {@link ErrorDelivery}）；
 *       绝不向 {@code mainHandler} 投递包含完整业务上下文的匿名巨型 lambda。</li>
 *   <li><b>双重防御性检查</b>：在 main 线程实际触碰 {@code adapter} 与
 *       {@code progressBar} 之前，必须同时校验 {@link #isAdded()} 与
 *       {@link #getView()} 不为 {@code null}。</li>
 *   <li><b>对接 {@link CollectionResult}</b>：{@code collectInfo} 返回代数结构，
 *       行数据交给 RecyclerView，降级事件通过 {@link Log#w} 沉淀。</li>
 * </ul>
 *
 * <h3>线程归属约定</h3>
 * <ul>
 *   <li>{@code state} / {@code cachedResult} / {@code runningTask} / {@code executor}
 *       / 三个 View 句柄：仅主线程读写。</li>
 *   <li>{@code mainHandler}：跨线程投递的唯一通道，post 入队由 Looper 保证有序。</li>
 *   <li>{@code collectInfo(env)}：仅 worker 线程执行；禁止触碰任何 View。</li>
 * </ul>
 */
public abstract class BaseInfoFragment extends Fragment {

    /**
     * UI 数据加载状态机。
     *
     * <pre>
     *   IDLE        ──loadData()──▶  LOADING
     *   LOADING     ──成功投递──▶    SUCCESS
     *   LOADING     ──异常投递──▶    ERROR
     *   SUCCESS/ERROR ──loadData()──▶ LOADING （允许重新触发刷新）
     *   * ──onDestroyView──▶ IDLE  （executor 已被销毁，必须复位以解锁后续加载）
     * </pre>
     */
    private enum LoadState { IDLE, LOADING, SUCCESS, ERROR }

    // ── View-scoped 资源（onDestroyView 时统一释放） ─────────────────
    @Nullable private InfoAdapter     adapter;
    @Nullable private ProgressBar     progressBar;
    @Nullable private Button          btnRefresh;
    @Nullable private ExecutorService executor;
    @Nullable private Future<?>       runningTask;

    // ── Fragment-scoped 状态（跨 view 重建保留） ─────────────────────
    @NonNull  private LoadState        state = LoadState.IDLE;
    @Nullable private CollectionResult cachedResult;

    /** 跨线程投递的唯一通道；onDestroyView 中通过 removeCallbacksAndMessages(null) 清空。 */
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
            @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {

        final View view = inflater.inflate(R.layout.fragment_list, container, false);

        final RecyclerView recyclerView = view.findViewById(R.id.recycler_view);
        progressBar = view.findViewById(R.id.progress_loading);
        btnRefresh  = view.findViewById(R.id.btn_refresh);

        recyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new InfoAdapter(new ArrayList<>());
        recyclerView.setAdapter(adapter);
        onAdapterReady(adapter);

        // 每次重建 view 都新建一个 single-thread executor。
        // 上一轮的 executor 已在 onDestroyView 被 shutdownNow 销毁，无法复用。
        // 命名 worker 线程方便 logcat 排查。
        executor = Executors.newSingleThreadExecutor(r -> {
            final Thread t = new Thread(r, getLogTag() + "-Worker");
            t.setDaemon(true);
            return t;
        });

        btnRefresh.setOnClickListener(v -> loadData());

        // 防御性复位：上一轮 LOADING 中途被 onDestroyView 切断，
        // 旧 worker 已被中断；若不复位，下面的 cachedResult==null 分支会因
        // state==LOADING 在 loadData() 内被拦截，导致永久卡住。
        if (state == LoadState.LOADING) {
            state = LoadState.IDLE;
        }

        // 缓存命中：跨 view 重建时即时回显，避免每次切 tab 都跑一遍 collector
        if (cachedResult != null) {
            renderRows(cachedResult);
        } else if (state == LoadState.IDLE) {
            // 首次进入或上一轮被中断后的冷启动
            loadData();
        }

        return view;
    }

    // ───────────────────────────────────────────────────────────────
    // 加载触发（@MainThread 严格约束，状态机驱动）
    // ───────────────────────────────────────────────────────────────

    /**
     * 触发一次后台采集。
     *
     * <p>不变量：</p>
     * <ul>
     *   <li>仅主线程调用（{@link MainThread}）。</li>
     *   <li>状态为 {@code LOADING} 时短路返回，拦截重复点击或重复加载。</li>
     *   <li>UI 资源缺失（view 未就绪 / 已销毁）时短路返回。</li>
     * </ul>
     */
    @MainThread
    public final void loadData() {
        if (state == LoadState.LOADING) {
            // 拦截：刷新按钮的多次连击 / 自动加载与手动刷新的并发竞争
            return;
        }
        if (executor == null || progressBar == null || btnRefresh == null) {
            // View 还未构造或已销毁，无可操作的 UI 句柄
            return;
        }
        if (!isAdded()) {
            // Fragment 已 detach，requireContext() 会抛 IllegalStateException
            return;
        }

        state = LoadState.LOADING;
        progressBar.setVisibility(View.VISIBLE);
        btnRefresh.setEnabled(false);

        // 在主线程构造 SystemEnvironment：
        //   AndroidSystemEnvironment 内部仅持有 ApplicationContext，
        //   可安全跨线程传递、不会泄漏 Activity，
        //   也不要求 worker 持有任何 Fragment / Context 引用。
        final SystemEnvironment env = new AndroidSystemEnvironment(requireContext());

        try {
            runningTask = executor.submit(new CollectTask(env));
        } catch (final RejectedExecutionException e) {
            // executor 在状态切换的瞬间被关闭（例如极快的 tab 切换）
            // 此时必须回滚状态机，否则会被 LOADING 永久卡死
            state = LoadState.IDLE;
            progressBar.setVisibility(View.GONE);
            btnRefresh.setEnabled(true);
            Log.w(getLogTag(), "采集任务被拒绝执行（executor 已关闭）", e);
        }
    }

    // ───────────────────────────────────────────────────────────────
    // 后台任务 + 命名投递（避免向 mainHandler 丢匿名巨型 Runnable）
    // ───────────────────────────────────────────────────────────────

    /**
     * 后台采集任务。
     *
     * <p>仅捕获不可变的 {@link SystemEnvironment} 与外部类（Fragment）引用。
     * 不直接捕获任何 View 句柄——这样即使在 collectInfo() 阻塞期间 view 被销毁，
     * worker 也不会持有失效的 ImageView/TextView 等大对象。</p>
     */
    private final class CollectTask implements Runnable {

        @NonNull private final SystemEnvironment env;

        CollectTask(@NonNull final SystemEnvironment env) {
            this.env = env;
        }

        @Override
        public void run() {
            try {
                CollectionResult result = collectInfo(env);
                if (result == null) {
                    // 子类约定不应返回 null；防御性兜底，避免 NPE 蔓延到 UI 线程
                    result = CollectionResult.builder().build();
                }
                // 关键：投递的是只持有"不可变 CollectionResult"的小 Runnable，
                // 而不是把整个 collectInfo 上下文塞进 mainHandler 的匿名 lambda
                mainHandler.post(new SuccessDelivery(result));
            } catch (final InterruptedException ie) {
                // shutdownNow 触发的中断：view 已死，丢弃结果，
                // 但仍要恢复中断标志，避免被外层框架误判
                Thread.currentThread().interrupt();
            } catch (final Throwable t) {
                // 捕获 RuntimeException / Error 全集；
                // 不让任何异常传播到 ThreadPoolExecutor 的默认未捕获处理器
                mainHandler.post(new ErrorDelivery(t));
            }
        }
    }

    /** 成功投递。仅持有不可变 CollectionResult，不持有任何 View 引用。 */
    private final class SuccessDelivery implements Runnable {

        @NonNull private final CollectionResult result;

        SuccessDelivery(@NonNull final CollectionResult result) {
            this.result = result;
        }

        @Override
        public void run() {
            // ╔══════════════════════════════════════════════════════════╗
            // ║ 双重防御性检查（核心反崩溃防线）                          ║
            // ║                                                          ║
            // ║ 在 mainHandler.post 入队 与 此处实际执行 之间，          ║
            // ║ View 树可能被销毁。removeCallbacksAndMessages(null) 仅能 ║
            // ║ 清掉销毁前已入队的消息，无法阻止 worker 在销毁后追加新   ║
            // ║ 消息。仅靠 isAdded() 仍存在 reattach 但 view 未 inflate ║
            // ║ 的反例；仅靠 getView() != null 也覆盖不全已 detach 场景。║
            // ║ 必须二者同时为真，才允许触碰 adapter / progressBar。     ║
            // ╚══════════════════════════════════════════════════════════╝
            if (!isAdded() || getView() == null) {
                return;
            }
            cachedResult = result;
            state        = LoadState.SUCCESS;
            renderRows(result);
            // 降级事件沉淀到 logcat；子类可重写 onDegradesObserved 做 Snackbar
            onDegradesObserved(result.getDegrades());
        }
    }

    /** 异常投递。 */
    private final class ErrorDelivery implements Runnable {

        @NonNull private final Throwable error;

        ErrorDelivery(@NonNull final Throwable error) {
            this.error = error;
        }

        @Override
        public void run() {
            // 同 SuccessDelivery，必须先确认 View 树活着
            if (!isAdded() || getView() == null) {
                return;
            }
            state = LoadState.ERROR;
            Log.e(getLogTag(), "采集失败", error);

            // 用一行 HIGH 风险占位行替代 RecyclerView 空白
            final List<InfoRow> errorRows = new ArrayList<>(1);
            errorRows.add(InfoRow.item(
                    "采集异常",
                    error.getMessage() != null ? error.getMessage() : error.getClass().getSimpleName(),
                    RiskLevel.HIGH));
            if (adapter     != null) adapter.updateData(errorRows);
            if (progressBar != null) progressBar.setVisibility(View.GONE);
            if (btnRefresh  != null) btnRefresh.setEnabled(true);
        }
    }

    /** 把成功结果落到 RecyclerView。仅在主线程 + view 仍活的前提下被调用。 */
    @MainThread
    private void renderRows(@NonNull final CollectionResult result) {
        if (adapter     != null) adapter.updateData(result.getRows());
        if (progressBar != null) progressBar.setVisibility(View.GONE);
        if (btnRefresh  != null) btnRefresh.setEnabled(true);
    }

    /**
     * 默认实现：把降级事件统一沉淀到 logcat。
     *
     * <p>子类可重写以替换为 Toast / Snackbar / 顶部告警条等可视化机制。</p>
     */
    @MainThread
    protected void onDegradesObserved(@NonNull final List<DegradeEntry> degrades) {
        if (degrades.isEmpty()) return;
        final String tag = getLogTag();
        for (final DegradeEntry d : degrades) {
            Log.w(tag, d.toString());
        }
    }

    // ───────────────────────────────────────────────────────────────
    // 销毁路径（杜绝僵尸回调）
    // ───────────────────────────────────────────────────────────────

    @Override
    public void onDestroyView() {
        super.onDestroyView();

        // ① 立刻清空 mainHandler 上所有挂起但尚未执行的投递。
        //   removeCallbacksAndMessages(null) 会移除任意 token 的消息和 callback。
        //   注意：这只能清掉"已入队"的消息——worker 在被中断后可能仍会调用
        //   mainHandler.post(...) 追加新消息，那些"僵尸投递"靠 SuccessDelivery#run
        //   里的双重防御吃掉。
        mainHandler.removeCallbacksAndMessages(null);

        // ② 中断后台任务并销毁 executor。
        //   shutdownNow 会向 worker 线程发送 interrupt，
        //   collectInfo 内若有阻塞 IO 会抛 InterruptedException 提前退出。
        if (runningTask != null) {
            runningTask.cancel(true);
            runningTask = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }

        // ③ 状态机回退：LOADING → IDLE，让下次 onCreateView 能重新触发加载。
        //   SUCCESS / ERROR 状态保留，配合 cachedResult 实现"切回 tab 即时回显"。
        if (state == LoadState.LOADING) {
            state = LoadState.IDLE;
        }

        // ④ 释放所有 View 引用，避免 GC 根可达 Activity / 大图等资源
        adapter     = null;
        progressBar = null;
        btnRefresh  = null;
    }

    // ───────────────────────────────────────────────────────────────
    // 子类契约
    // ───────────────────────────────────────────────────────────────

    /**
     * 在 worker 线程上执行的采集逻辑。
     *
     * <p>实现者必须返回 {@link CollectionResult}（行数据 + 降级事件），
     * 不得返回 {@code null}（基类会做兜底但仅作为防御性容错）。</p>
     *
     * <p>{@code env} 由基类在主线程构造、跨线程传入。
     * 实现者<b>禁止持久持有此引用</b>，因 Fragment 销毁后允许其被 GC。</p>
     *
     * @param env 系统环境句柄，调用期内有效
     */
    @WorkerThread
    @NonNull
    protected abstract CollectionResult collectInfo(@NonNull SystemEnvironment env);

    /** 子类可重写以配置 Adapter（如设置点击回调）。 */
    @MainThread
    protected void onAdapterReady(@NonNull final InfoAdapter adapter) {}

    /** 子类可重写以提供专属 logcat 标签；默认使用类名。 */
    @NonNull
    protected String getLogTag() {
        return getClass().getSimpleName();
    }
}
