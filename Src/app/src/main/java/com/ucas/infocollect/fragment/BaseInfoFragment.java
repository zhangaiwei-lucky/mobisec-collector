package com.ucas.infocollect.fragment;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ucas.infocollect.R;
import com.ucas.infocollect.adapter.InfoAdapter;
import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

/**
 * 通用信息列表 Fragment 基类
 * - 数据在后台线程收集，避免主线程卡顿
 * - 提供"刷新"按钮，让用户在切换到该 tab 后手动触发（对剪贴板等敏感数据尤其重要）
 */
public abstract class BaseInfoFragment extends Fragment {

    private InfoAdapter adapter;
    private ProgressBar progressBar;
    private Button btnRefresh;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    /**
     * 线程池与任务句柄绑定到 View 生命周期，避免 onDestroyView 后复用失效 executor。
     */
    @Nullable
    private ExecutorService executor;
    @Nullable
    private Future<?> runningTask;
    private final Object taskLock = new Object();
    private volatile boolean viewActive = false;
    private boolean loaded = false;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
            @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_list, container, false);
        viewActive = true;
        ensureExecutor();

        RecyclerView recyclerView = view.findViewById(R.id.recycler_view);
        progressBar = view.findViewById(R.id.progress_loading);
        btnRefresh = view.findViewById(R.id.btn_refresh);

        recyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new InfoAdapter(new java.util.ArrayList<>());
        recyclerView.setAdapter(adapter);

        btnRefresh.setOnClickListener(v -> loadData());

        // 首次进入 tab 时自动加载
        if (!loaded) loadData();

        return view;
    }

    /** 在后台线程收集数据，完成后在主线程更新 UI */
    protected void loadData() {
        if (!isViewUsable()) return;

        synchronized (taskLock) {
            if (runningTask != null && !runningTask.isDone()) {
                return;
            }
        }

        progressBar.setVisibility(View.VISIBLE);
        btnRefresh.setEnabled(false);

        ExecutorService activeExecutor = ensureExecutor();
        if (activeExecutor == null) {
            if (btnRefresh != null) btnRefresh.setEnabled(true);
            if (progressBar != null) progressBar.setVisibility(View.GONE);
            return;
        }

        try {
            Future<?> task = activeExecutor.submit(() -> {
                List<InfoRow> data;
                try {
                    data = collectInfo();
                } catch (Exception e) {
                    data = new java.util.ArrayList<>();
                    data.add(InfoRow.item("收集异常", e.getMessage(), RiskLevel.HIGH));
                }
                final List<InfoRow> result = data;
                mainHandler.post(() -> {
                    synchronized (taskLock) {
                        runningTask = null;
                    }
                    if (!isViewUsable()) return;
                    adapter.updateData(result);
                    progressBar.setVisibility(View.GONE);
                    btnRefresh.setEnabled(true);
                    loaded = true;
                });
            });
            synchronized (taskLock) {
                runningTask = task;
            }
        } catch (RejectedExecutionException e) {
            if (btnRefresh != null) btnRefresh.setEnabled(true);
            if (progressBar != null) progressBar.setVisibility(View.GONE);
        }
    }

    protected abstract List<InfoRow> collectInfo();

    @Override
    public void onDestroyView() {
        viewActive = false;
        super.onDestroyView();
        mainHandler.removeCallbacksAndMessages(null);
        synchronized (taskLock) {
            if (runningTask != null && !runningTask.isDone()) {
                runningTask.cancel(true);
            }
            runningTask = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        adapter = null;
        progressBar = null;
        btnRefresh = null;
    }

    @Nullable
    private ExecutorService ensureExecutor() {
        if (executor == null || executor.isShutdown() || executor.isTerminated()) {
            executor = Executors.newSingleThreadExecutor();
        }
        return executor;
    }

    private boolean isViewUsable() {
        return viewActive
                && isAdded()
                && getView() != null
                && adapter != null
                && progressBar != null
                && btnRefresh != null;
    }
}
