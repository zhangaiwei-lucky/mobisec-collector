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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private boolean loaded = false;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
            @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_list, container, false);

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
        if (progressBar == null) return;
        progressBar.setVisibility(View.VISIBLE);
        btnRefresh.setEnabled(false);

        executor.execute(() -> {
            List<Map.Entry<String, String>> data;
            try {
                data = collectInfo();
            } catch (Exception e) {
                data = new java.util.ArrayList<>();
                data.add(new java.util.AbstractMap.SimpleEntry<>("收集异常", e.getMessage()));
            }
            final List<Map.Entry<String, String>> result = data;
            mainHandler.post(() -> {
                adapter.updateData(result);
                if (progressBar != null) progressBar.setVisibility(View.GONE);
                if (btnRefresh != null) btnRefresh.setEnabled(true);
                loaded = true;
            });
        });
    }

    protected abstract List<Map.Entry<String, String>> collectInfo();

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        mainHandler.removeCallbacksAndMessages(null);
        executor.shutdownNow();
        progressBar = null;
        btnRefresh = null;
    }
}
