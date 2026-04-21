package com.ucas.infocollect.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.RecyclerView;

import com.ucas.infocollect.R;
import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;
import com.ucas.infocollect.model.RowType;

import java.util.List;

/**
 * 通用键值对信息列表适配器
 * 支持强类型行模型，避免 key 冲突导致 Diff 异常。
 */
public class InfoAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final int TYPE_HEADER = 0;
    private static final int TYPE_ITEM   = 1;

    private final List<InfoRow> items = new java.util.ArrayList<>();

    public InfoAdapter(List<InfoRow> initialItems) {
        setHasStableIds(true);
        if (initialItems != null) this.items.addAll(initialItems);
    }

    public void updateData(List<InfoRow> newItems) {
        List<InfoRow> safeNewItems =
            newItems != null ? newItems : new java.util.ArrayList<>();
        List<InfoRow> oldItems = new java.util.ArrayList<>(items);
        DiffUtil.DiffResult diffResult =
            DiffUtil.calculateDiff(new InfoDiffCallback(oldItems, safeNewItems));
        items.clear();
        items.addAll(safeNewItems);
        diffResult.dispatchUpdatesTo(this);
    }

    @Override
    public int getItemViewType(int position) {
        return items.get(position).getType() == RowType.HEADER
            ? TYPE_HEADER : TYPE_ITEM;
    }

    @Override
    public long getItemId(int position) {
        return items.get(position).getStableId();
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        if (viewType == TYPE_HEADER) {
            View v = inflater.inflate(R.layout.item_header, parent, false);
            return new HeaderHolder(v);
        } else {
            View v = inflater.inflate(R.layout.item_info, parent, false);
            return new ItemHolder(v);
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        InfoRow entry = items.get(position);
        if (holder instanceof HeaderHolder) {
            ((HeaderHolder) holder).title.setText(entry.getKey());
        } else {
            ItemHolder h = (ItemHolder) holder;
            h.key.setText(entry.getKey());
            h.value.setText(entry.getValue());
            // 高敏感度信息用红色标注
            if (entry.getRiskLevel() == RiskLevel.HIGH) {
                h.value.setTextColor(ContextCompat.getColor(h.value.getContext(), R.color.risk_high_text));
            } else {
                h.value.setTextColor(ContextCompat.getColor(h.value.getContext(), R.color.info_text_primary));
            }
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class HeaderHolder extends RecyclerView.ViewHolder {
        TextView title;
        HeaderHolder(View v) {
            super(v);
            title = v.findViewById(R.id.header_title);
        }
    }

    static class ItemHolder extends RecyclerView.ViewHolder {
        TextView key, value;
        ItemHolder(View v) {
            super(v);
            key   = v.findViewById(R.id.info_key);
            value = v.findViewById(R.id.info_value);
        }
    }
}
