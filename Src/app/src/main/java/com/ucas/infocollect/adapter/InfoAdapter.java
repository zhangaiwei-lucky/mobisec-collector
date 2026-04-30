package com.ucas.infocollect.adapter;

import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.RecyclerView;

import com.ucas.infocollect.R;
import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;
import com.ucas.infocollect.model.RowType;

import java.util.List;

public class InfoAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final int TYPE_HEADER   = 0;
    private static final int TYPE_ITEM     = 1;
    private static final int TYPE_APP_ITEM = 2;

    public interface OnItemClickListener {
        void onAppItemClick(String packageName);
    }

    private final List<InfoRow> items = new java.util.ArrayList<>();
    @Nullable private OnItemClickListener clickListener;

    public InfoAdapter(List<InfoRow> initialItems) {
        setHasStableIds(true);
        if (initialItems != null) this.items.addAll(initialItems);
    }

    public void setOnItemClickListener(@Nullable OnItemClickListener listener) {
        this.clickListener = listener;
    }

    public void updateData(List<InfoRow> newItems) {
        List<InfoRow> safeNew = newItems != null ? newItems : new java.util.ArrayList<>();
        List<InfoRow> oldItems = new java.util.ArrayList<>(items);
        DiffUtil.DiffResult diff = DiffUtil.calculateDiff(new InfoDiffCallback(oldItems, safeNew));
        items.clear();
        items.addAll(safeNew);
        diff.dispatchUpdatesTo(this);
    }

    @Override
    public int getItemViewType(int position) {
        RowType type = items.get(position).getType();
        if (type == RowType.HEADER)   return TYPE_HEADER;
        if (type == RowType.APP_ITEM) return TYPE_APP_ITEM;
        return TYPE_ITEM;
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
            return new HeaderHolder(inflater.inflate(R.layout.item_header, parent, false));
        } else if (viewType == TYPE_APP_ITEM) {
            return new AppHolder(inflater.inflate(R.layout.item_app, parent, false));
        } else {
            return new ItemHolder(inflater.inflate(R.layout.item_info, parent, false));
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        InfoRow entry = items.get(position);
        if (holder instanceof HeaderHolder) {
            ((HeaderHolder) holder).title.setText(entry.getKey());
        } else if (holder instanceof AppHolder) {
            bindAppHolder((AppHolder) holder, entry);
        } else {
            bindItemHolder((ItemHolder) holder, entry);
        }
    }

    private void bindItemHolder(ItemHolder h, InfoRow entry) {
        h.key.setText(entry.getKey());
        h.value.setText(entry.getValue());
        if (entry.getRiskLevel() == RiskLevel.HIGH) {
            h.value.setTextColor(ContextCompat.getColor(h.value.getContext(), R.color.risk_high_text));
        } else {
            h.value.setTextColor(ContextCompat.getColor(h.value.getContext(), R.color.info_text_primary));
        }
    }

    private void bindAppHolder(AppHolder h, InfoRow entry) {
        String packageName = entry.getPayload();
        h.name.setText(entry.getKey());
        h.pkg.setText(packageName != null ? packageName : "");

        if (packageName != null) {
            try {
                PackageManager pm = h.itemView.getContext().getPackageManager();
                Drawable icon = pm.getApplicationIcon(packageName);
                h.icon.setImageDrawable(icon);
            } catch (Exception e) {
                h.icon.setImageResource(android.R.drawable.sym_def_app_icon);
            }
        } else {
            h.icon.setImageResource(android.R.drawable.sym_def_app_icon);
        }

        if (entry.getRiskLevel() == RiskLevel.HIGH) {
            h.permBadge.setVisibility(View.VISIBLE);
            h.permBadge.setText(entry.getValue());
        } else {
            h.permBadge.setVisibility(View.GONE);
        }

        h.itemView.setOnClickListener(v -> {
            if (clickListener != null && packageName != null) {
                clickListener.onAppItemClick(packageName);
            }
        });
    }

    @Override
    public int getItemCount() { return items.size(); }


    static class HeaderHolder extends RecyclerView.ViewHolder {
        TextView title;
        HeaderHolder(View v) { super(v); title = v.findViewById(R.id.header_title); }
    }

    static class ItemHolder extends RecyclerView.ViewHolder {
        TextView key, value;
        ItemHolder(View v) {
            super(v);
            key   = v.findViewById(R.id.info_key);
            value = v.findViewById(R.id.info_value);
        }
    }

    static class AppHolder extends RecyclerView.ViewHolder {
        ImageView icon;
        TextView  name, pkg, permBadge;
        AppHolder(View v) {
            super(v);
            icon      = v.findViewById(R.id.app_icon);
            name      = v.findViewById(R.id.app_name);
            pkg       = v.findViewById(R.id.app_package);
            permBadge = v.findViewById(R.id.perm_badge);
        }
    }
}
