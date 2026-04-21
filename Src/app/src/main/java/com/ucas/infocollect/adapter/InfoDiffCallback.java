package com.ucas.infocollect.adapter;

import androidx.recyclerview.widget.DiffUtil;

import com.ucas.infocollect.model.InfoRow;

import java.util.List;
import java.util.Objects;

public class InfoDiffCallback extends DiffUtil.Callback {

    private final List<InfoRow> oldList;
    private final List<InfoRow> newList;

    public InfoDiffCallback(List<InfoRow> oldList, List<InfoRow> newList) {
        this.oldList = oldList;
        this.newList = newList;
    }

    @Override
    public int getOldListSize() {
        return oldList.size();
    }

    @Override
    public int getNewListSize() {
        return newList.size();
    }

    @Override
    public boolean areItemsTheSame(int oldItemPosition, int newItemPosition) {
        return oldList.get(oldItemPosition).getStableId()
            == newList.get(newItemPosition).getStableId();
    }

    @Override
    public boolean areContentsTheSame(int oldItemPosition, int newItemPosition) {
        InfoRow oldItem = oldList.get(oldItemPosition);
        InfoRow newItem = newList.get(newItemPosition);
        return oldItem.getType() == newItem.getType()
            && Objects.equals(oldItem.getKey(), newItem.getKey())
            && Objects.equals(oldItem.getValue(), newItem.getValue())
            && oldItem.getRiskLevel() == newItem.getRiskLevel();
    }
}
