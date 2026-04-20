package com.ucas.infocollect.adapter;

import androidx.recyclerview.widget.DiffUtil;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public class InfoDiffCallback extends DiffUtil.Callback {

    private final List<Map.Entry<String, String>> oldList;
    private final List<Map.Entry<String, String>> newList;

    public InfoDiffCallback(List<Map.Entry<String, String>> oldList,
                            List<Map.Entry<String, String>> newList) {
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
        return Objects.equals(oldList.get(oldItemPosition).getKey(),
            newList.get(newItemPosition).getKey());
    }

    @Override
    public boolean areContentsTheSame(int oldItemPosition, int newItemPosition) {
        Map.Entry<String, String> oldItem = oldList.get(oldItemPosition);
        Map.Entry<String, String> newItem = newList.get(newItemPosition);
        return Objects.equals(oldItem.getKey(), newItem.getKey())
            && Objects.equals(oldItem.getValue(), newItem.getValue());
    }
}
