package com.ucas.infocollect.fragment;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import java.util.ArrayList;
import java.util.List;

/**
 * ViewPager2 适配器，按构造传入的页面工厂管理标签页
 */
public class PagerAdapter extends FragmentStateAdapter {

    public interface FragmentFactory {
        Fragment create();
    }

    private final List<FragmentFactory> fragmentFactories;

    public PagerAdapter(
            @NonNull FragmentActivity activity,
            @NonNull List<FragmentFactory> fragmentFactories
    ) {
        super(activity);
        if (fragmentFactories.isEmpty()) {
            throw new IllegalArgumentException("fragmentFactories must not be empty");
        }
        this.fragmentFactories = new ArrayList<>(fragmentFactories);
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        return fragmentFactories.get(position).create();
    }

    @Override
    public int getItemCount() {
        return fragmentFactories.size();
    }
}
