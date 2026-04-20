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

    public static class TabSpec {
        private final String title;
        private final FragmentFactory fragmentFactory;

        public TabSpec(@NonNull String title, @NonNull FragmentFactory fragmentFactory) {
            this.title = title;
            this.fragmentFactory = fragmentFactory;
        }

        public String getTitle() {
            return title;
        }

        public FragmentFactory getFragmentFactory() {
            return fragmentFactory;
        }
    }

    private final List<TabSpec> tabSpecs;

    public PagerAdapter(
            @NonNull FragmentActivity activity,
            @NonNull List<TabSpec> tabSpecs
    ) {
        super(activity);
        if (tabSpecs.isEmpty()) {
            throw new IllegalArgumentException("tabSpecs must not be empty");
        }
        this.tabSpecs = new ArrayList<>(tabSpecs);
    }

    public String getTabTitle(int position) {
        return tabSpecs.get(position).getTitle();
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        return tabSpecs.get(position).getFragmentFactory().create();
    }

    @Override
    public int getItemCount() {
        return tabSpecs.size();
    }
}
