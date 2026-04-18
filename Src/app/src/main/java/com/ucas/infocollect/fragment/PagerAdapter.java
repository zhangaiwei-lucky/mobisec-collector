package com.ucas.infocollect.fragment;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

/**
 * ViewPager2 适配器，管理六个信息收集页面
 */
public class PagerAdapter extends FragmentStateAdapter {

    public PagerAdapter(@NonNull FragmentActivity activity) {
        super(activity);
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        switch (position) {
            case 0: return new DeviceFragment();    // 设备/系统信息
            case 1: return new AppsFragment();      // 已安装应用
            case 2: return new SensorFragment();    // 传感器侧信道（亮点）
            case 3: return new NetworkFragment();   // 网络信息
            case 4: return new UserFragment();      // 用户账户与数据
            case 5: return new SecurityFragment();  // 安全分析（课件联动）
            default: return new DeviceFragment();
        }
    }

    @Override
    public int getItemCount() {
        return 6;
    }
}
