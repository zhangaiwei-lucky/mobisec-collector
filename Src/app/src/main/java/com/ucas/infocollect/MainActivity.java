package com.ucas.infocollect;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;
import com.ucas.infocollect.fragment.PagerAdapter;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final int PERMISSION_REQUEST_CODE = 100;

    private static final String[] TAB_TITLES = {
        "设备", "应用", "传感器★", "网络", "用户", "安全分析"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ViewPager2 viewPager = findViewById(R.id.view_pager);
        TabLayout tabLayout = findViewById(R.id.tab_layout);

        PagerAdapter adapter = new PagerAdapter(this);
        viewPager.setAdapter(adapter);
        // 不设置 offscreenPageLimit，让 Fragment 按需创建
        // 这样 UserFragment 只在切换到该 tab 时才初始化，此时 app 已获得焦点
        // 传感器 Fragment 通过 onResume/onPause 自行管理注册状态

        new TabLayoutMediator(tabLayout, viewPager,
            (tab, position) -> tab.setText(TAB_TITLES[position])
        ).attach();

        requestMissingPermissions();
    }

    private void requestMissingPermissions() {
        List<String> dangerousPermissions = buildDangerousPermissions();
        List<String> missing = new ArrayList<>();
        for (String perm : dangerousPermissions) {
            if (ContextCompat.checkSelfPermission(this, perm)
                    != PackageManager.PERMISSION_GRANTED) {
                missing.add(perm);
            }
        }
        if (!missing.isEmpty()) {
            ActivityCompat.requestPermissions(
                this, missing.toArray(new String[0]), PERMISSION_REQUEST_CODE);
        }
    }

    private List<String> buildDangerousPermissions() {
        List<String> permList = new ArrayList<>();
        permList.add(Manifest.permission.READ_PHONE_STATE);
        permList.add(Manifest.permission.GET_ACCOUNTS);
        permList.add(Manifest.permission.READ_CONTACTS);
        permList.add(Manifest.permission.READ_CALL_LOG);
        permList.add(Manifest.permission.ACCESS_FINE_LOCATION);
        permList.add(Manifest.permission.ACCESS_COARSE_LOCATION);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permList.add(Manifest.permission.READ_MEDIA_IMAGES);
            permList.add(Manifest.permission.READ_MEDIA_VIDEO);
        } else {
            permList.add(Manifest.permission.READ_EXTERNAL_STORAGE);
        }
        return permList;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
            @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            int granted = 0;
            for (int r : grantResults) if (r == PackageManager.PERMISSION_GRANTED) granted++;
            Toast.makeText(this, "已获得 " + granted + "/" + grantResults.length + " 项权限",
                Toast.LENGTH_SHORT).show();
        }
    }
}
