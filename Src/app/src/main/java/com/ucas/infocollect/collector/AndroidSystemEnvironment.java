package com.ucas.infocollect.collector;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.Settings;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * {@link SystemEnvironment} 的 Android 运行时实现。
 *
 * <p>此类是 Context 唯一被允许存在的边界层。它封装了所有
 * {@code Context.getSystemService}、{@code ContentResolver} 及
 * {@code Settings} 访问，对 Collector 层暴露纯接口。</p>
 *
 * <p><b>实例化规则：</b>只允许在应用层（Fragment / Activity / Application）
 * 创建本实例，禁止将其下沉到 Collector 实现内部。</p>
 */
public final class AndroidSystemEnvironment implements SystemEnvironment {

    @NonNull
    private final Context appContext;

    /**
     * @param context 任意 Context；内部自动切换为 ApplicationContext 以避免内存泄漏
     */
    public AndroidSystemEnvironment(@NonNull final Context context) {
        this.appContext = context.getApplicationContext();
    }

    @Nullable
    @Override
    public <T> T getSystemService(@NonNull final Class<T> serviceClass) {
        try {
            return appContext.getSystemService(serviceClass);
        } catch (final Exception ignored) {
            return null;
        }
    }

    @SuppressLint("HardwareIds")
    @Nullable
    @Override
    public String getSecureStringSetting(@NonNull final String key) {
        try {
            return Settings.Secure.getString(appContext.getContentResolver(), key);
        } catch (final Exception ignored) {
            return null;
        }
    }

    @Override
    public int getSecureIntSetting(@NonNull final String key, final int defValue) {
        try {
            return Settings.Secure.getInt(appContext.getContentResolver(), key, defValue);
        } catch (final Exception ignored) {
            return defValue;
        }
    }

    @Override
    public int getGlobalIntSetting(@NonNull final String key, final int defValue) {
        try {
            return Settings.Global.getInt(appContext.getContentResolver(), key, defValue);
        } catch (final Exception ignored) {
            return defValue;
        }
    }

    @NonNull
    @Override
    public PackageManager getPackageManager() {
        return appContext.getPackageManager();
    }
}
