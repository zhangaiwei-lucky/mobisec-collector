package com.ucas.infocollect.collector;

import android.content.ContentResolver;
import android.content.pm.PackageManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * 系统环境防腐层（Anti-Corruption Layer）。
 *
 * <p>Collector 实现类只允许通过此接口访问系统资源，禁止持有或接受任何
 * {@code android.content.Context} 引用。这使得 Collector 层与 Android 运行时
 * 解耦，具备独立测试能力。</p>
 *
 * <p>此接口的 Android 运行时实现为 {@link AndroidSystemEnvironment}，
 * 测试环境可注入 stub/mock 实现。</p>
 */
public interface SystemEnvironment {

    /**
     * 获取系统服务，语义等价于 {@code Context.getSystemService(Class)}。
     *
     * @param serviceClass 目标服务类型，例如 {@code TelephonyManager.class}
     * @return 服务实例；若当前设备或 API 级别不支持，则返回 {@code null}
     */
    @Nullable
    <T> T getSystemService(@NonNull Class<T> serviceClass);

    /**
     * 读取 {@code Settings.Secure} 字符串字段。
     *
     * @param key {@code android.provider.Settings.Secure} 中定义的常量
     * @return 字段值；不存在或读取失败时返回 {@code null}
     */
    @Nullable
    String getSecureStringSetting(@NonNull String key);

    /**
     * 读取 {@code Settings.Secure} 整型字段。
     *
     * @param key      {@code android.provider.Settings.Secure} 中定义的常量
     * @param defValue 字段不存在时的默认返回值
     */
    int getSecureIntSetting(@NonNull String key, int defValue);

    /**
     * 读取 {@code Settings.Global} 整型字段。
     *
     * @param key      {@code android.provider.Settings.Global} 中定义的常量
     * @param defValue 字段不存在时的默认返回值
     */
    int getGlobalIntSetting(@NonNull String key, int defValue);

    /**
     * 提供 {@link PackageManager} 实例，用于枚举已安装应用及其元数据。
     *
     * <p>调用方不得持久持有返回的引用；每次需要时应重新获取，
     * 以防 Activity 重建后出现陈旧实例。</p>
     */
    @NonNull
    PackageManager getPackageManager();

    /**
     * 提供 {@link ContentResolver} 实例，用于访问 MediaStore、联系人、
     * 通话记录及 {@code Settings} 等 ContentProvider 数据源。
     *
     * <p>Collector 层使用此方法获取 ContentResolver，禁止绕过此接口
     * 直接访问 {@code android.content.Context}。</p>
     */
    @NonNull
    ContentResolver getContentResolver();

    /**
     * 返回宿主应用的包名（{@code applicationId}）。
     *
     * <p>用于 {@code AppOpsManager.checkOpNoThrow(op, uid, packageName)}
     * 等需要包名参数的系统 API 调用。</p>
     */
    @NonNull
    String getPackageName();
}
