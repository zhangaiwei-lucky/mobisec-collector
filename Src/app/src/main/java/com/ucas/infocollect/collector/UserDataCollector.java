package com.ucas.infocollect.collector;

import android.Manifest;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.database.Cursor;
import android.os.Build;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.Settings;

import androidx.annotation.NonNull;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * 用户数据收集器（V2 无 Context 版）。
 *
 * <p>注意：剪贴板读取需要 App 处于前台焦点状态（Android 10+ 限制）。</p>
 */
public class UserDataCollector implements InfoCollectorV2 {

    private static final int MAX_CONTACT_DISPLAY = 10;
    private static final int MAX_CALL_LOG_DISPLAY = 10;

    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        return Arrays.asList(
            Manifest.permission.GET_ACCOUNTS,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_CALL_LOG
        );
    }

    @NonNull
    @Override
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder result = CollectionResult.builder();

        result.addHeader("剪贴板内容（需 App 处于前台焦点）");
        readClipboard(env, result);

        result.addHeader("锁屏安全状态");
        readLockScreenInfo(env, result);

        result.addHeader("设备关联账户");
        readAccounts(env, result);

        result.addHeader("联系人（前10条）");
        readContacts(env, result);

        result.addHeader("通话记录（前10条）");
        readCallLog(env, result);

        result.addHeader("用户偏好与设备习惯");
        readPreferences(env, result);

        return result.build();
    }

    private void readClipboard(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final ClipboardManager cm = env.getSystemService(ClipboardManager.class);
            if (cm == null) {
                result.addDegrade("剪贴板", DegradeReason.SERVICE_UNAVAILABLE,
                    "ClipboardManager 不可用");
                return;
            }
            if (!cm.hasPrimaryClip()) {
                result.add("剪贴板", "当前为空");
                return;
            }
            final ClipData clip = cm.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0) {
                result.add("剪贴板", "无内容");
                return;
            }
            final ClipData.Item item = clip.getItemAt(0);
            final CharSequence text  = item.getText();
            if (text != null && text.length() > 0) {
                result.addHighRisk("剪贴板文本", text.toString());
            } else if (item.getUri() != null) {
                result.addHighRisk("剪贴板 URI", item.getUri().toString());
            } else {
                result.add("剪贴板", "含内容但非文本/URI 类型");
            }
            result.add("剪贴板 MIME 类型", clip.getDescription().getMimeType(0));
        } catch (final SecurityException e) {
            result.addDegrade("剪贴板", DegradeReason.SYSTEM_RESTRICTED,
                "Android 10+ 限制：需在前台焦点状态读取，请点击「刷新」按钮重试");
        } catch (final Exception e) {
            result.addDegrade("剪贴板", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readLockScreenInfo(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final KeyguardManager km = env.getSystemService(KeyguardManager.class);
            if (km == null) {
                result.addDegrade("锁屏", DegradeReason.SERVICE_UNAVAILABLE, "KeyguardManager 不可用");
                return;
            }
            final boolean isSecure = km.isDeviceSecure();
            result.add("是否设置锁屏密码",
                isSecure ? "是（设备受保护）" : "否（无锁屏）");

            final boolean isLocked = km.isKeyguardLocked();
            result.add("当前是否锁屏", String.valueOf(isLocked));

            final ContentResolver cr = env.getContentResolver();
            final String timeout =
                Settings.System.getString(cr, Settings.System.SCREEN_OFF_TIMEOUT);
            if (timeout != null) {
                result.add("屏幕自动锁定时间", formatDuration(Long.parseLong(timeout)));
            }
        } catch (final Exception e) {
            result.addDegrade("锁屏状态", DegradeReason.READ_FAILED, String.valueOf(e.getMessage()));
        }

        try {
            final ContentResolver cr = env.getContentResolver();
            int adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, -1);
            if (adb == -1) adb = Settings.Secure.getInt(cr, "adb_enabled", 0);
            if (adb == 1) {
                result.addHighRisk("ADB 调试", "已开启（USB 可直接提取数据）");
            } else {
                result.add("ADB 调试", "关闭");
            }

            int dev = Settings.Global.getInt(cr,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1);
            if (dev == -1) {
                String devStr = Settings.Global.getString(cr, "development_settings_enabled");
                if (devStr == null)
                    devStr = Settings.Secure.getString(cr, "development_settings_enabled");
                dev = "1".equals(devStr) ? 1 : 0;
            }
            if (adb == 1) dev = 1;
            if (dev == 1) {
                result.addHighRisk("开发者选项", "已开启");
            } else {
                result.add("开发者选项", "关闭");
            }
        } catch (final Exception e) {
            result.addDegrade("开发者/ADB 状态", DegradeReason.READ_FAILED,
                String.valueOf(e.getMessage()));
        }
    }

    private void readAccounts(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final AccountManager am = env.getSystemService(AccountManager.class);
            if (am == null) {
                result.addDegrade("账户", DegradeReason.SERVICE_UNAVAILABLE, "AccountManager 不可用");
                return;
            }

            Account[] accounts;
            try {
                accounts = am.getAccounts();
                result.add("GET_ACCOUNTS 权限", "已授权");
            } catch (final SecurityException e) {
                result.add("GET_ACCOUNTS 权限", "未授权");
                accounts = am.getAccountsByType("com.google");
            }

            if (accounts == null || accounts.length == 0) {
                result.add("账户", "未获取到账户信息");
            } else {
                result.add("账户总数", String.valueOf(accounts.length));
                for (final Account acc : accounts) {
                    result.addHighRisk(acc.name, "类型: " + acc.type);
                }
            }
        } catch (final Exception e) {
            result.addDegrade("账户", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readContacts(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final Cursor cursor = env.getContentResolver().query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                new String[]{
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER,
                    ContactsContract.CommonDataKinds.Phone.TIMES_CONTACTED
                },
                null, null,
                ContactsContract.CommonDataKinds.Phone.TIMES_CONTACTED + " DESC"
            );
            if (cursor == null) {
                result.addDegrade("联系人", DegradeReason.NO_DATA, "查询返回 null");
                return;
            }
            result.add("联系人总数", String.valueOf(cursor.getCount()));
            int count = 0;
            while (cursor.moveToNext() && count++ < MAX_CONTACT_DISPLAY) {
                final String name   = cursor.getString(0);
                final String number = cursor.getString(1);
                result.addHighRisk(name != null ? name : "(无名称)",
                    number != null ? number : "无号码");
            }
            cursor.close();
        } catch (final SecurityException e) {
            result.addDegrade("联系人", DegradeReason.PERMISSION_DENIED,
                "缺少 READ_CONTACTS 权限");
        } catch (final Exception e) {
            result.addDegrade("联系人", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readCallLog(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final Cursor cursor = env.getContentResolver().query(
                CallLog.Calls.CONTENT_URI,
                new String[]{
                    CallLog.Calls.CACHED_NAME,
                    CallLog.Calls.NUMBER,
                    CallLog.Calls.TYPE,
                    CallLog.Calls.DATE,
                    CallLog.Calls.DURATION
                },
                null, null,
                CallLog.Calls.DATE + " DESC"
            );
            if (cursor == null) {
                result.addDegrade("通话记录", DegradeReason.NO_DATA, "查询返回 null");
                return;
            }
            result.add("通话记录总数", String.valueOf(cursor.getCount()));
            final SimpleDateFormat sdf =
                new SimpleDateFormat("MM-dd HH:mm", Locale.getDefault());
            int count = 0;
            while (cursor.moveToNext() && count++ < MAX_CALL_LOG_DISPLAY) {
                final String name   = cursor.getString(0);
                final String number = cursor.getString(1);
                final int    type   = cursor.getInt(2);
                final long   date   = cursor.getLong(3);
                final long   dur    = cursor.getLong(4);
                final String typeStr = type == CallLog.Calls.INCOMING_TYPE ? "接入" :
                                       type == CallLog.Calls.OUTGOING_TYPE ? "呼出" : "未接";
                final String label = (name != null && !name.isEmpty()) ? name : number;
                result.addHighRisk(label + " [" + typeStr + "]",
                    sdf.format(new Date(date)) + " 时长:" + dur + "s");
            }
            cursor.close();
        } catch (final SecurityException e) {
            result.addDegrade("通话记录", DegradeReason.PERMISSION_DENIED,
                "缺少 READ_CALL_LOG 权限");
        } catch (final Exception e) {
            result.addDegrade("通话记录", DegradeReason.READ_FAILED,
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readPreferences(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final ContentResolver cr = env.getContentResolver();
            result.add("时区",     TimeZone.getDefault().getID());
            result.add("系统语言", Locale.getDefault().toString());
            result.add("字体缩放",
                Settings.System.getString(cr, Settings.System.FONT_SCALE));
            result.add("屏幕亮度",
                Settings.System.getString(cr, Settings.System.SCREEN_BRIGHTNESS));
            final String autoRotate =
                Settings.System.getString(cr, Settings.System.ACCELEROMETER_ROTATION);
            result.add("自动旋转", "1".equals(autoRotate) ? "开启" : "关闭");

            final String installUnknown;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                installUnknown = "请查看设置（Android 8+ 改为单应用授权）";
            } else {
                installUnknown = Settings.Secure.getInt(cr,
                    Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
                    ? "已允许" : "不允许";
            }
            result.add("安装未知来源 App", installUnknown);
        } catch (final Exception e) {
            result.addDegrade("用户偏好", DegradeReason.READ_FAILED, String.valueOf(e.getMessage()));
        }
    }

    private String formatDuration(final long ms) {
        final long sec = ms / 1000;
        if (sec < 60) return sec + " 秒";
        final long min = sec / 60;
        if (min < 60) return min + " 分钟";
        return (min / 60) + " 小时 " + (min % 60) + " 分钟";
    }
}
