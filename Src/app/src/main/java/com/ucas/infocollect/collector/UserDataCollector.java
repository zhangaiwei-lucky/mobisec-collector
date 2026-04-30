package com.ucas.infocollect.collector;

import android.Manifest;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.Build;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.Settings;

import androidx.core.content.ContextCompat;

import com.ucas.infocollect.model.InfoRow;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

public class UserDataCollector implements InfoCollector {

    private static final int MAX_CONTACT_DISPLAY = 10;
    private static final int MAX_CALL_LOG_DISPLAY = 10;

    @Override
    public List<InfoRow> collect(Context context) {
        List<InfoRow> items = new ArrayList<>();

        CollectorUtils.addHeader(items, "剪贴板内容（需 App 处于前台焦点）");
        readClipboard(context, items);

        CollectorUtils.addHeader(items, "锁屏安全状态");
        readLockScreenInfo(context, items);

        CollectorUtils.addHeader(items, "设备关联账户");
        readAccounts(context, items);

        CollectorUtils.addHeader(items, "联系人（前10条）");
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS)
                == PackageManager.PERMISSION_GRANTED) {
            readContacts(context, items);
        } else {
            CollectorUtils.add(items, "状态", "未授予 READ_CONTACTS 权限");
        }

        CollectorUtils.addHeader(items, "通话记录（前10条）");
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALL_LOG)
                == PackageManager.PERMISSION_GRANTED) {
            readCallLog(context, items);
        } else {
            CollectorUtils.add(items, "状态", "未授予 READ_CALL_LOG 权限");
        }

        CollectorUtils.addHeader(items, "用户偏好与设备习惯");
        readPreferences(context, items);

        return items;
    }


    private void readClipboard(Context context, List<InfoRow> items) {
        try {
            ClipboardManager cm =
                (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm == null) {
                CollectorUtils.add(items, "剪贴板", "ClipboardManager 不可用");
                return;
            }
            if (!cm.hasPrimaryClip()) {
                CollectorUtils.add(items, "剪贴板", "当前为空");
                return;
            }
            ClipData clip = cm.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0) {
                CollectorUtils.add(items, "剪贴板", "无内容");
                return;
            }
            ClipData.Item item = clip.getItemAt(0);
            CharSequence text = item.getText();
            if (text != null && text.length() > 0) {
                CollectorUtils.add(items, "剪贴板文本", CollectorUtils.HIGH_RISK_PREFIX + text);
            } else if (item.getUri() != null) {
                CollectorUtils.add(items, "剪贴板 URI", CollectorUtils.HIGH_RISK_PREFIX + item.getUri().toString());
            } else {
                CollectorUtils.add(items, "剪贴板", "含内容但非文本/URI 类型");
            }
            CollectorUtils.add(items, "剪贴板 MIME 类型",
                clip.getDescription().getMimeType(0));
        } catch (SecurityException e) {
            CollectorUtils.add(items, "剪贴板", "Android 10+ 限制：需在前台焦点状态读取\n请点击「刷新」按钮重试");
        } catch (Exception e) {
            CollectorUtils.add(items, "剪贴板读取异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readLockScreenInfo(Context context, List<InfoRow> items) {
        try {
            KeyguardManager km =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            if (km == null) {
                CollectorUtils.add(items, "锁屏", "KeyguardManager 不可用");
                return;
            }
            boolean isSecure = km.isDeviceSecure();
            CollectorUtils.add(items, "是否设置锁屏密码",
                isSecure ? CollectorUtils.HIGH_RISK_PREFIX + "是（设备受保护）" : "否（无锁屏）");

            boolean isLocked = km.isKeyguardLocked();
            CollectorUtils.add(items, "当前是否锁屏", String.valueOf(isLocked));

            ContentResolver cr = context.getContentResolver();
            String timeout = Settings.System.getString(cr, Settings.System.SCREEN_OFF_TIMEOUT);
            if (timeout != null) {
                long ms = Long.parseLong(timeout);
                CollectorUtils.add(items, "屏幕自动锁定时间", formatDuration(ms));
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "锁屏状态读取失败", e.getMessage());
        }

        try {
            ContentResolver cr = context.getContentResolver();

            int adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, -1);
            if (adb == -1) adb = Settings.Secure.getInt(cr, "adb_enabled", 0);
            CollectorUtils.add(items, "ADB 调试",
                adb == 1 ? CollectorUtils.HIGH_RISK_PREFIX + "已开启（USB 可直接提取数据）" : "关闭");

            int dev = Settings.Global.getInt(cr,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1);
            if (dev == -1) {
                String devStr = Settings.Global.getString(cr, "development_settings_enabled");
                if (devStr == null)
                    devStr = Settings.Secure.getString(cr, "development_settings_enabled");
                dev = "1".equals(devStr) ? 1 : 0;
            }
            if (adb == 1) dev = 1;
            CollectorUtils.add(items, "开发者选项",
                dev == 1 ? CollectorUtils.HIGH_RISK_PREFIX + "已开启" : "关闭");

        } catch (Exception e) {
            CollectorUtils.add(items, "开发者/ADB 状态读取失败", e.getMessage());
        }
    }

    private void readAccounts(Context context, List<InfoRow> items) {
        boolean hasPermission = ContextCompat.checkSelfPermission(
            context, Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED;
        CollectorUtils.add(items, "GET_ACCOUNTS 权限", hasPermission ? "已授权" : "未授权");

        try {
            AccountManager am = AccountManager.get(context);
            Account[] accounts = hasPermission
                ? am.getAccounts()
                : am.getAccountsByType("com.google");

            if (accounts == null || accounts.length == 0) {
                CollectorUtils.add(items, "账户", "未获取到账户信息");
            } else {
                CollectorUtils.add(items, "账户总数", String.valueOf(accounts.length));
                for (Account acc : accounts) {
                    CollectorUtils.add(items, acc.name, CollectorUtils.HIGH_RISK_PREFIX + "类型: " + acc.type);
                }
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "账户读取异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readContacts(Context context, List<InfoRow> items) {
        try {
            Cursor cursor = context.getContentResolver().query(
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
                CollectorUtils.add(items, "联系人", "查询返回 null");
                return;
            }
            CollectorUtils.add(items, "联系人总数", String.valueOf(cursor.getCount()));
            int count = 0;
            while (cursor.moveToNext() && count++ < MAX_CONTACT_DISPLAY) {
                String name   = cursor.getString(0);
                String number = cursor.getString(1);
                CollectorUtils.add(items, name != null ? name : "(无名称)",
                    CollectorUtils.HIGH_RISK_PREFIX + (number != null ? number : "无号码"));
            }
            cursor.close();
        } catch (Exception e) {
            CollectorUtils.add(items, "联系人读取异常", e.getMessage());
        }
    }

    private void readCallLog(Context context, List<InfoRow> items) {
        try {
            Cursor cursor = context.getContentResolver().query(
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
                CollectorUtils.add(items, "通话记录", "查询返回 null");
                return;
            }
            CollectorUtils.add(items, "通话记录总数", String.valueOf(cursor.getCount()));
            SimpleDateFormat sdf = new SimpleDateFormat("MM-dd HH:mm", Locale.getDefault());
            int count = 0;
            while (cursor.moveToNext() && count++ < MAX_CALL_LOG_DISPLAY) {
                String name   = cursor.getString(0);
                String number = cursor.getString(1);
                int    type   = cursor.getInt(2);
                long   date   = cursor.getLong(3);
                long   dur    = cursor.getLong(4);
                String typeStr = type == CallLog.Calls.INCOMING_TYPE ? "接入" :
                                 type == CallLog.Calls.OUTGOING_TYPE ? "呼出" : "未接";
                String label = (name != null && !name.isEmpty()) ? name : number;
                CollectorUtils.add(items, label + " [" + typeStr + "]",
                    CollectorUtils.HIGH_RISK_PREFIX + sdf.format(new Date(date)) + " 时长:" + dur + "s");
            }
            cursor.close();
        } catch (Exception e) {
            CollectorUtils.add(items, "通话记录读取异常", e.getMessage());
        }
    }

    private void readPreferences(Context context, List<InfoRow> items) {
        try {
            ContentResolver cr = context.getContentResolver();
            CollectorUtils.add(items, "时区",     TimeZone.getDefault().getID());
            CollectorUtils.add(items, "系统语言", Locale.getDefault().toString());
            CollectorUtils.add(items, "字体缩放",
                Settings.System.getString(cr, Settings.System.FONT_SCALE));
            CollectorUtils.add(items, "屏幕亮度",
                Settings.System.getString(cr, Settings.System.SCREEN_BRIGHTNESS));
            String autoRotate = Settings.System.getString(
                cr, Settings.System.ACCELEROMETER_ROTATION);
            CollectorUtils.add(items, "自动旋转", "1".equals(autoRotate) ? "开启" : "关闭");

            String installUnknown;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                installUnknown = "请查看设置（Android 8+ 改为单应用授权）";
            } else {
                installUnknown = Settings.Secure.getInt(cr,
                    Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
                    ? CollectorUtils.HIGH_RISK_PREFIX + "已允许" : "不允许";
            }
            CollectorUtils.add(items, "安装未知来源 App", installUnknown);
        } catch (Exception e) {
            CollectorUtils.add(items, "偏好读取失败", e.getMessage());
        }
    }

    private String formatDuration(long ms) {
        long sec = ms / 1000;
        if (sec < 60) return sec + " 秒";
        long min = sec / 60;
        if (min < 60) return min + " 分钟";
        return (min / 60) + " 小时 " + (min % 60) + " 分钟";
    }

}
