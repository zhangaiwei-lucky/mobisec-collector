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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

/**
 * 用户数据收集器
 *
 * 注意：本 Fragment 通过 BaseInfoFragment 的后台线程加载，
 * 且只在用户切换到"用户"标签时才初始化，确保 App 持有焦点（剪贴板读取需要）。
 */
public class UserDataCollector {

    private final Context context;

    public UserDataCollector(Context context) {
        this.context = context;
    }

    public List<Map.Entry<String, String>> collect() {
        List<Map.Entry<String, String>> items = new ArrayList<>();

        // ── 剪贴板（需要焦点窗口，Android 10+）──────────────────
        CollectorUtils.addHeader(items, "剪贴板内容（需 App 处于前台焦点）");
        readClipboard(items);

        // ── 锁屏安全状态（KeyguardManager，无需权限）──────────────
        CollectorUtils.addHeader(items, "锁屏安全状态");
        readLockScreenInfo(items);

        // ── 系统账户（GET_ACCOUNTS）──────────────────────────────
        CollectorUtils.addHeader(items, "设备关联账户");
        readAccounts(items);

        // ── 联系人（READ_CONTACTS）──────────────────────────────
        CollectorUtils.addHeader(items, "联系人（前10条）");
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS)
                == PackageManager.PERMISSION_GRANTED) {
            readContacts(items);
        } else {
            CollectorUtils.add(items, "状态", "未授予 READ_CONTACTS 权限");
        }

        // ── 通话记录（READ_CALL_LOG）────────────────────────────
        CollectorUtils.addHeader(items, "通话记录（前10条）");
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALL_LOG)
                == PackageManager.PERMISSION_GRANTED) {
            readCallLog(items);
        } else {
            CollectorUtils.add(items, "状态", "未授予 READ_CALL_LOG 权限");
        }

        // ── 用户偏好（无需权限）──────────────────────────────────
        CollectorUtils.addHeader(items, "用户偏好与设备习惯");
        readPreferences(items);

        return items;
    }

    // ─────────────────────────────────────────────────────────────

    private void readClipboard(List<Map.Entry<String, String>> items) {
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
                CollectorUtils.add(items, "剪贴板文本", "[HIGH]" + text);
            } else if (item.getUri() != null) {
                CollectorUtils.add(items, "剪贴板 URI", "[HIGH]" + item.getUri().toString());
            } else {
                CollectorUtils.add(items, "剪贴板", "含内容但非文本/URI 类型");
            }
            CollectorUtils.add(items, "剪贴板 MIME 类型",
                clip.getDescription().getMimeType(0));
        } catch (SecurityException e) {
            // Android 10+ 后台读取剪贴板会抛 SecurityException
            CollectorUtils.add(items, "剪贴板", "Android 10+ 限制：需在前台焦点状态读取\n请点击「刷新」按钮重试");
        } catch (Exception e) {
            CollectorUtils.add(items, "剪贴板读取异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readLockScreenInfo(List<Map.Entry<String, String>> items) {
        try {
            KeyguardManager km =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            if (km == null) {
                CollectorUtils.add(items, "锁屏", "KeyguardManager 不可用");
                return;
            }
            // isDeviceSecure：是否设置了 PIN/图案/密码（API 23+）
            boolean isSecure = km.isDeviceSecure();
            CollectorUtils.add(items, "是否设置锁屏密码", isSecure ? "[HIGH]是（设备受保护）" : "否（无锁屏）");

            // isKeyguardLocked：当前是否处于锁屏状态
            boolean isLocked = km.isKeyguardLocked();
            CollectorUtils.add(items, "当前是否锁屏", String.valueOf(isLocked));

            // 尝试读取屏幕超时时间（间接判断安全习惯）
            ContentResolver cr = context.getContentResolver();
            String timeout = Settings.System.getString(cr, Settings.System.SCREEN_OFF_TIMEOUT);
            if (timeout != null) {
                long ms = Long.parseLong(timeout);
                CollectorUtils.add(items, "屏幕自动锁定时间", formatDuration(ms));
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "锁屏状态读取失败", e.getMessage());
        }

        // 开发者选项和 ADB 状态（多重读取，适配不同 ROM）
        try {
            ContentResolver cr = context.getContentResolver();

            // ADB 调试状态（Settings.Global，通用）
            int adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, -1);
            if (adb == -1) adb = Settings.Secure.getInt(cr, "adb_enabled", 0);
            CollectorUtils.add(items, "ADB 调试",
                adb == 1 ? "[HIGH]已开启（USB 可直接提取数据）" : "关闭");

            // 开发者选项：先读 Global，MIUI/ColorOS 等 ROM 可能存在 Secure 里
            int dev = Settings.Global.getInt(cr,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1);
            if (dev == -1) {
                // fallback：部分 ROM 的 key 不同
                String devStr = Settings.Global.getString(cr, "development_settings_enabled");
                if (devStr == null)
                    devStr = Settings.Secure.getString(cr, "development_settings_enabled");
                dev = "1".equals(devStr) ? 1 : 0;
            }
            // 如果 ADB 已开，开发者模式必然开启
            if (adb == 1) dev = 1;
            CollectorUtils.add(items, "开发者选项",
                dev == 1 ? "[HIGH]已开启" : "关闭");

        } catch (Exception e) {
            CollectorUtils.add(items, "开发者/ADB 状态读取失败", e.getMessage());
        }
    }

    private void readAccounts(List<Map.Entry<String, String>> items) {
        // 尝试有权限和无权限两种路径
        boolean hasPermission = ContextCompat.checkSelfPermission(
            context, Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED;
        CollectorUtils.add(items, "GET_ACCOUNTS 权限", hasPermission ? "已授权" : "未授权");

        try {
            AccountManager am = AccountManager.get(context);
            Account[] accounts = hasPermission
                ? am.getAccounts()
                : am.getAccountsByType("com.google");  // 部分账户类型无需权限

            if (accounts == null || accounts.length == 0) {
                CollectorUtils.add(items, "账户", "未获取到账户信息");
            } else {
                CollectorUtils.add(items, "账户总数", String.valueOf(accounts.length));
                for (Account acc : accounts) {
                    CollectorUtils.add(items, acc.name, "[HIGH]类型: " + acc.type);
                }
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "账户读取异常", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readContacts(List<Map.Entry<String, String>> items) {
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
            while (cursor.moveToNext() && count++ < 10) {
                String name   = cursor.getString(0);
                String number = cursor.getString(1);
                CollectorUtils.add(items, name != null ? name : "(无名称)",
                    "[HIGH]" + (number != null ? number : "无号码"));
            }
            cursor.close();
        } catch (Exception e) {
            CollectorUtils.add(items, "联系人读取异常", e.getMessage());
        }
    }

    private void readCallLog(List<Map.Entry<String, String>> items) {
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
            while (cursor.moveToNext() && count++ < 10) {
                String name   = cursor.getString(0);
                String number = cursor.getString(1);
                int    type   = cursor.getInt(2);
                long   date   = cursor.getLong(3);
                long   dur    = cursor.getLong(4);
                String typeStr = type == CallLog.Calls.INCOMING_TYPE ? "接入" :
                                 type == CallLog.Calls.OUTGOING_TYPE ? "呼出" : "未接";
                String label = (name != null && !name.isEmpty()) ? name : number;
                CollectorUtils.add(items, label + " [" + typeStr + "]",
                    "[HIGH]" + sdf.format(new Date(date)) + " 时长:" + dur + "s");
            }
            cursor.close();
        } catch (Exception e) {
            CollectorUtils.add(items, "通话记录读取异常", e.getMessage());
        }
    }

    private void readPreferences(List<Map.Entry<String, String>> items) {
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

            // 安装未知来源
            String installUnknown;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                installUnknown = "请查看设置（Android 8+ 改为单应用授权）";
            } else {
                installUnknown = Settings.Secure.getInt(cr,
                    Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
                    ? "[HIGH]已允许" : "不允许";
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
