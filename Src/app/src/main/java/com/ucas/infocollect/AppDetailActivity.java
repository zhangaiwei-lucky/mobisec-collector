package com.ucas.infocollect;

import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.view.MenuItem;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ucas.infocollect.adapter.InfoAdapter;
import com.ucas.infocollect.model.InfoRow;
import com.ucas.infocollect.model.RiskLevel;

import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 应用详情页——展示单个应用的安全画像：
 * - 基本信息（UID、安装来源、targetSdk、签名证书 SHA-256）
 * - 危险权限 / 普通权限（已授予 vs 仅声明）
 * - 导出组件（Attack Surface）
 * - Intent Filter / Deep Link（外部可唤起的入口）
 */
public class AppDetailActivity extends AppCompatActivity {

    public static final String EXTRA_PACKAGE = "package_name";

    private InfoAdapter adapter;
    private ImageView iconView;
    private TextView nameView, packageView, versionView;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_detail);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("应用详情");
        }

        iconView    = findViewById(R.id.detail_icon);
        nameView    = findViewById(R.id.detail_name);
        packageView = findViewById(R.id.detail_package);
        versionView = findViewById(R.id.detail_version);

        RecyclerView rv = findViewById(R.id.recycler_view);
        rv.setLayoutManager(new LinearLayoutManager(this));
        adapter = new InfoAdapter(new ArrayList<>());
        rv.setAdapter(adapter);

        String packageName = getIntent().getStringExtra(EXTRA_PACKAGE);
        if (packageName != null) loadAppDetail(packageName);
    }

    private void loadAppDetail(String packageName) {
        executor.submit(() -> {
            PackageManager pm = getPackageManager();
            Drawable icon;
            String label, version;
            try {
                ApplicationInfo ai = pm.getApplicationInfo(packageName, 0);
                icon  = pm.getApplicationIcon(ai);
                label = pm.getApplicationLabel(ai).toString();
                PackageInfo pi0 = pm.getPackageInfo(packageName, 0);
                version = "v" + (pi0.versionName != null ? pi0.versionName : "?")
                    + "  (code " + pi0.versionCode + ")";
            } catch (Exception e) {
                icon    = null;
                label   = packageName;
                version = "";
            }
            List<InfoRow> rows = buildDetailRows(packageName);
            final Drawable finalIcon    = icon;
            final String   finalLabel   = label;
            final String   finalVersion = version;
            runOnUiThread(() -> {
                if (finalIcon != null) iconView.setImageDrawable(finalIcon);
                else iconView.setImageResource(android.R.drawable.sym_def_app_icon);
                nameView.setText(finalLabel);
                packageView.setText(packageName);
                versionView.setText(finalVersion);
                if (getSupportActionBar() != null)
                    getSupportActionBar().setTitle(finalLabel);
                adapter.updateData(rows);
            });
        });
    }

    // ─────────────────────────────────────────────────────────────
    // 构建详情数据
    // ─────────────────────────────────────────────────────────────

    private List<InfoRow> buildDetailRows(String packageName) {
        List<InfoRow> items = new ArrayList<>();
        PackageManager pm = getPackageManager();

        try {
            // 一次性获取权限 + 组件
            int flags = PackageManager.GET_PERMISSIONS
                | PackageManager.GET_ACTIVITIES
                | PackageManager.GET_SERVICES
                | PackageManager.GET_RECEIVERS
                | PackageManager.GET_PROVIDERS;
            PackageInfo pi = pm.getPackageInfo(packageName, flags);
            ApplicationInfo ai = pi.applicationInfo;

            // ── 基本信息 ────────────────────────────────────────────
            addHeader(items, "应用基本信息");
            add(items, "应用名称", pm.getApplicationLabel(ai).toString());
            add(items, "包名",    packageName);
            add(items, "版本",
                (pi.versionName != null ? pi.versionName : "?") + " (code:" + pi.versionCode + ")");

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
            add(items, "首次安装", sdf.format(new Date(pi.firstInstallTime)));
            add(items, "最后更新", sdf.format(new Date(pi.lastUpdateTime)));

            boolean isSys = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            add(items, "类型", isSys ? "系统应用" : "用户应用");
            add(items, "UID", "uid=" + ai.uid
                + "（每个应用独立 uid，沙箱隔离基础）");
            add(items, "targetSdkVersion", String.valueOf(ai.targetSdkVersion)
                + (ai.targetSdkVersion < 29 ? " ⚠低于 Android 10，享有旧兼容行为" : ""));
            add(items, "minSdkVersion",    String.valueOf(ai.minSdkVersion));
            add(items, "数据目录", ai.dataDir
                + "\n（其他应用无法直接读取，体现 Android 沙箱隔离）");
            add(items, "APK 路径", ai.sourceDir);

            // 安装来源
            String installer = "未知";
            try {
                installer = pm.getInstallerPackageName(packageName);
                if (installer == null) installer = "未知（可能为 adb/系统）;
            } catch (Exception ignored) {}
            RiskLevel instRisk = installer.contains("unknown") || installer.equals("未知（可能为 adb/系统）")
                ? RiskLevel.HIGH : RiskLevel.NORMAL;
            if (instRisk == RiskLevel.HIGH) {
                addHighRisk(items, "安装来源", installer + " —非正规市场安装风险较高");
            } else {
                add(items, "安装来源", installer);
            }

            // 明文 HTTP
            boolean cleartext = (ai.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0;
            if (cleartext) addHighRisk(items, "明文 HTTP", "允许（MITM 风险）");
            else           add(items, "明文 HTTP", "不允许（强制 HTTPS）");

            // 签名证书 SHA-256
            addHeader(items, "签名证书");
            addSigningInfo(pm, packageName, items);

            // ── 权限详情 ─────────────────────────────────────────────
            String[] requestedPerms = pi.requestedPermissions;
            int[]    permFlags      = pi.requestedPermissionsFlags;

            if (requestedPerms != null && requestedPerms.length > 0) {
                List<int[]> dangIdx  = new ArrayList<>(); // {index, granted, protLevel}
                List<int[]> otherIdx = new ArrayList<>();

                for (int i = 0; i < requestedPerms.length; i++) {
                    boolean granted = permFlags != null && i < permFlags.length
                        && (permFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                    int protLevel = PermissionInfo.PROTECTION_NORMAL;
                    try {
                        PermissionInfo pi2 = pm.getPermissionInfo(requestedPerms[i], 0);
                        protLevel = pi2.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE;
                    } catch (Exception ignored) {}
                    int[] entry = {i, granted ? 1 : 0, protLevel};
                    if (protLevel == PermissionInfo.PROTECTION_DANGEROUS) dangIdx.add(entry);
                    else otherIdx.add(entry);
                }

                // 危险权限：授予的在前
                dangIdx.sort((a, b) -> b[1] - a[1]);
                addHeader(items,
                    "危险权限： + dangIdx.size() + " 项声明
                    + " / " + dangIdx.stream().mapToInt(e -> e[1]).sum() + " 项已授予）");
                for (int[] e : dangIdx) {
                    String perm    = requestedPerms[e[0]];
                    boolean granted = e[1] == 1;
                    String shortName = permShortName(perm);
                    String status    = granted ? "✓ 已授予" : "✗ 未授予";
                    if (granted) {
                        addHighRisk(items, shortName + "\n" + perm, status + " | 危险");
                    } else {
                        add(items, shortName + "\n" + perm, status + " | 危险");
                    }
                }

                addHeader(items,
                    "其他权限： + otherIdx.size() + " 项）");
                for (int[] e : otherIdx) {
                    String perm     = requestedPerms[e[0]];
                    boolean granted = e[1] == 1;
                    String shortName = permShortName(perm);
                    String level     = protectionLevelLabel(e[2]);
                    add(items, shortName + "\n" + perm,
                        (granted ? "✓ 已授予" : "✗ 未授予") + " | " + level);
                }
            } else {
                addHeader(items, "权限");
                add(items, "无权限声明", "该应用未声明任何权限");
            }

            // ── 组件概览 ─────────────────────────────────────────────
            int actCount = pi.activities != null ? pi.activities.length : 0;
            int svcCount = pi.services   != null ? pi.services.length   : 0;
            int recCount = pi.receivers  != null ? pi.receivers.length   : 0;
            int prvCount = pi.providers  != null ? pi.providers.length   : 0;

            addHeader(items, "组件概览");
            add(items, "Activity",         String.valueOf(actCount));
            add(items, "Service",          String.valueOf(svcCount));
            add(items, "BroadcastReceiver",String.valueOf(recCount));
            add(items, "ContentProvider",  String.valueOf(prvCount));

            // ── 导出组件（攻击面）────────────────────────────────────
            addHeader(items, "导出组件（对外暴露的攻击面）");
            int expAct = 0; List<ActivityInfo> expActivities = new ArrayList<>();
            if (pi.activities != null) for (ActivityInfo a : pi.activities) {
                if (a.exported) { expAct++; expActivities.add(a); }
            }
            int expSvc = 0;
            if (pi.services   != null) for (ServiceInfo  s : pi.services)   if (s.exported) expSvc++;
            int expRec = 0;
            if (pi.receivers  != null) for (ActivityInfo r : pi.receivers)   if (r.exported) expRec++;
            int expPrv = 0; List<ProviderInfo> expProviders = new ArrayList<>();
            if (pi.providers  != null) for (ProviderInfo p : pi.providers) {
                if (p.exported) { expPrv++; expProviders.add(p); }
            }

            addExportedRow(items, "导出 Activity",         expAct);
            addExportedRow(items, "导出 Service",          expSvc);
            addExportedRow(items, "导出 Receiver",         expRec);
            addExportedRow(items, "导出 ContentProvider",  expPrv);

            // ── Intent Scheme / Deep Link ────────────────────────────
            if (!expActivities.isEmpty()) {
                addHeader(items, "Intent Scheme / Deep Link 分析");
                add(items, "说明",
                    "Exported Activity 是 Intent Scheme URL 攻击的直接入口。\n"
                    + "BROWSABLE + 无权限保护 = 可被任意网页或 App 唤起。");
                int deepLinkCount = 0;
                for (ActivityInfo a : expActivities) {
                    boolean noPermission = (a.permission == null);
                    String shortName = a.name.contains(".")
                        ? a.name.substring(a.name.lastIndexOf('.') + 1) : a.name;
                    String detail = (noPermission ? "⚠ 无权限保护" : "有权限: " + a.permission);
                    if (noPermission) {
                        addHighRisk(items, "Exported Activity: " + shortName,
                            detail + "\n完整名: " + a.name);
                        deepLinkCount++;
                    } else {
                        add(items, "Exported Activity: " + shortName,
                            detail + "\n完整名: " + a.name);
                    }
                }
                if (deepLinkCount == 0) {
                    add(items, "深链风险", "所有导出 Activity 均有权限保护");
                }
            }

            // ── ContentProvider 详情 ─────────────────────────────────
            if (!expProviders.isEmpty()) {
                addHeader(items, "ContentProvider 详情（路径遍历攻击面初筛）");
                add(items, "说明",
                    "Exported + 无读写权限保护 = 路径遍历攻击面（初筛）。\n"
                    + "注意：是否实际可利用还需验证 openFile() 实现。");
                for (ProviderInfo p : expProviders) {
                    boolean noRead  = p.readPermission  == null;
                    boolean noWrite = p.writePermission == null;
                    String risk = (noRead && noWrite)
                        ? "⚠ 读写均无权限保护（路径遍历攻击面）
                        : "读权限: " + (p.readPermission != null ? p.readPermission : "无")
                        + " 写权限: " + (p.writePermission != null ? p.writePermission : "无");
                    if (noRead && noWrite) {
                        addHighRisk(items, p.authority, risk);
                    } else {
                        add(items, p.authority, risk);
                    }
                }
            }

        } catch (PackageManager.NameNotFoundException e) {
            add(items, "错误", "找不到应用 " + packageName);
        } catch (Exception e) {
            add(items, "错误", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return items;
    }

    private void addSigningInfo(PackageManager pm, String packageName, List<InfoRow> items) {
        try {
            Signature[] sigs = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo piSig = pm.getPackageInfo(packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES);
                if (piSig.signingInfo != null) {
                    sigs = piSig.signingInfo.getApkContentsSigners();
                }
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo piSig = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                sigs = piSig.signatures;
            }
            if (sigs != null && sigs.length > 0) {
                String sha256 = certSha256(sigs[0]);
                add(items, "证书数量", String.valueOf(sigs.length));
                add(items, "签名 SHA-256",
                    sha256 + "\n（可用于识别重打包应用）");
                add(items, "说明",
                    "相同签名证书的应用可共享数据（android:sharedUserId）。\n"
                    + "Janus(CVE-2017-13156) 攻击利用 V1-only 签名漏洞附加恶意 DEX。");
            } else {
                add(items, "签名", "无法读取");
            }
        } catch (Exception e) {
            add(items, "签名读取失败", e.getClass().getSimpleName());
        }
    }

    private String certSha256(Signature sig) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sig.toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02X", b));
            // 每 8 字节插入空格方便阅读
            String hex = sb.toString();
            StringBuilder formatted = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 8) {
                if (i > 0) formatted.append(' ');
                formatted.append(hex, i, Math.min(i + 8, hex.length()));
            }
            return formatted.toString();
        } catch (Exception e) {
            return "SHA-256 计算失败";
        }
    }

    private void addExportedRow(List<InfoRow> items, String label, int count) {
        if (count > 0) addHighRisk(items, label, count + " 个");
        else           add(items, label, "无");
    }

    // ─────────────────────────────────────────────────────────────
    // 工具方法
    // ─────────────────────────────────────────────────────────────

    private String protectionLevelLabel(int level) {
        switch (level & PermissionInfo.PROTECTION_MASK_BASE) {
            case PermissionInfo.PROTECTION_NORMAL:    return "普通;
            case PermissionInfo.PROTECTION_DANGEROUS: return "危险";
            case PermissionInfo.PROTECTION_SIGNATURE: return "签名";
            default:                                  return "系统";
        }
    }

    private String permShortName(String perm) {
        String s = perm.contains(".") ? perm.substring(perm.lastIndexOf('.') + 1) : perm;
        switch (s) {
            case "READ_CONTACTS":                    return "读取联系人;
            case "WRITE_CONTACTS":                   return "修改联系人;
            case "READ_CALL_LOG":                    return "读取通话记录";
            case "WRITE_CALL_LOG":                   return "修改通话记录";
            case "READ_SMS":                         return "读取短信";
            case "SEND_SMS":                         return "发送短信;
            case "RECEIVE_SMS":                      return "接收短信";
            case "CAMERA":                           return "使用相机";
            case "RECORD_AUDIO":                     return "录音麦克风;
            case "ACCESS_FINE_LOCATION":             return "精确定位 (GPS)";
            case "ACCESS_COARSE_LOCATION":           return "粗略定位 (基站)";
            case "READ_EXTERNAL_STORAGE":            return "读取外部存储";
            case "WRITE_EXTERNAL_STORAGE":           return "写入外部存储";
            case "READ_PHONE_STATE":                 return "读取手机状态/IMEI";
            case "PROCESS_OUTGOING_CALLS":           return "处理外拨电话";
            case "SYSTEM_ALERT_WINDOW":              return "悬浮窗显示;
            case "BIND_ACCESSIBILITY_SERVICE":       return "无障碍服务;
            case "BIND_DEVICE_ADMIN":                return "设备管理员;
            case "BIND_NOTIFICATION_LISTENER_SERVICE": return "通知监听";
            case "READ_MEDIA_IMAGES":                return "读取图片";
            case "READ_MEDIA_VIDEO":                 return "读取视频";
            case "READ_MEDIA_AUDIO":                 return "读取音频";
            case "INTERNET":                         return "访问网络";
            case "VIBRATE":                          return "振动马达";
            case "WAKE_LOCK":                        return "保持 CPU 唤醒";
            case "RECEIVE_BOOT_COMPLETED":           return "开机自启;
            case "GET_ACCOUNTS":                     return "获取账户信息";
            case "QUERY_ALL_PACKAGES":               return "枚举已安装应用;
            case "PACKAGE_USAGE_STATS":              return "应用使用统计";
            case "REQUEST_INSTALL_PACKAGES":         return "安装其他应用";
            case "FOREGROUND_SERVICE":               return "前台服务";
            case "ACCESS_NETWORK_STATE":             return "查看网络状态;
            case "ACCESS_WIFI_STATE":                return "查看 WiFi 状态;
            case "CHANGE_WIFI_STATE":                return "修改 WiFi 状态;
            case "BLUETOOTH":                        return "蓝牙";
            case "BLUETOOTH_ADMIN":                  return "蓝牙管理";
            case "NFC":                              return "NFC 近场通信";
            case "USE_BIOMETRIC":                    return "生物识别";
            case "USE_FINGERPRINT":                  return "指纹识别";
            case "CHANGE_NETWORK_STATE":             return "修改网络状态;
            default:                                 return s;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 本地 InfoRow 构建辅助（原 CollectorUtils 静态方法内联）
    // ─────────────────────────────────────────────────────────────

    private static void add(
            final List<InfoRow> list, final String key, final String value) {
        list.add(InfoRow.item(key, value != null ? value : "N/A", RiskLevel.NORMAL));
    }

    private static void addHighRisk(
            final List<InfoRow> list, final String key, final String value) {
        list.add(InfoRow.item(key, value != null ? value : "N/A", RiskLevel.HIGH));
    }

    private static void addHeader(final List<InfoRow> list, final String title) {
        list.add(InfoRow.header(title != null ? title : ""));
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}
