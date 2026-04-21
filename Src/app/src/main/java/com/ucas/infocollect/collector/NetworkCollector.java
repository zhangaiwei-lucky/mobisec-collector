package com.ucas.infocollect.collector;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.telephony.TelephonyManager;
import android.text.format.Formatter;

import androidx.core.content.ContextCompat;

import com.ucas.infocollect.model.InfoRow;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * 网络信息收集器
 *
 * 无需权限（部分）：
 * - 网络连接类型（WiFi/移动数据/无网络）
 * - 所有网络接口 IP 地址
 * - /proc/net/arp 中的 ARP 缓存（局域网内其他设备 IP-MAC 映射）
 *
 * 需要权限：
 * - WiFi SSID / BSSID / 信号强度（ACCESS_WIFI_STATE + 位置权限）
 * - 周边 WiFi 热点扫描结果（同上）
 * - 移动数据详情（READ_PHONE_STATE）
 *
 * 安全价值：
 * - ARP 缓存泄露局域网拓扑，可辅助 MITM 攻击
 * - WiFi 历史可推断用户常去地点
 * - MAC 地址可用于网络层追踪（部分场景）
 */
public class NetworkCollector implements InfoCollector {

    @Override
    public List<InfoRow> collect(Context context) {
        List<InfoRow> items = new ArrayList<>();

        ConnectivityManager cm =
            (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

        // ── 当前网络状态（无需权限）──────────────────────────────
        CollectorUtils.addHeader(items, "当前网络状态");
        Network activeNetwork = cm.getActiveNetwork();
        if (activeNetwork != null) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps != null) {
                CollectorUtils.add(items, "有 WiFi",    String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)));
                CollectorUtils.add(items, "有移动数据", String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)));
                CollectorUtils.add(items, "有以太网",   String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)));
                CollectorUtils.add(items, "是否计费",   String.valueOf(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)));
            }
        } else {
            CollectorUtils.add(items, "网络状态", "无网络连接");
        }

        // ── 网络接口与 IP 地址（无需权限）──────────────────────
        CollectorUtils.addHeader(items, "网络接口 IP 地址");
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces != null) {
                for (NetworkInterface ni : Collections.list(interfaces)) {
                    if (!ni.isUp() || ni.isLoopback()) continue;
                    for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                        if (!addr.isLoopbackAddress()) {
                            CollectorUtils.add(items, ni.getName(), addr.getHostAddress());
                        }
                    }
                }
            }
        } catch (Exception e) {
            CollectorUtils.add(items, "IP 读取失败", e.getMessage());
        }

        // ── ARP 缓存（无需权限，揭示局域网设备）──────────────────
        CollectorUtils.addHeader(items, "ARP 缓存（局域网设备探测）");
        collectArpTable(items);

        // ── WiFi 详细信息（需权限）──────────────────────────────
        CollectorUtils.addHeader(items, "WiFi 连接信息");
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED) {
            WifiManager wm = (WifiManager) context.getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
            WifiInfo wi = wm.getConnectionInfo();
            if (wi != null) {
                CollectorUtils.add(items, "SSID",    CollectorUtils.HIGH_RISK_PREFIX + wi.getSSID());
                CollectorUtils.add(items, "BSSID",   CollectorUtils.HIGH_RISK_PREFIX + wi.getBSSID());  // 可定位 AP 位置
                CollectorUtils.add(items, "MAC 地址", wi.getMacAddress());
                CollectorUtils.add(items, "信号强度", wi.getRssi() + " dBm");
                CollectorUtils.add(items, "链接速度", wi.getLinkSpeed() + " Mbps");
                CollectorUtils.add(items, "IP 地址",
                    Formatter.formatIpAddress(wi.getIpAddress()));
                CollectorUtils.add(items, "网络 ID",  String.valueOf(wi.getNetworkId()));

                // DHCP 信息（网关 MAC = 路由器 MAC，可推断位置）
                DhcpInfo dhcp = wm.getDhcpInfo();
                CollectorUtils.add(items, "网关 IP",
                    Formatter.formatIpAddress(dhcp.gateway));
                CollectorUtils.add(items, "DNS1",
                    Formatter.formatIpAddress(dhcp.dns1));
                CollectorUtils.add(items, "DNS2",
                    Formatter.formatIpAddress(dhcp.dns2));
            }

            // 周边 WiFi 扫描（可用于 WiFi 定位，精度约 15m）
            CollectorUtils.addHeader(items, "周边 WiFi 热点（WiFi 定位）");
            List<ScanResult> scanResults = wm.getScanResults();
            if (scanResults != null) {
                for (ScanResult sr : scanResults) {
                    CollectorUtils.add(items, sr.SSID,
                        CollectorUtils.HIGH_RISK_PREFIX + "BSSID:" + sr.BSSID + " 信号:" + sr.level + "dBm");
                }
            }
        } else {
            CollectorUtils.add(items, "WiFi 详情", "需要位置权限（ACCESS_FINE_LOCATION）");
        }

        // ── /proc/net 路由表（无需权限）──────────────────────────
        CollectorUtils.addHeader(items, "路由表（/proc/net/route）");
        readProcNetRoute(items);

        return items;
    }

    /**
     * 读取 ARP 缓存 - 揭示局域网内所有通信过的设备 IP 和 MAC
     * 攻击价值：构建局域网拓扑，辅助 ARP 欺骗 / MITM
     */
    private void collectArpTable(List<InfoRow> items) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            br.readLine(); // 跳过表头
            while ((line = br.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 4) {
                    String ip  = parts[0];
                    String mac = parts[3];
                    String iface = parts.length >= 6 ? parts[5] : "?";
                    if (!mac.equals("00:00:00:00:00:00")) {
                        CollectorUtils.add(items, ip + " [" + iface + "]",
                            CollectorUtils.HIGH_RISK_PREFIX + "MAC: " + mac);
                    }
                }
            }
        } catch (IOException e) {
            CollectorUtils.add(items, "ARP 读取", "失败: " + e.getMessage());
        }
    }

    /** 读取内核路由表 */
    private void readProcNetRoute(List<InfoRow> items) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/route"))) {
            String line;
            br.readLine(); // 跳过表头
            while ((line = br.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 3) {
                    CollectorUtils.add(items, "接口: " + parts[0],
                        "目标: " + hexToIp(parts[1]) + " 网关: " + hexToIp(parts[2]));
                }
            }
        } catch (IOException e) {
            CollectorUtils.add(items, "路由表读取", "失败: " + e.getMessage());
        }
    }

    /** 将小端十六进制 IP 转为点分十进制 */
    private String hexToIp(String hex) {
        try {
            long val = Long.parseLong(hex, 16);
            return String.format("%d.%d.%d.%d",
                val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF);
        } catch (Exception e) {
            return hex;
        }
    }

}
