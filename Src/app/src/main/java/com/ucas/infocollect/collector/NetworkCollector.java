package com.ucas.infocollect.collector;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
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

        // ── 当前网络状态（无需权限）──────────────────────────────
        CollectorUtils.addHeader(items, "当前网络状态");
        collectCurrentNetwork(context, items);

        // ── 网络接口与 IP 地址（无需权限）──────────────────────
        CollectorUtils.addHeader(items, "网络接口 IP 地址");
        collectNetworkInterfaces(items);

        // ── ARP 缓存（无需权限，揭示局域网设备）──────────────────
        CollectorUtils.addHeader(items, "ARP 缓存（局域网设备探测）");
        collectArpTable(items);

        // ── WiFi 详细信息（需权限）──────────────────────────────
        CollectorUtils.addHeader(items, "WiFi 连接信息");
        collectWifiInfo(context, items);

        // ── /proc/net 路由表（无需权限）──────────────────────────
        CollectorUtils.addHeader(items, "路由表（/proc/net/route）");
        readProcNetRoute(items);

        // ── 网络安全环境（DNS / 代理 / VPN）──────────────────────
        CollectorUtils.addHeader(items, "网络安全环境（DNS / 代理 / VPN）");
        collectNetworkSecurityEnv(context, items);

        return items;
    }

    private void collectCurrentNetwork(Context context, List<InfoRow> items) {
        try {
            ConnectivityManager cm = CollectorUtils.safeService(
                    context,
                    Context.CONNECTIVITY_SERVICE,
                    ConnectivityManager.class,
                    items,
                    "当前网络状态",
                    "ConnectivityManager 不可用");
            if (cm == null) return;

            Network activeNetwork = cm.getActiveNetwork();
            if (activeNetwork == null) {
                CollectorUtils.addDegrade(items, "网络状态",
                        CollectorUtils.DegradeReason.NO_DATA, "当前无活动网络");
                return;
            }

            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps == null) {
                CollectorUtils.addDegrade(items, "网络能力",
                        CollectorUtils.DegradeReason.SYSTEM_RESTRICTED, "系统未返回 NetworkCapabilities");
                return;
            }
            CollectorUtils.safeAdd(items, "有 WiFi",
                    String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)));
            CollectorUtils.safeAdd(items, "有移动数据",
                    String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)));
            CollectorUtils.safeAdd(items, "有以太网",
                    String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)));
            CollectorUtils.safeAdd(items, "是否计费",
                    String.valueOf(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)));
        } catch (Exception e) {
            CollectorUtils.addDegrade(items, "当前网络状态",
                    CollectorUtils.DegradeReason.READ_FAILED, "读取网络状态失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectNetworkInterfaces(List<InfoRow> items) {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) {
                CollectorUtils.addDegrade(items, "网络接口",
                        CollectorUtils.DegradeReason.NO_DATA, "系统未返回网络接口列表");
                return;
            }
            boolean hasData = false;
            for (NetworkInterface ni : Collections.list(interfaces)) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (!addr.isLoopbackAddress()) {
                        hasData = true;
                        CollectorUtils.safeAdd(items, ni.getName(), addr.getHostAddress());
                    }
                }
            }
            if (!hasData) {
                CollectorUtils.addDegrade(items, "网络接口",
                        CollectorUtils.DegradeReason.NO_DATA, "未发现可用 IP 地址");
            }
        } catch (Exception e) {
            CollectorUtils.addDegrade(items, "网络接口",
                    CollectorUtils.DegradeReason.READ_FAILED, "IP 读取异常: " + e.getClass().getSimpleName());
        }
    }

    private void collectWifiInfo(Context context, List<InfoRow> items) {
        // Android 上系统服务和子对象返回 null 是常见现象：权限缺失、WiFi 关闭、厂商 ROM 限制均可能触发。
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            CollectorUtils.addDegrade(items, "WiFi 详情",
                    CollectorUtils.DegradeReason.PERMISSION_DENIED, "缺少 ACCESS_FINE_LOCATION 权限");
            return;
        }
        try {
            WifiManager wm = CollectorUtils.safeService(
                    context.getApplicationContext(),
                    Context.WIFI_SERVICE,
                    WifiManager.class,
                    items,
                    "WiFi 服务",
                    "WifiManager 不可用");
            if (wm == null) return;
            collectWifiConnectionInfo(wm, items);
            collectWifiScanInfo(wm, items);
        } catch (SecurityException e) {
            CollectorUtils.addDegrade(items, "WiFi 详情",
                    CollectorUtils.DegradeReason.SYSTEM_RESTRICTED, "系统限制 WiFi 数据访问");
        } catch (Exception e) {
            CollectorUtils.addDegrade(items, "WiFi 详情",
                    CollectorUtils.DegradeReason.READ_FAILED, "读取 WiFi 信息失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectWifiConnectionInfo(WifiManager wm, List<InfoRow> items) {
        try {
            WifiInfo wi = wm.getConnectionInfo();
            if (wi == null) {
                CollectorUtils.addDegrade(items, "WiFi 连接",
                        CollectorUtils.DegradeReason.NO_DATA, "WiFi 未连接或系统未返回连接信息");
            } else {
                CollectorUtils.addHighRisk(items, "SSID", wi.getSSID());
                CollectorUtils.addHighRisk(items, "BSSID", wi.getBSSID());
                CollectorUtils.safeAdd(items, "MAC 地址", wi.getMacAddress(), "系统已隐藏");
                CollectorUtils.safeAdd(items, "信号强度", wi.getRssi() + " dBm");
                CollectorUtils.safeAdd(items, "链接速度", wi.getLinkSpeed() + " Mbps");
                CollectorUtils.safeAdd(items, "IP 地址", Formatter.formatIpAddress(wi.getIpAddress()));
                CollectorUtils.safeAdd(items, "网络 ID", String.valueOf(wi.getNetworkId()));
            }

            DhcpInfo dhcp = wm.getDhcpInfo();
            if (dhcp == null) {
                CollectorUtils.addDegrade(items, "DHCP 信息",
                        CollectorUtils.DegradeReason.NO_DATA, "WiFi 未就绪或 ROM 未暴露 DHCP 数据");
            } else {
                CollectorUtils.safeAdd(items, "网关 IP", Formatter.formatIpAddress(dhcp.gateway));
                CollectorUtils.safeAdd(items, "DNS1", Formatter.formatIpAddress(dhcp.dns1));
                CollectorUtils.safeAdd(items, "DNS2", Formatter.formatIpAddress(dhcp.dns2));
            }
        } catch (SecurityException e) {
            CollectorUtils.addDegrade(items, "WiFi 连接",
                    CollectorUtils.DegradeReason.SYSTEM_RESTRICTED, "系统限制读取连接态信息");
        } catch (Exception e) {
            CollectorUtils.addDegrade(items, "WiFi 连接",
                    CollectorUtils.DegradeReason.READ_FAILED, "读取连接态失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectWifiScanInfo(WifiManager wm, List<InfoRow> items) {
        CollectorUtils.addHeader(items, "周边 WiFi 热点（WiFi 定位）");
        try {
            List<ScanResult> scanResults = wm.getScanResults();
            if (scanResults == null || scanResults.isEmpty()) {
                CollectorUtils.addDegrade(items, "热点扫描",
                        CollectorUtils.DegradeReason.NO_DATA, "未扫描到热点或系统限制返回结果");
                return;
            }
            for (ScanResult sr : scanResults) {
                String ssid = sr != null && sr.SSID != null && !sr.SSID.isEmpty() ? sr.SSID : "(隐藏 SSID)";
                String bssid = sr != null ? sr.BSSID : null;
                int level = sr != null ? sr.level : 0;
                CollectorUtils.addHighRisk(items, ssid, "BSSID:" + (bssid != null ? bssid : "N/A") + " 信号:" + level + "dBm");
            }
        } catch (SecurityException e) {
            CollectorUtils.addDegrade(items, "热点扫描",
                    CollectorUtils.DegradeReason.SYSTEM_RESTRICTED, "系统限制热点扫描结果访问");
        } catch (Exception e) {
            CollectorUtils.addDegrade(items, "热点扫描",
                    CollectorUtils.DegradeReason.READ_FAILED, "读取扫描结果失败: " + e.getClass().getSimpleName());
        }
    }

    /**
     * 读取 ARP 缓存 - 揭示局域网内所有通信过的设备 IP 和 MAC
     * 攻击价值：构建局域网拓扑，辅助 ARP 欺骗 / MITM
     */
    private void collectArpTable(List<InfoRow> items) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            br.readLine(); // 跳过表头
            boolean hasData = false;
            while ((line = br.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 4) {
                    String ip  = parts[0];
                    String mac = parts[3];
                    String iface = parts.length >= 6 ? parts[5] : "?";
                    if (!mac.equals("00:00:00:00:00:00")) {
                        hasData = true;
                        CollectorUtils.addHighRisk(items, ip + " [" + iface + "]", "MAC: " + mac);
                    }
                }
            }
            if (!hasData) {
                CollectorUtils.addDegrade(items, "ARP 缓存",
                        CollectorUtils.DegradeReason.NO_DATA, "未发现可用 ARP 记录");
            }
        } catch (IOException e) {
            CollectorUtils.addDegrade(items, "ARP 读取",
                    CollectorUtils.DegradeReason.READ_FAILED, "读取失败: " + e.getClass().getSimpleName());
        }
    }

    /** 读取内核路由表 */
    private void readProcNetRoute(List<InfoRow> items) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/route"))) {
            String line;
            br.readLine(); // 跳过表头
            boolean hasData = false;
            while ((line = br.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 3) {
                    hasData = true;
                    CollectorUtils.safeAdd(items, "接口: " + parts[0],
                        "目标: " + hexToIp(parts[1]) + " 网关: " + hexToIp(parts[2]));
                }
            }
            if (!hasData) {
                CollectorUtils.addDegrade(items, "路由表",
                        CollectorUtils.DegradeReason.NO_DATA, "路由表为空");
            }
        } catch (IOException e) {
            CollectorUtils.addDegrade(items, "路由表读取",
                    CollectorUtils.DegradeReason.READ_FAILED, "读取失败: " + e.getClass().getSimpleName());
        }
    }

    /**
     * DNS / 代理 / VPN / Private DNS 检测
     * 安全价值：
     * - 自定义 DNS 可被用于 DNS 劫持（MITM 入口）
     * - HTTP 代理存在 = 流量可能被截获（抓包环境）
     * - VPN 存在 = 流量被路由至 VPN 服务器
     */
    private void collectNetworkSecurityEnv(Context context, List<InfoRow> items) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                CollectorUtils.add(items, "网络安全检测", "ConnectivityManager 不可用");
                return;
            }
            Network activeNetwork = cm.getActiveNetwork();
            if (activeNetwork == null) {
                CollectorUtils.add(items, "网络", "无活动网络");
                return;
            }

            // VPN 检测
            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps != null) {
                boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                if (isVpn) {
                    CollectorUtils.addHighRisk(items, "VPN 状态",
                        "⚠ 检测到 VPN！流量被路由至 VPN 服务器，\n"
                        + "存在流量被第三方监控的风险");
                } else {
                    CollectorUtils.add(items, "VPN 状态", "未检测到 VPN");
                }

                // 计费网络
                boolean metered = !caps.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
                CollectorUtils.add(items, "计费网络", metered ? "是（流量可能产生费用）" : "否");
            }

            // DNS 服务器（API 23+）
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    LinkProperties lp = cm.getLinkProperties(activeNetwork);
                    if (lp != null) {
                        List<InetAddress> dnsServers = lp.getDnsServers();
                        if (dnsServers.isEmpty()) {
                            CollectorUtils.add(items, "DNS 服务器", "无（未获取到）");
                        } else {
                            StringBuilder sb = new StringBuilder();
                            for (InetAddress dns : dnsServers) {
                                sb.append(dns.getHostAddress()).append('\n');
                            }
                            boolean isSuspicious = dnsServers.stream().anyMatch(d -> {
                                String ip = d.getHostAddress();
                                return ip != null && !ip.startsWith("192.168")
                                    && !ip.startsWith("10.") && !ip.startsWith("172.")
                                    && !ip.equals("8.8.8.8") && !ip.equals("8.8.4.4")
                                    && !ip.equals("114.114.114.114")
                                    && !ip.equals("1.1.1.1") && !ip.equals("1.0.0.1");
                            });
                            if (isSuspicious) {
                                CollectorUtils.addHighRisk(items, "DNS 服务器",
                                    sb.toString().trim()
                                    + "\n⚠ 非常见公共 DNS，可能存在 DNS 劫持风险");
                            } else {
                                CollectorUtils.add(items, "DNS 服务器",
                                    sb.toString().trim());
                            }
                        }

                        // HTTP 代理检测
                        ProxyInfo proxy = lp.getHttpProxy();
                        if (proxy != null && proxy.getHost() != null
                                && !proxy.getHost().isEmpty()) {
                            CollectorUtils.addHighRisk(items, "HTTP 代理",
                                "⚠ 检测到代理: " + proxy.getHost() + ":" + proxy.getPort()
                                + "\n可能处于抓包/流量审计环境！");
                        } else {
                            CollectorUtils.add(items, "HTTP 代理", "未检测到代理");
                        }

                        // Private DNS (DoT/DoH) - Android 9+
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            String privateDns = lp.getPrivateDnsServerName();
                            if (privateDns != null && !privateDns.isEmpty()) {
                                CollectorUtils.add(items, "Private DNS (DoT)",
                                    privateDns + "\n（DNS over TLS，加密 DNS 查询）");
                            } else {
                                boolean usingPrivate = lp.isPrivateDnsActive();
                                CollectorUtils.add(items, "Private DNS",
                                    usingPrivate ? "已启用（系统默认）" : "未启用");
                            }
                        }
                    }
                } catch (Exception e) {
                    CollectorUtils.add(items, "DNS/代理检测", "读取失败: " + e.getClass().getSimpleName());
                }
            }

            // 全局代理检测（System.getProperty）
            String httpProxy = System.getProperty("http.proxyHost");
            String httpPort  = System.getProperty("http.proxyPort");
            if (httpProxy != null && !httpProxy.isEmpty()) {
                CollectorUtils.addHighRisk(items, "系统 HTTP 代理属性",
                    "⚠ " + httpProxy + ":" + httpPort
                    + "\n流量可能被代理服务器拦截");
            } else {
                CollectorUtils.add(items, "系统 HTTP 代理属性", "未设置");
            }

        } catch (Exception e) {
            CollectorUtils.add(items, "网络安全检测失败",
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // MITM 风险提示
        CollectorUtils.addHeader(items, "网络攻击面说明");
        CollectorUtils.add(items, "DNS 劫持",
            "恶意 DNS 服务器可将正常域名解析到攻击者 IP，\n"
            + "结合伪造 HTTPS 证书实施 MITM 攻击");
        CollectorUtils.add(items, "HTTP 代理",
            "在代理环境下明文 HTTP 流量可被完整记录，\n"
            + "HTTPS 若未做证书绑定(Certificate Pinning)同样可被解密");
        CollectorUtils.add(items, "VPN 风险",
            "不可信 VPN 可记录所有流量，\n"
            + "免费 VPN 常见数据收集和出售用户行为的问题");
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
