package com.ucas.infocollect.collector;

import android.Manifest;
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

import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * 网络信息收集器（V2 无 Context 版）。
 */
public class NetworkCollector implements InfoCollectorV2 {

    @NonNull
    @Override
    public List<String> getRequiredPermissions() {
        return Arrays.asList(
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.ACCESS_FINE_LOCATION
        );
    }

    @NonNull
    @Override
    public CollectionResult collect(@NonNull final SystemEnvironment env) {
        final CollectionResult.Builder result = CollectionResult.builder();

        result.addHeader("当前网络状态");
        collectCurrentNetwork(env, result);

        result.addHeader("网络接口 IP 地址");
        collectNetworkInterfaces(result);

        result.addHeader("ARP 缓存（局域网设备探测）");
        collectArpTable(result);

        result.addHeader("WiFi 连接信息");
        collectWifiInfo(env, result);

        result.addHeader("路由表（/proc/net/route）");
        readProcNetRoute(result);

        result.addHeader("网络安全环境（DNS / 代理 / VPN）");
        collectNetworkSecurityEnv(env, result);

        return result.build();
    }

    private void collectCurrentNetwork(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final ConnectivityManager cm = env.getSystemService(ConnectivityManager.class);
            if (cm == null) {
                result.addDegrade("当前网络状态", DegradeReason.SERVICE_UNAVAILABLE,
                    "ConnectivityManager 不可用");
                return;
            }
            final Network activeNetwork = cm.getActiveNetwork();
            if (activeNetwork == null) {
                result.addDegrade("网络状态", DegradeReason.NO_DATA, "当前无活动网络");
                return;
            }
            final NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps == null) {
                result.addDegrade("网络能力", DegradeReason.SYSTEM_RESTRICTED,
                    "系统未返回 NetworkCapabilities");
                return;
            }
            result.add("有 WiFi",      String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)));
            result.add("有移动数据",   String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)));
            result.add("有以太网",     String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)));
            result.add("是否计费",
                String.valueOf(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)));
        } catch (final Exception e) {
            result.addDegrade("当前网络状态", DegradeReason.READ_FAILED,
                "读取网络状态失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectNetworkInterfaces(
            @NonNull final CollectionResult.Builder result) {
        try {
            final Enumeration<NetworkInterface> interfaces =
                NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) {
                result.addDegrade("网络接口", DegradeReason.NO_DATA, "系统未返回网络接口列表");
                return;
            }
            boolean hasData = false;
            for (final NetworkInterface ni : Collections.list(interfaces)) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (final InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (!addr.isLoopbackAddress()) {
                        hasData = true;
                        result.add(ni.getName(), addr.getHostAddress());
                    }
                }
            }
            if (!hasData)
                result.addDegrade("网络接口", DegradeReason.NO_DATA, "未发现可用 IP 地址");
        } catch (final Exception e) {
            result.addDegrade("网络接口", DegradeReason.READ_FAILED,
                "IP 读取异常: " + e.getClass().getSimpleName());
        }
    }

    private void collectWifiInfo(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final WifiManager wm = env.getSystemService(WifiManager.class);
            if (wm == null) {
                result.addDegrade("WiFi 服务", DegradeReason.SERVICE_UNAVAILABLE,
                    "WifiManager 不可用");
                return;
            }
            collectWifiConnectionInfo(wm, result);
            collectWifiScanInfo(wm, result);
        } catch (final SecurityException e) {
            result.addDegrade("WiFi 详情", DegradeReason.PERMISSION_DENIED,
                "缺少 ACCESS_FINE_LOCATION 或 ACCESS_WIFI_STATE 权限");
        } catch (final Exception e) {
            result.addDegrade("WiFi 详情", DegradeReason.READ_FAILED,
                "读取 WiFi 信息失败: " + e.getClass().getSimpleName());
        }
    }

    @SuppressWarnings("deprecation")
    private void collectWifiConnectionInfo(
            @NonNull final WifiManager            wm,
            @NonNull final CollectionResult.Builder result) {
        try {
            final WifiInfo wi = wm.getConnectionInfo();
            if (wi == null) {
                result.addDegrade("WiFi 连接", DegradeReason.NO_DATA,
                    "WiFi 未连接或系统未返回连接信息");
            } else {
                result.addHighRisk("SSID",   wi.getSSID());
                result.addHighRisk("BSSID",  wi.getBSSID());
                result.add("MAC 地址", wi.getMacAddress() != null ? wi.getMacAddress() : "系统已隐藏");
                result.add("信号强度", wi.getRssi() + " dBm");
                result.add("链接速度", wi.getLinkSpeed() + " Mbps");
                result.add("IP 地址",  Formatter.formatIpAddress(wi.getIpAddress()));
                result.add("网络 ID",  String.valueOf(wi.getNetworkId()));
            }
            final DhcpInfo dhcp = wm.getDhcpInfo();
            if (dhcp == null) {
                result.addDegrade("DHCP 信息", DegradeReason.NO_DATA,
                    "WiFi 未就绪或 ROM 未暴露 DHCP 数据");
            } else {
                result.add("网关 IP", Formatter.formatIpAddress(dhcp.gateway));
                result.add("DNS1",   Formatter.formatIpAddress(dhcp.dns1));
                result.add("DNS2",   Formatter.formatIpAddress(dhcp.dns2));
            }
        } catch (final SecurityException e) {
            result.addDegrade("WiFi 连接", DegradeReason.SYSTEM_RESTRICTED,
                "系统限制读取连接态信息");
        } catch (final Exception e) {
            result.addDegrade("WiFi 连接", DegradeReason.READ_FAILED,
                "读取连接态失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectWifiScanInfo(
            @NonNull final WifiManager            wm,
            @NonNull final CollectionResult.Builder result) {
        result.addHeader("周边 WiFi 热点（WiFi 定位）");
        try {
            final List<ScanResult> scanResults = wm.getScanResults();
            if (scanResults == null || scanResults.isEmpty()) {
                result.addDegrade("热点扫描", DegradeReason.NO_DATA,
                    "未扫描到热点或系统限制返回结果");
                return;
            }
            for (final ScanResult sr : scanResults) {
                if (sr == null) continue;
                final String ssid  = (sr.SSID != null && !sr.SSID.isEmpty()) ? sr.SSID : "(隐藏 SSID)";
                final String bssid = sr.BSSID != null ? sr.BSSID : "N/A";
                result.addHighRisk(ssid, "BSSID:" + bssid + " 信号:" + sr.level + "dBm");
            }
        } catch (final SecurityException e) {
            result.addDegrade("热点扫描", DegradeReason.SYSTEM_RESTRICTED,
                "系统限制热点扫描结果访问");
        } catch (final Exception e) {
            result.addDegrade("热点扫描", DegradeReason.READ_FAILED,
                "读取扫描结果失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectArpTable(
            @NonNull final CollectionResult.Builder result) {
        try (final BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            br.readLine(); // 跳过表头
            boolean hasData = false;
            while ((line = br.readLine()) != null) {
                final String[] parts = line.trim().split("\\s+");
                if (parts.length >= 4) {
                    final String ip    = parts[0];
                    final String mac   = parts[3];
                    final String iface = parts.length >= 6 ? parts[5] : "?";
                    if (!mac.equals("00:00:00:00:00:00")) {
                        hasData = true;
                        result.addHighRisk(ip + " [" + iface + "]", "MAC: " + mac);
                    }
                }
            }
            if (!hasData)
                result.addDegrade("ARP 缓存", DegradeReason.NO_DATA, "未发现可用 ARP 记录");
        } catch (final IOException e) {
            result.addDegrade("ARP 读取", DegradeReason.READ_FAILED,
                "读取失败: " + e.getClass().getSimpleName());
        }
    }

    private void readProcNetRoute(
            @NonNull final CollectionResult.Builder result) {
        try (final BufferedReader br = new BufferedReader(new FileReader("/proc/net/route"))) {
            String line;
            br.readLine(); // 跳过表头
            boolean hasData = false;
            while ((line = br.readLine()) != null) {
                final String[] parts = line.trim().split("\\s+");
                if (parts.length >= 3) {
                    hasData = true;
                    result.add("接口: " + parts[0],
                        "目标: " + hexToIp(parts[1]) + " 网关: " + hexToIp(parts[2]));
                }
            }
            if (!hasData)
                result.addDegrade("路由表", DegradeReason.NO_DATA, "路由表为空");
        } catch (final IOException e) {
            result.addDegrade("路由表读取", DegradeReason.READ_FAILED,
                "读取失败: " + e.getClass().getSimpleName());
        }
    }

    private void collectNetworkSecurityEnv(
            @NonNull final SystemEnvironment      env,
            @NonNull final CollectionResult.Builder result) {
        try {
            final ConnectivityManager cm = env.getSystemService(ConnectivityManager.class);
            if (cm == null) {
                result.add("网络安全检测", "ConnectivityManager 不可用");
                return;
            }
            final Network activeNetwork = cm.getActiveNetwork();
            if (activeNetwork == null) {
                result.add("网络", "无活动网络");
                return;
            }

            final NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps != null) {
                final boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                if (isVpn) {
                    result.addHighRisk("VPN 状态",
                        "检测到 VPN！流量被路由至 VPN 服务器，\n存在流量被第三方监控的风险");
                } else {
                    result.add("VPN 状态", "未检测到 VPN");
                }
                final boolean metered =
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
                result.add("计费网络", metered ? "是（流量可能产生费用）" : "否");
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    final LinkProperties lp = cm.getLinkProperties(activeNetwork);
                    if (lp != null) {
                        final List<InetAddress> dnsServers = lp.getDnsServers();
                        if (dnsServers.isEmpty()) {
                            result.add("DNS 服务器", "无（未获取到）");
                        } else {
                            final StringBuilder sb = new StringBuilder();
                            for (final InetAddress dns : dnsServers)
                                sb.append(dns.getHostAddress()).append('\n');
                            final boolean isSuspicious = dnsServers.stream().anyMatch(d -> {
                                final String ip = d.getHostAddress();
                                return ip != null && !ip.startsWith("192.168")
                                    && !ip.startsWith("10.") && !ip.startsWith("172.")
                                    && !ip.equals("8.8.8.8") && !ip.equals("8.8.4.4")
                                    && !ip.equals("114.114.114.114")
                                    && !ip.equals("1.1.1.1") && !ip.equals("1.0.0.1");
                            });
                            if (isSuspicious) {
                                result.addHighRisk("DNS 服务器",
                                    sb.toString().trim() + "\n⚠ 非常见公共 DNS，可能存在 DNS 劫持风险");
                            } else {
                                result.add("DNS 服务器", sb.toString().trim());
                            }
                        }

                        final ProxyInfo proxy = lp.getHttpProxy();
                        if (proxy != null && proxy.getHost() != null
                                && !proxy.getHost().isEmpty()) {
                            result.addHighRisk("HTTP 代理",
                                "检测到代理: " + proxy.getHost() + ":" + proxy.getPort()
                                + "\n可能处于抓包/流量审计环境！");
                        } else {
                            result.add("HTTP 代理", "未检测到代理");
                        }

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            final String privateDns = lp.getPrivateDnsServerName();
                            if (privateDns != null && !privateDns.isEmpty()) {
                                result.add("Private DNS (DoT)", privateDns + "\n（DNS over TLS，加密 DNS 查询）");
                            } else {
                                result.add("Private DNS",
                                    lp.isPrivateDnsActive() ? "已启用（系统默认）" : "未启用");
                            }
                        }
                    }
                } catch (final Exception e) {
                    result.add("DNS/代理检测", "读取失败: " + e.getClass().getSimpleName());
                }
            }

            final String httpProxy = System.getProperty("http.proxyHost");
            final String httpPort  = System.getProperty("http.proxyPort");
            if (httpProxy != null && !httpProxy.isEmpty()) {
                result.addHighRisk("系统 HTTP 代理属性",
                    httpProxy + ":" + httpPort + "\n流量可能被代理服务器拦截");
            } else {
                result.add("系统 HTTP 代理属性", "未设置");
            }
        } catch (final Exception e) {
            result.add("网络安全检测失败", e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        result.addHeader("网络攻击面说明");
        result.add("DNS 劫持",
            "恶意 DNS 服务器可将正常域名解析到攻击者 IP，\n结合伪造 HTTPS 证书实施 MITM 攻击");
        result.add("HTTP 代理",
            "在代理环境下明文 HTTP 流量可被完整记录，\nHTTPS 若未做证书绑定同样可被解密");
        result.add("VPN 风险",
            "不可信 VPN 可记录所有流量，\n免费 VPN 常见数据收集和出售用户行为的问题");
    }

    private String hexToIp(final String hex) {
        try {
            final long val = Long.parseLong(hex, 16);
            return String.format("%d.%d.%d.%d",
                val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF);
        } catch (final Exception e) {
            return hex;
        }
    }
}
