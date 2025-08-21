package com.protect7.authanalyzer.util;

import java.util.HashMap;
import java.util.Map;

/**
 * 域名过滤器帮助工具类
 * 提供常用的域名黑白名单模板和验证功能
 */
public class DomainFilterHelper {
    
    // 常用白名单域名模板
    private static final Map<String, String[]> WHITELIST_TEMPLATES = new HashMap<>();
    
    // 常用黑名单域名模板
    private static final Map<String, String[]> BLACKLIST_TEMPLATES = new HashMap<>();
    
    static {
        // 白名单模板
        WHITELIST_TEMPLATES.put("Production Domains", new String[]{
            "example.com", "www.example.com", "api.example.com"
        });
        
        WHITELIST_TEMPLATES.put("Testing Domains", new String[]{
            "test.example.com", "staging.example.com", "dev.example.com"
        });
        
        WHITELIST_TEMPLATES.put("API Domains", new String[]{
            "api.example.com", "*.api.example.com", "rest.example.com"
        });
        
        WHITELIST_TEMPLATES.put("Admin Domains", new String[]{
            "admin.example.com", "manage.example.com", "control.example.com"
        });
        
        WHITELIST_TEMPLATES.put("Wildcard Domains", new String[]{
            "*.example.com", "*.test.example.com"
        });
        
        // 黑名单模板
        BLACKLIST_TEMPLATES.put("Third Party Services", new String[]{
            "google-analytics.com", "facebook.com", "twitter.com", "linkedin.com",
            "googletagmanager.com", "doubleclick.net", "amazonaws.com"
        });
        
        BLACKLIST_TEMPLATES.put("CDN and Static", new String[]{
            "cdn.example.com", "static.example.com", "assets.example.com",
            "*.cloudfront.net", "*.akamaihd.net"
        });
        
        BLACKLIST_TEMPLATES.put("Monitoring and Logs", new String[]{
            "monitoring.example.com", "logs.example.com", "metrics.example.com",
            "health.example.com", "status.example.com"
        });
        
        BLACKLIST_TEMPLATES.put("Development Tools", new String[]{
            "localhost", "127.0.0.1", "*.ngrok.io", "*.localtunnel.me"
        });
        
        BLACKLIST_TEMPLATES.put("External APIs", new String[]{
            "api.github.com", "api.twitter.com", "graph.facebook.com",
            "maps.googleapis.com", "www.googleapis.com"
        });
    }
    
    /**
     * 获取所有可用的白名单域名模板
     */
    public static Map<String, String[]> getWhitelistTemplates() {
        return new HashMap<>(WHITELIST_TEMPLATES);
    }
    
    /**
     * 获取所有可用的黑名单域名模板
     */
    public static Map<String, String[]> getBlacklistTemplates() {
        return new HashMap<>(BLACKLIST_TEMPLATES);
    }
    
    /**
     * 获取指定模板的域名
     */
    public static String[] getTemplateDomains(String templateName, boolean isWhitelist) {
        Map<String, String[]> templates = isWhitelist ? WHITELIST_TEMPLATES : BLACKLIST_TEMPLATES;
        return templates.get(templateName);
    }
    
    /**
     * 验证域名格式是否有效
     */
    public static boolean isValidDomain(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return false;
        }
        
        String cleanDomain = domain.trim();
        
        // 支持通配符格式
        if (cleanDomain.startsWith("*.")) {
            cleanDomain = cleanDomain.substring(2);
        } else if (cleanDomain.startsWith(".")) {
            cleanDomain = cleanDomain.substring(1);
        }
        
        // 移除协议前缀
        if (cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
            try {
                cleanDomain = new java.net.URL(cleanDomain).getHost();
            } catch (Exception e) {
                return false;
            }
        }
        
        // 基本域名格式验证
        if (cleanDomain.length() > 253) {
            return false;
        }
        
        String[] parts = cleanDomain.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        
        for (String part : parts) {
            if (part.length() > 63 || part.length() == 0) {
                return false;
            }
            if (!part.matches("^[a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?$")) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 将域名数组转换为逗号分隔的字符串
     */
    public static String domainsToString(String[] domains) {
        if (domains == null || domains.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < domains.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(domains[i]);
        }
        return sb.toString();
    }
    
    /**
     * 将逗号分隔的字符串转换为域名数组
     */
    public static String[] stringToDomains(String input) {
        if (input == null || input.trim().isEmpty()) {
            return new String[0];
        }
        String[] domains = input.split(",");
        String[] result = new String[domains.length];
        for (int i = 0; i < domains.length; i++) {
            result[i] = domains[i].trim();
        }
        return result;
    }
    
    /**
     * 获取域名的显示名称（用于UI显示）
     */
    public static String getDomainDisplayName(String domain) {
        if (domain == null) {
            return "";
        }
        
        String cleanDomain = domain.trim();
        
        // 处理通配符格式
        if (cleanDomain.startsWith("*.")) {
            return "All subdomains of " + cleanDomain.substring(2);
        } else if (cleanDomain.startsWith(".")) {
            return "All subdomains of " + cleanDomain.substring(1);
        }
        
        // 移除协议前缀
        if (cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
            try {
                cleanDomain = new java.net.URL(cleanDomain).getHost();
            } catch (Exception e) {
                // 如果解析失败，返回原值
            }
        }
        
        return cleanDomain;
    }
} 