package com.protect7.authanalyzer.filter;

import java.net.URL;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * 域名白名单过滤器
 * 只允许指定域名的请求通过分析
 */
public class DomainWhitelistFilter extends RequestFilter {

	public DomainWhitelistFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(onOffButton.isSelected() && stringLiterals.length > 0) {
			URL url = requestInfo.getUrl();
			if(url != null) {
				String host = url.getHost().toLowerCase();
				boolean isWhitelisted = false;
				
				// 检查域名是否匹配白名单中的任何模式
				for(String domain : stringLiterals) {
					if(!domain.trim().equals("")) {
						String cleanDomain = domain.trim().toLowerCase();
						// 移除协议前缀（如果存在）
						if(cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
							try {
								cleanDomain = new URL(cleanDomain).getHost();
							} catch (Exception e) {
								// 如果URL解析失败，跳过这个域名
								continue;
							}
						}
						
						// 支持通配符匹配
						if(cleanDomain.startsWith("*.")) {
							// 通配符匹配：*.example.com 匹配 example.com, sub.example.com 等
							String suffix = cleanDomain.substring(2);
							if(host.equals(suffix) || host.endsWith("." + suffix)) {
								isWhitelisted = true;
								break;
							}
						} else if(cleanDomain.startsWith(".")) {
							// 以点开头：.example.com 匹配 example.com, sub.example.com 等
							String suffix = cleanDomain.substring(1);
							if(host.equals(suffix) || host.endsWith("." + suffix)) {
								isWhitelisted = true;
								break;
							}
						} else {
							// 精确匹配
							if(host.equals(cleanDomain)) {
								isWhitelisted = true;
								break;
							}
						}
					}
				}
				
				// 如果不匹配任何白名单域名，则过滤掉
				if(!isWhitelisted) {
					incrementFiltered();
					return true;
				}
			}
		}
		return false;
	}
	
	@Override
	public boolean hasStringLiterals() {
		return true;
	}
} 