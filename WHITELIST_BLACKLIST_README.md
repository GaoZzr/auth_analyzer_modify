# Auth Analyzer 域名黑白名单功能说明

## 概述

Auth Analyzer 插件现已支持域名级别的黑白名单功能，允许用户精确控制哪些域名的HTTP请求需要进行分析，哪些域名的请求应该被过滤掉。

## 功能特性

### 1. 域名白名单过滤器 (Domain Whitelist Filter)
- **功能**: 只允许指定域名的请求通过分析
- **用途**: 当您只想分析特定域名的请求时使用
- **示例**: 只分析 `example.com` 和 `*.test.example.com` 的请求

### 2. 域名黑名单过滤器 (Domain Blacklist Filter)
- **功能**: 过滤掉指定域名的请求
- **用途**: 排除不需要分析的第三方服务、CDN、监控域名等
- **示例**: 排除 `google-analytics.com`、`*.cdn.example.com`、`localhost`

### 3. 通配符支持
- 支持 `*.example.com` 格式，匹配所有子域名
- 支持 `.example.com` 格式，匹配所有子域名
- 支持精确域名匹配
- 自动处理协议前缀（http://, https://）

### 4. 预定义模板
提供常用的域名黑白名单模板，快速配置：

#### 白名单模板
- **Production Domains**: `example.com`, `www.example.com`, `api.example.com`
- **Testing Domains**: `test.example.com`, `staging.example.com`, `dev.example.com`
- **API Domains**: `api.example.com`, `*.api.example.com`, `rest.example.com`
- **Admin Domains**: `admin.example.com`, `manage.example.com`, `control.example.com`
- **Wildcard Domains**: `*.example.com`, `*.test.example.com`

#### 黑名单模板
- **Third Party Services**: `google-analytics.com`, `facebook.com`, `twitter.com`, `linkedin.com`
- **CDN and Static**: `cdn.example.com`, `static.example.com`, `assets.example.com`
- **Monitoring and Logs**: `monitoring.example.com`, `logs.example.com`, `metrics.example.com`
- **Development Tools**: `localhost`, `127.0.0.1`, `*.ngrok.io`, `*.localtunnel.me`
- **External APIs**: `api.github.com`, `api.twitter.com`, `graph.facebook.com`

## 使用方法

### 1. 启用过滤器
1. 在Auth Analyzer的配置面板中找到"Filters"部分
2. 勾选"Whitelist Domains"或"Blacklist Domains"复选框
3. 点击信息图标查看详细说明

### 2. 配置域名
1. 点击过滤器旁边的信息图标
2. 在弹出的提示框中输入域名，用逗号分隔
3. 支持通配符和精确匹配

### 3. 域名格式示例

#### 白名单域名示例
```
example.com, *.test.example.com, api.example.com
staging.example.com, dev.example.com
*.api.example.com, *.admin.example.com
```

#### 黑名单域名示例
```
google-analytics.com, *.cdn.example.com, localhost
*.thirdparty.com, monitoring.example.com
127.0.0.1, *.ngrok.io
```

## 高级功能

### 1. 通配符匹配规则
- `*.example.com` - 匹配所有子域名（如 `api.example.com`, `admin.example.com`）
- `.example.com` - 匹配所有子域名（与 `*.example.com` 效果相同）
- `example.com` - 精确匹配域名

### 2. 域名验证
- 自动验证域名格式的有效性
- 支持带协议前缀的域名（自动提取主机部分）
- 长度和格式检查

### 3. 智能匹配
- 自动转换为小写进行匹配
- 忽略协议前缀
- 支持IPv4地址

## 配置建议

### 1. 白名单配置建议
- 只包含需要测试的目标域名
- 使用通配符减少重复配置
- 考虑测试环境和生产环境

### 2. 黑名单配置建议
- 排除第三方服务调用
- 排除CDN和静态资源域名
- 排除监控和日志域名
- 排除开发工具域名

### 3. 性能优化
- 白名单域名应该精确，避免过于宽泛
- 黑名单域名应该全面，减少不必要的分析
- 合理使用通配符

## 使用场景

### 1. 生产环境测试
```
白名单: example.com, *.example.com
黑名单: *.cdn.example.com, monitoring.example.com, logs.example.com
```

### 2. 测试环境测试
```
白名单: test.example.com, staging.example.com, *.test.example.com
黑名单: *.thirdparty.com, localhost, 127.0.0.1
```

### 3. API测试
```
白名单: api.example.com, *.api.example.com, rest.example.com
黑名单: *.cdn.example.com, *.monitoring.example.com
```

## 注意事项

1. **优先级**: 白名单和黑名单可以同时使用，但要注意逻辑关系
2. **性能**: 域名匹配比URL路径匹配更高效
3. **调试**: 使用过滤器的统计信息监控过滤效果
4. **备份**: 定期备份过滤器配置，避免丢失

## 故障排除

### 常见问题
1. **过滤器不生效**: 检查是否正确启用了过滤器
2. **域名匹配错误**: 检查域名格式和通配符使用
3. **性能问题**: 避免过于复杂的通配符模式

### 调试技巧
1. 查看过滤器的统计信息
2. 使用简单的域名进行测试
3. 逐步添加复杂的匹配规则

## 更新日志

- **v1.1.15**: 新增域名黑白名单过滤器功能
- 支持通配符域名匹配
- 提供预定义域名模板
- 自动域名格式验证
- 高效的域名级别过滤 