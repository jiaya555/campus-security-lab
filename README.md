# 校园二手交易平台攻防双视图靶场

这是一个用于信息安全课程大作业的 Flask Web 安全作品。系统模拟校园二手交易业务，并在同一套功能中提供“漏洞模式”和“安全模式”对照，方便复现漏洞、观察修复效果，并支撑论文与 PPT 展示。

## 快速运行

推荐使用 PowerShell 7，避免中文路径乱码。

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app run --host 127.0.0.1 --port 5000
```

也可以直接运行：

```powershell
powershell -ExecutionPolicy Bypass -File ".\start.ps1"
```

浏览器访问 `http://127.0.0.1:5000`。

## 内置账号

| 角色 | 用户名 | 密码 |
| --- | --- | --- |
| 普通用户 | alice | alice123 |
| 普通用户 | bob | bob123 |
| 管理员 | admin | admin123 |

## 作品亮点

- 同一业务系统下对比漏洞实现和安全实现。
- 覆盖 SQL 注入、XSS、越权访问、文件上传、CSRF 五类经典 Web 风险。
- 每个页面都能通过右上方模式切换直接观察“攻击成功”和“修复生效”的差异。
- SQLite 初始化脚本可一键生成测试数据，便于答辩现场演示。

## 漏洞复现实验

| 漏洞 | 漏洞模式复现 | 安全模式修复 |
| --- | --- | --- |
| SQL 注入 | 首页搜索输入 `' OR 1=1 --` 可返回全部商品 | 参数化查询，payload 被当作普通文本 |
| XSS | 商品评论输入 `<script>alert('xss')</script>` 原样渲染 | Jinja 自动转义输出 |
| 越权访问 | bob 登录后访问 `/orders/1?mode=vulnerable` 可看到 Alice 订单 | 校验订单归属，返回 403 |
| 文件上传 | 发布商品上传 `shell.php` 可通过 | 扩展名白名单拒绝 |
| CSRF | 漏洞模式资料更新不需要 token | 安全模式要求 session 中的 CSRF token |

## 测试

```powershell
python -m unittest discover -s tests -v
```

测试覆盖五类漏洞在漏洞模式与安全模式下的行为差异。

## 提交物

`deliverables/` 中包含：

- `课程大论文.md`：按作品赛模板组织的论文草稿
- `汇报PPT.md`：10 分钟汇报 PPT 文案
- `作品海报.html`：一页作品海报，可直接用浏览器打开并截图/打印

最终可打包为 `校园二手交易平台攻防双视图靶场_姓名.zip`，包含代码、README、测试、PPT、海报和课程论文。
