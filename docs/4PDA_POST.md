# Пост для 4PDA - AuthMCP Gateway

## BB-код для поста:

```bbcode
[B]🛡️ AuthMCP Gateway - шлюз для MCP серверов[/B]

Сделал шлюз для подключения MCP серверов к AI клиентам (Claude Desktop, GitHub Copilot, Cursor и др.).

[B]Что это даёт:[/B]
• Можно подключить несколько MCP серверов через одну точку
• Добавляется авторизация (обычно MCP сервера без защиты)
• Видно кто и что запрашивает
• Можно давать доступ разным пользователям
• Защита от злоупотреблений

В общем - удобное и безопасное подключение MCP инструментов к AI.

PyPI: [url=https://pypi.org/project/authmcp-gateway/]authmcp-gateway[/url]
GitHub: [url=https://github.com/loglux/authmcp-gateway]loglux/authmcp-gateway[/url]

[B]Скриншоты:[/B]
[img]https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/01-dashboard.png[/img]
[img]https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/02-mcp-servers.png[/img]
[img]https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/05-mcp-security-audit.png[/img]

[spoiler=Установка:]
[code]
pip install authmcp-gateway
authmcp-gateway
[/code]
Открыть http://localhost:9105/setup - создать админа, добавить свои MCP сервера.

Подробнее: [url=https://github.com/loglux/authmcp-gateway]GitHub[/url]
[/spoiler]

Open Source (MIT). Новая версия 1.0.2 - добавил проверку безопасности MCP серверов.

#ИИинструменты #MCP
```
