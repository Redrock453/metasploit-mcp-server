# MCP Configuration Files

## Для VS Code + Claude Extension

1. Скопируйте `vscode_mcp.json` в `.vscode/mcp.json` вашего проекта
2. Или в глобальные настройки: `~/.config/Code/User/globalStorage/anthropic.claude-code/settings/mcp_settings.json`

```bash
# Для проекта
mkdir -p .vscode && cp configs/vscode_mcp.json .vscode/mcp.json

# Глобально
mkdir -p ~/.config/Code/User/globalStorage/anthropic.claude-code/settings/
cp configs/vscode_mcp.json ~/.config/Code/User/globalStorage/anthropic.claude-code/settings/mcp_settings.json
```

## Для Claude Desktop

1. Скопируйте содержимое `claude_desktop_config.json` в:
   - **Linux:** `~/.config/claude/claude_desktop_config.json`
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```bash
# Linux
mkdir -p ~/.config/claude && cp configs/claude_desktop_config.json ~/.config/claude/
```

## ⚠️ Важно: Измените пути!

Замените `/home/adam/` на ваш домашний каталог:

```bash
# Узнать ваш путь
echo $HOME

# Пример для пользователя 'user'
# /home/user/metasploit-mcp-server/venv/bin/python3
```

## Перед использованием

1. Установите зависимости:
```bash
cd ~/metasploit-mcp-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Запустите Metasploit RPC:
```bash
msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553
```

3. Перезапустите VS Code / Claude Desktop
