# 🔴 Metasploit MCP Server

MCP (Model Context Protocol) сервер для интеграции Metasploit Framework с Claude AI.

## ⚠️ ПРЕДУПРЕЖДЕНИЕ

```
╔══════════════════════════════════════════════════════════════════╗
║  ТОЛЬКО ДЛЯ АВТОРИЗОВАННОГО ТЕСТИРОВАНИЯ БЕЗОПАСНОСТИ!          ║
║  Использование без разрешения владельца системы НЕЗАКОННО!      ║
║  Автор не несёт ответственности за неправомерное использование  ║
╚══════════════════════════════════════════════════════════════════╝
```

## 📋 Требования

- Python 3.8+
- Metasploit Framework
- msfrpcd (Metasploit RPC Daemon)

## 🚀 Установка

### 1. Установка зависимостей Python

```bash
cd metasploit-mcp-server
pip install -r requirements.txt
```

### 2. Установка Metasploit (если не установлен)

**Kali Linux:**
```bash
sudo apt update && sudo apt install metasploit-framework
```

**macOS:**
```bash
brew install metasploit
```

**Другие системы:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sh
```

### 3. Запуск msfrpcd

```bash
# Запуск RPC демона
msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553

# Или через msfconsole
msfconsole -q -x "load msgrpc Pass=msf_password ServerHost=127.0.0.1 ServerPort=55553"
```

### 4. Настройка конфигурации

Отредактируйте `msf_config.json`:

```json
{
    "host": "127.0.0.1",
    "port": 55553,
    "password": "ваш_пароль",
    "ssl": true,
    "timeout": 30
}
```

## 🔧 Интеграция с Claude Code

### Добавьте в `.vscode/mcp.json`:

```json
{
    "servers": {
        "metasploit": {
            "type": "stdio",
            "command": "python3",
            "args": ["/путь/к/metasploit-mcp-server/metasploit_mcp_server.py"]
        }
    }
}
```

### Или в Claude Desktop `claude_desktop_config.json`:

```json
{
    "mcpServers": {
        "metasploit": {
            "command": "python3",
            "args": ["/путь/к/metasploit-mcp-server/metasploit_mcp_server.py"]
        }
    }
}
```

## 📚 Доступные инструменты

| Инструмент | Описание |
|------------|----------|
| `msf_connect` | Подключение к Metasploit RPC |
| `msf_disconnect` | Отключение |
| `msf_search` | Поиск модулей (эксплойты, auxiliary, post) |
| `msf_module_info` | Информация о модуле |
| `msf_sessions` | Список активных сессий |
| `msf_session_cmd` | Команда в сессии (белый список) |
| `msf_create_handler` | Создание handler |
| `msf_generate_payload_cmd` | Команда msfvenom |
| `msf_jobs` | Список задач |
| `msf_kill_job` | Остановка задачи |
| `msf_db_hosts` | Хосты в БД |
| `msf_db_services` | Сервисы в БД |
| `msf_db_vulns` | Уязвимости в БД |

## 💬 Примеры использования с Claude

### Поиск эксплойтов:
```
Найди эксплойты для Windows SMB
```

### Информация о модуле:
```
Покажи информацию о exploit/windows/smb/ms17_010_eternalblue
```

### Проверка сессий:
```
Какие сессии сейчас активны?
```

### Поиск по CVE:
```
Найди модули для CVE-2021-44228 (Log4Shell)
```

## 🛡️ Безопасность

### Белый список команд для сессий:
- `sysinfo`, `getuid`, `pwd`, `ls`, `dir`
- `ps`, `ifconfig`, `ipconfig`
- `route`, `arp`, `help`
- `background`, `sessions`

### Ограничения:
- Нельзя выполнять произвольные команды
- Нельзя генерировать реальные payload-файлы
- Все действия логируются
- Требуется подтверждение для опасных операций

## 📁 Структура проекта

```
metasploit-mcp-server/
├── metasploit_mcp_server.py  # Основной MCP сервер
├── msf_config.json           # Конфигурация
├── requirements.txt          # Python зависимости
├── README.md                 # Документация
└── metasploit_mcp.log        # Логи работы
```

## 🔍 Отладка

### Проверка подключения вручную:

```python
from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient('msf_password', server='127.0.0.1', port=55553)
print(client.core.version)
```

### Логи:
```bash
tail -f metasploit_mcp.log
```

## 📜 Лицензия

MIT License - только для образовательных целей и авторизованного тестирования.

## 🔗 Ресурсы

- [Metasploit Framework](https://www.metasploit.com/)
- [pymetasploit3 Documentation](https://github.com/DanMcInerney/pymetasploit3)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Offensive Security](https://www.offensive-security.com/)
