#!/usr/bin/env python3
"""
Metasploit MCP Server - интеграция Metasploit Framework с Claude
Позволяет AI управлять Metasploit через Model Context Protocol

Автор: CARRIE AI Ecosystem
Лицензия: MIT (только для авторизованного тестирования)
"""

import asyncio
import json
import logging
import sys
import os
from typing import Any, Dict, List, Optional
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('metasploit_mcp.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Попытка импорта pymetasploit3
try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False
    logger.warning("pymetasploit3 не установлен. Установите: pip install pymetasploit3")


class MetasploitMCPServer:
    """MCP сервер для управления Metasploit Framework"""

    def __init__(self):
        self.client: Optional[MsfRpcClient] = None
        self.connected = False
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Загрузка конфигурации"""
        config_file = os.path.join(os.path.dirname(__file__), 'msf_config.json')
        
        default_config = {
            "host": "127.0.0.1",
            "port": 55553,
            "password": "msf_password",
            "ssl": True,
            "timeout": 30
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return {**default_config, **json.load(f)}
            except Exception as e:
                logger.error(f"Ошибка загрузки конфигурации: {e}")
        
        return default_config

    async def connect(self) -> Dict[str, Any]:
        """Подключение к Metasploit RPC"""
        if not MSF_AVAILABLE:
            return {
                "success": False,
                "error": "pymetasploit3 не установлен. Выполните: pip install pymetasploit3"
            }
        
        try:
            self.client = MsfRpcClient(
                self.config["password"],
                server=self.config["host"],
                port=self.config["port"],
                ssl=self.config["ssl"]
            )
            self.connected = True
            
            # Получаем информацию о версии
            version = self.client.core.version
            
            return {
                "success": True,
                "message": "Подключено к Metasploit RPC",
                "version": version,
                "host": f"{self.config['host']}:{self.config['port']}"
            }
            
        except Exception as e:
            self.connected = False
            return {
                "success": False,
                "error": str(e),
                "hint": "Убедитесь, что msfrpcd запущен: msfrpcd -P msf_password -S -a 127.0.0.1"
            }

    async def disconnect(self) -> Dict[str, Any]:
        """Отключение от Metasploit RPC"""
        if self.client:
            try:
                self.client.logout()
            except:
                pass
            self.client = None
            self.connected = False
        return {"success": True, "message": "Отключено от Metasploit"}

    async def search_modules(self, query: str, module_type: str = "all") -> Dict[str, Any]:
        """
        Поиск модулей Metasploit
        
        Args:
            query: Поисковый запрос (CVE, имя, платформа)
            module_type: Тип модуля (exploit, auxiliary, post, payload, all)
        """
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            results = self.client.modules.search(query)
            
            # Фильтрация по типу
            if module_type != "all":
                results = [m for m in results if m.get('type') == module_type]
            
            # Ограничиваем до 20 результатов
            results = results[:20]
            
            formatted = []
            for module in results:
                formatted.append({
                    "name": module.get('name', 'Unknown'),
                    "fullname": module.get('fullname', ''),
                    "type": module.get('type', ''),
                    "rank": module.get('rank', ''),
                    "description": module.get('description', '')[:200]
                })
            
            return {
                "success": True,
                "query": query,
                "total_found": len(results),
                "modules": formatted
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_module_info(self, module_path: str) -> Dict[str, Any]:
        """
        Получить информацию о модуле
        
        Args:
            module_path: Полный путь модуля (например: exploit/windows/smb/ms17_010_eternalblue)
        """
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            # Определяем тип модуля
            parts = module_path.split('/')
            module_type = parts[0]
            
            module = self.client.modules.use(module_type, module_path)
            
            # Собираем информацию
            info = {
                "name": module.name,
                "fullname": module.fullname,
                "description": module.description,
                "authors": module.authors,
                "references": module.references[:10] if hasattr(module, 'references') else [],
                "platform": module.platform if hasattr(module, 'platform') else [],
                "arch": module.arch if hasattr(module, 'arch') else [],
                "rank": module.rank,
                "options": {}
            }
            
            # Получаем опции
            for opt_name, opt_info in module.options.items():
                info["options"][opt_name] = {
                    "required": opt_info.get('required', False),
                    "default": opt_info.get('default', ''),
                    "description": opt_info.get('desc', '')
                }
            
            return {"success": True, "module": info}
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_exploits_by_platform(self, platform: str) -> Dict[str, Any]:
        """
        Список эксплойтов для платформы
        
        Args:
            platform: Платформа (windows, linux, unix, osx, android, etc.)
        """
        return await self.search_modules(platform, "exploit")

    async def list_sessions(self) -> Dict[str, Any]:
        """Список активных сессий Meterpreter/Shell"""
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            sessions = self.client.sessions.list
            
            formatted = []
            for sid, info in sessions.items():
                formatted.append({
                    "id": sid,
                    "type": info.get('type', ''),
                    "tunnel_local": info.get('tunnel_local', ''),
                    "tunnel_peer": info.get('tunnel_peer', ''),
                    "via_exploit": info.get('via_exploit', ''),
                    "via_payload": info.get('via_payload', ''),
                    "info": info.get('info', ''),
                    "platform": info.get('platform', ''),
                    "arch": info.get('arch', '')
                })
            
            return {
                "success": True,
                "total_sessions": len(formatted),
                "sessions": formatted
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def session_command(self, session_id: int, command: str) -> Dict[str, Any]:
        """
        Выполнить команду в сессии
        
        Args:
            session_id: ID сессии
            command: Команда для выполнения
        """
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        # Белый список безопасных команд
        safe_commands = [
            'sysinfo', 'getuid', 'pwd', 'ls', 'dir', 'ps', 
            'ifconfig', 'ipconfig', 'route', 'arp',
            'help', 'background', 'sessions'
        ]
        
        cmd_base = command.split()[0].lower()
        if cmd_base not in safe_commands:
            return {
                "success": False,
                "error": f"Команда '{cmd_base}' не в белом списке безопасных команд",
                "allowed_commands": safe_commands
            }
        
        try:
            session = self.client.sessions.session(str(session_id))
            result = session.run_shell_cmd_with_output(command, timeout=30)
            
            return {
                "success": True,
                "session_id": session_id,
                "command": command,
                "output": result
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_handler(self, payload: str, lhost: str, lport: int) -> Dict[str, Any]:
        """
        Создать handler для приёма соединений
        
        Args:
            payload: Тип payload (например: windows/meterpreter/reverse_tcp)
            lhost: Локальный IP для приёма соединений
            lport: Локальный порт
        """
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            handler = self.client.modules.use('exploit', 'multi/handler')
            handler['PAYLOAD'] = payload
            handler['LHOST'] = lhost
            handler['LPORT'] = lport
            
            job = handler.execute(payload=payload)
            
            return {
                "success": True,
                "message": "Handler создан",
                "payload": payload,
                "lhost": lhost,
                "lport": lport,
                "job_id": job.get('job_id')
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_payload(self, payload_type: str, lhost: str, lport: int, 
                              format_type: str = "exe") -> Dict[str, Any]:
        """
        Сгенерировать payload (только информация о команде)
        
        Args:
            payload_type: Тип payload
            lhost: IP для обратного соединения
            lport: Порт
            format_type: Формат (exe, elf, raw, python, etc.)
        """
        # Не генерируем реальный payload, только команду
        command = f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f {format_type}"
        
        return {
            "success": True,
            "message": "Команда для генерации payload",
            "command": command,
            "warning": "⚠️ Используйте только для авторизованного тестирования!"
        }

    async def list_jobs(self) -> Dict[str, Any]:
        """Список активных задач"""
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            jobs = self.client.jobs.list
            
            return {
                "success": True,
                "total_jobs": len(jobs),
                "jobs": jobs
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def kill_job(self, job_id: int) -> Dict[str, Any]:
        """Остановить задачу"""
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            result = self.client.jobs.stop(str(job_id))
            return {"success": True, "message": f"Задача {job_id} остановлена"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def db_hosts(self) -> Dict[str, Any]:
        """Список хостов в базе данных MSF"""
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            hosts = self.client.db.hosts
            
            formatted = []
            for host in hosts[:50]:  # Ограничение
                formatted.append({
                    "address": host.get('address', ''),
                    "mac": host.get('mac', ''),
                    "name": host.get('name', ''),
                    "os_name": host.get('os_name', ''),
                    "os_flavor": host.get('os_flavor', ''),
                    "state": host.get('state', '')
                })
            
            return {
                "success": True,
                "total_hosts": len(hosts),
                "hosts": formatted
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def db_services(self, host: str = None) -> Dict[str, Any]:
        """Список сервисов в базе данных"""
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            if host:
                services = self.client.db.services(host=host)
            else:
                services = self.client.db.services
            
            formatted = []
            for svc in services[:100]:
                formatted.append({
                    "host": svc.get('host', ''),
                    "port": svc.get('port', ''),
                    "proto": svc.get('proto', ''),
                    "name": svc.get('name', ''),
                    "state": svc.get('state', ''),
                    "info": svc.get('info', '')
                })
            
            return {
                "success": True,
                "total_services": len(services),
                "services": formatted
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def db_vulns(self, host: str = None) -> Dict[str, Any]:
        """Список уязвимостей в базе данных"""
        if not self._check_connection():
            return {"success": False, "error": "Не подключено к Metasploit"}
        
        try:
            if host:
                vulns = self.client.db.vulns(host=host)
            else:
                vulns = self.client.db.vulns
            
            formatted = []
            for vuln in vulns[:50]:
                formatted.append({
                    "host": vuln.get('host', ''),
                    "name": vuln.get('name', ''),
                    "refs": vuln.get('refs', [])[:5],
                    "info": vuln.get('info', '')[:200]
                })
            
            return {
                "success": True,
                "total_vulns": len(vulns),
                "vulnerabilities": formatted
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _check_connection(self) -> bool:
        """Проверка подключения"""
        return self.connected and self.client is not None

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Обработка MCP запроса"""
        
        if request.get("method") == "tools/list":
            return {
                "result": {
                    "tools": await self._get_tools_list()
                }
            }
        
        elif request.get("method") == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            try:
                result = await self._call_tool(tool_name, arguments)
                return {
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": json.dumps(result, indent=2, ensure_ascii=False)
                        }]
                    }
                }
            except Exception as e:
                return {
                    "error": {
                        "code": -32000,
                        "message": str(e)
                    }
                }
        
        return {"error": {"code": -32601, "message": "Method not found"}}

    async def _get_tools_list(self) -> List[Dict[str, Any]]:
        """Список доступных инструментов"""
        return [
            {
                "name": "msf_connect",
                "description": "Подключиться к Metasploit RPC серверу",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "msf_disconnect",
                "description": "Отключиться от Metasploit RPC",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "msf_search",
                "description": "Поиск модулей Metasploit (эксплойты, auxiliary, post)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Поисковый запрос (CVE, платформа, сервис)"
                        },
                        "module_type": {
                            "type": "string",
                            "description": "Тип модуля: exploit, auxiliary, post, payload, all",
                            "default": "all"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "msf_module_info",
                "description": "Получить подробную информацию о модуле",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "module_path": {
                            "type": "string",
                            "description": "Путь модуля (например: exploit/windows/smb/ms17_010_eternalblue)"
                        }
                    },
                    "required": ["module_path"]
                }
            },
            {
                "name": "msf_sessions",
                "description": "Список активных сессий Meterpreter/Shell",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "msf_session_cmd",
                "description": "Выполнить безопасную команду в сессии",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "integer",
                            "description": "ID сессии"
                        },
                        "command": {
                            "type": "string",
                            "description": "Команда (только из белого списка)"
                        }
                    },
                    "required": ["session_id", "command"]
                }
            },
            {
                "name": "msf_create_handler",
                "description": "Создать handler для приёма обратных соединений",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Тип payload"
                        },
                        "lhost": {
                            "type": "string",
                            "description": "Локальный IP"
                        },
                        "lport": {
                            "type": "integer",
                            "description": "Локальный порт"
                        }
                    },
                    "required": ["payload", "lhost", "lport"]
                }
            },
            {
                "name": "msf_generate_payload_cmd",
                "description": "Получить команду msfvenom для генерации payload",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload_type": {
                            "type": "string",
                            "description": "Тип payload"
                        },
                        "lhost": {
                            "type": "string",
                            "description": "IP для обратного соединения"
                        },
                        "lport": {
                            "type": "integer",
                            "description": "Порт"
                        },
                        "format_type": {
                            "type": "string",
                            "description": "Формат вывода",
                            "default": "exe"
                        }
                    },
                    "required": ["payload_type", "lhost", "lport"]
                }
            },
            {
                "name": "msf_jobs",
                "description": "Список активных задач",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "msf_kill_job",
                "description": "Остановить задачу",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {
                            "type": "integer",
                            "description": "ID задачи"
                        }
                    },
                    "required": ["job_id"]
                }
            },
            {
                "name": "msf_db_hosts",
                "description": "Список хостов в базе данных Metasploit",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "msf_db_services",
                "description": "Список сервисов в базе данных",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Фильтр по хосту (опционально)"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "msf_db_vulns",
                "description": "Список уязвимостей в базе данных",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Фильтр по хосту (опционально)"
                        }
                    },
                    "required": []
                }
            }
        ]

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Вызов инструмента"""
        
        tool_mapping = {
            "msf_connect": lambda: self.connect(),
            "msf_disconnect": lambda: self.disconnect(),
            "msf_search": lambda: self.search_modules(
                arguments.get("query", ""),
                arguments.get("module_type", "all")
            ),
            "msf_module_info": lambda: self.get_module_info(
                arguments.get("module_path", "")
            ),
            "msf_sessions": lambda: self.list_sessions(),
            "msf_session_cmd": lambda: self.session_command(
                arguments.get("session_id"),
                arguments.get("command", "")
            ),
            "msf_create_handler": lambda: self.create_handler(
                arguments.get("payload", ""),
                arguments.get("lhost", ""),
                arguments.get("lport", 4444)
            ),
            "msf_generate_payload_cmd": lambda: self.generate_payload(
                arguments.get("payload_type", ""),
                arguments.get("lhost", ""),
                arguments.get("lport", 4444),
                arguments.get("format_type", "exe")
            ),
            "msf_jobs": lambda: self.list_jobs(),
            "msf_kill_job": lambda: self.kill_job(arguments.get("job_id")),
            "msf_db_hosts": lambda: self.db_hosts(),
            "msf_db_services": lambda: self.db_services(arguments.get("host")),
            "msf_db_vulns": lambda: self.db_vulns(arguments.get("host"))
        }
        
        if tool_name in tool_mapping:
            return await tool_mapping[tool_name]()
        else:
            return {"success": False, "error": f"Неизвестный инструмент: {tool_name}"}


async def main():
    """Главная точка входа MCP сервера"""
    logger.info("🚀 Запуск Metasploit MCP Server...")
    logger.info("⚠️  ВНИМАНИЕ: Используйте только для авторизованного тестирования!")
    
    server = MetasploitMCPServer()
    
    try:
        while True:
            try:
                # Читаем JSON из stdin
                line = await asyncio.get_event_loop().run_in_executor(
                    None, sys.stdin.readline
                )
                
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # Парсим запрос
                try:
                    request = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {e}")
                    continue
                
                # Обрабатываем запрос
                response = await server.handle_request(request)
                
                # Добавляем JSON-RPC поля
                if "id" in request:
                    response["jsonrpc"] = "2.0"
                    response["id"] = request["id"]
                
                # Отправляем ответ
                print(json.dumps(response, ensure_ascii=False), flush=True)
                
            except KeyboardInterrupt:
                logger.info("Сервер остановлен пользователем")
                break
            except Exception as e:
                logger.error(f"Ошибка обработки запроса: {e}")
                
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
