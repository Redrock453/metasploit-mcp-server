#!/usr/bin/env python3
"""
Тест подключения к Metasploit RPC
"""

import json
import os

def test_pymetasploit():
    """Тест импорта pymetasploit3"""
    print("🔍 Проверка pymetasploit3...")
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        print("✅ pymetasploit3 установлен")
        return True
    except ImportError:
        print("❌ pymetasploit3 не установлен")
        print("   Установите: pip install pymetasploit3")
        return False

def test_config():
    """Проверка конфигурации"""
    print("\n🔍 Проверка конфигурации...")
    config_file = os.path.join(os.path.dirname(__file__), 'msf_config.json')
    
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
        print(f"✅ Конфигурация загружена:")
        print(f"   Host: {config.get('host', 'N/A')}")
        print(f"   Port: {config.get('port', 'N/A')}")
        print(f"   SSL: {config.get('ssl', 'N/A')}")
        return config
    else:
        print("❌ Файл конфигурации не найден")
        return None

def test_connection(config):
    """Тест подключения к MSF RPC"""
    print("\n🔍 Тест подключения к Metasploit RPC...")
    
    if not config:
        print("❌ Конфигурация не загружена")
        return False
    
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        
        print(f"   Подключение к {config['host']}:{config['port']}...")
        
        client = MsfRpcClient(
            config['password'],
            server=config['host'],
            port=config['port'],
            ssl=config.get('ssl', True)
        )
        
        version = client.core.version
        print(f"✅ Подключено к Metasploit!")
        print(f"   Версия: {version.get('version', 'N/A')}")
        print(f"   Ruby: {version.get('ruby', 'N/A')}")
        print(f"   API: {version.get('api', 'N/A')}")
        
        # Тест базовых функций
        print("\n📊 Статистика:")
        
        # Модули
        exploits = len(client.modules.exploits)
        auxiliary = len(client.modules.auxiliary)
        payloads = len(client.modules.payloads)
        print(f"   Exploits: {exploits}")
        print(f"   Auxiliary: {auxiliary}")
        print(f"   Payloads: {payloads}")
        
        # Сессии
        sessions = client.sessions.list
        print(f"   Активных сессий: {len(sessions)}")
        
        # Jobs
        jobs = client.jobs.list
        print(f"   Активных задач: {len(jobs)}")
        
        return True
        
    except ConnectionRefusedError:
        print("❌ Соединение отклонено")
        print("   Убедитесь, что msfrpcd запущен:")
        print("   msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553")
        return False
        
    except Exception as e:
        print(f"❌ Ошибка подключения: {e}")
        return False

def main():
    print("=" * 50)
    print("🔴 METASPLOIT MCP SERVER - ТЕСТ ПОДКЛЮЧЕНИЯ")
    print("=" * 50)
    
    # Тест 1: pymetasploit3
    if not test_pymetasploit():
        return 1
    
    # Тест 2: Конфигурация
    config = test_config()
    
    # Тест 3: Подключение
    if config:
        if test_connection(config):
            print("\n" + "=" * 50)
            print("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
            print("   MCP сервер готов к работе")
            print("=" * 50)
            return 0
        else:
            print("\n" + "=" * 50)
            print("❌ ТЕСТ ПОДКЛЮЧЕНИЯ НЕ ПРОЙДЕН")
            print("=" * 50)
            return 1
    
    return 1

if __name__ == "__main__":
    exit(main())
