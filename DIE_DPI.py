import asyncio
import logging
import socket
import struct
import threading
from datetime import datetime
from typing import Dict, Set, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import web, ClientResponse

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dpi_bypass.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FragmentedTCPProxy:
    """Прокси с фрагментацией TLS рукопожатия"""
    
    def __init__(self, listen_port=8080, fragment_size=200):
        self.listen_port = listen_port
        self.fragment_size = fragment_size
        self.bypass_active = False
        self.failed_hosts: Set[str] = set()
        self.proxy_server = None
        self.runner = None
        self.app = None
        
        # Целевые ресурсы для мониторинга
        self.targets = [
            'https://www.youtube.com',
            'https://discord.com',
            'https://github.com',
            'https://www.google.com'
        ]
        
    async def check_access(self, url: str) -> tuple[bool, float]:
        """Проверка доступности через прямой запрос"""
        try:
            start = datetime.now()
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    latency = (datetime.now() - start).total_seconds()
                    return resp.status == 200, latency
        except Exception as e:
            logger.debug(f"Check failed for {url}: {e}")
            return False, 0
    
    async def monitor_resources(self):
        """Мониторинг доступности ресурсов"""
        while True:
            for url in self.targets:
                accessible, latency = await self.check_access(url)
                host = urlparse(url).netloc
                
                if not accessible:
                    if host not in self.failed_hosts:
                        self.failed_hosts.add(host)
                        logger.warning(f"НЕДОСТУПЕН: {host}")
                        
                        if not self.bypass_active:
                            await self.enable_bypass()
                else:
                    if host in self.failed_hosts:
                        self.failed_hosts.remove(host)
                        logger.info(f"ВОССТАНОВЛЕН: {host} ({latency:.2f}с)")
                        
                        if len(self.failed_hosts) == 0 and self.bypass_active:
                            await self.disable_bypass()
                    else:
                        logger.debug(f"Доступен: {host} ({latency:.2f}с)")
            
            await asyncio.sleep(30)
    
    def fragment_tls_packet(self, data: bytes) -> list[bytes]:
        """Фрагментация TLS ClientHello для обхода DPI"""
        if not data or len(data) < 50:
            return [data]
        
        # Проверяем, является ли это TLS handshake (Content Type 22)
        if len(data) > 0 and data[0] == 0x16:  # TLS handshake
            fragments = []
            offset = 0
            
            while offset < len(data):
                chunk = data[offset:offset + self.fragment_size]
                
                # Для первого фрагмента ClientHello делаем дополнительную фрагментацию
                if offset == 0 and len(chunk) > 100:
                    sub_fragments = [
                        chunk[:40],
                        chunk[40:80],
                        chunk[80:]
                    ]
                    fragments.extend([f for f in sub_fragments if f])
                else:
                    fragments.append(chunk)
                
                offset += self.fragment_size
            
            return fragments
        
        return [data]
    
    async def handle_proxy_request(self, request):
        """Обработка проксируемого запроса с фрагментацией"""
        try:
            target_url = str(request.url)
            method = request.method
            headers = dict(request.headers)
            
            # Удаляем прокси-заголовки
            headers.pop('Proxy-Connection', None)
            headers.pop('Proxy-Authorization', None)
            
            body = await request.read()
            
            # Для HTTPS используем CONNECT метод
            if target_url.startswith('https'):
                return await self.handle_connect(request)
            
            # Для HTTP делаем обычный прокси-запрос
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.request(method, target_url, headers=headers, data=body) as resp:
                    response_body = await resp.read()
                    
                    response_headers = dict(resp.headers)
                    response_headers.pop('Transfer-Encoding', None)
                    response_headers.pop('Content-Encoding', None)
                    
                    return web.Response(
                        status=resp.status,
                        headers=response_headers,
                        body=response_body
                    )
                    
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return web.Response(status=502, text=f"Proxy error: {str(e)}")
    
    async def handle_connect(self, request):
        """Обработка CONNECT метода для HTTPS с фрагментацией TLS"""
        try:
            host_port = request.path.lstrip('/')
            host, port = host_port.split(':')
            port = int(port)
            
            # Устанавливаем соединение с целевым сервером
            reader, writer = await asyncio.open_connection(host, port)
            
            # Отправляем ответ об установке соединения
            resp = web.Response(status=200, reason='Connection Established')
            await resp.prepare(request)
            await resp.write_eof()
            
            # Создаем задачи для двунаправленной передачи данных
            async def forward_client_to_server():
                try:
                    while True:
                        data = await request.content.read(8192)
                        if not data:
                            break
                        
                        # Фрагментируем только TLS пакеты
                        if len(data) > 0 and data[0] == 0x16:  # TLS handshake
                            fragments = self.fragment_tls_packet(data)
                            for frag in fragments:
                                writer.write(frag)
                                await writer.drain()
                                await asyncio.sleep(0.005)  # Небольшая задержка между фрагментами
                        else:
                            writer.write(data)
                            await writer.drain()
                except Exception as e:
                    logger.debug(f"Client to server forward error: {e}")
                finally:
                    writer.close()
                    await writer.wait_closed()
            
            async def forward_server_to_client():
                try:
                    while True:
                        data = await reader.read(8192)
                        if not data:
                            break
                        await request.writer.write(data)
                        await request.writer.drain()
                except Exception as e:
                    logger.debug(f"Server to client forward error: {e}")
            
            # Запускаем обе задачи параллельно
            task1 = asyncio.create_task(forward_client_to_server())
            task2 = asyncio.create_task(forward_server_to_client())
            
            # Ждем завершения любой из задач
            done, pending = await asyncio.wait(
                [task1, task2],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Отменяем оставшиеся задачи
            for task in pending:
                task.cancel()
                
            return web.Response()
            
        except Exception as e:
            logger.error(f"CONNECT error: {e}")
            return web.Response(status=502, text=f"CONNECT error: {str(e)}")
    
    async def enable_bypass(self):
        """Включение обхода DPI"""
        if self.bypass_active:
            return
            
        logger.info("ВКЛЮЧЕНИЕ ОБХОДА DPI...")
        
        try:
            # Создаем приложение только один раз
            if self.app is None:
                self.app = web.Application()
                # Исправляем регистрацию маршрутов
                self.app.router.add_route('CONNECT', '/{path:.*}', self.handle_connect)
                self.app.router.add_route('*', '/{path:.*}', self.handle_proxy_request)
                
                self.runner = web.AppRunner(self.app)
                await self.runner.setup()
            
            # Запускаем сервер
            self.proxy_server = web.TCPSite(self.runner, '127.0.0.1', self.listen_port)
            await self.proxy_server.start()
            
            self.bypass_active = True
            logger.info(f"✅ ОБХОД DPI ВКЛЮЧЕН (прокси на порту {self.listen_port})")
            logger.info("   Метод: фрагментация TLS ClientHello")
            
            # Показываем инструкцию по настройке
            self.show_proxy_instructions()
            
        except Exception as e:
            logger.error(f"Ошибка включения обхода: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def show_proxy_instructions(self):
        """Показывает инструкцию по настройке прокси"""
        logger.info("")
        logger.info("ДЛЯ ИСПОЛЬЗОВАНИЯ:")
        logger.info(f"   Настрой прокси в программах: 127.0.0.1:{self.listen_port}")
        logger.info("")
        logger.info("   Chrome/Edge: запустите с флагом:")
        logger.info(f'   --proxy-server="http://127.0.0.1:{self.listen_port}"')
        logger.info("")
        logger.info("   Windows системный прокси:")
        logger.info(f"   Параметры → Сеть → Прокси → 127.0.0.1:{self.listen_port}")
        logger.info("")
    
    async def disable_bypass(self):
        """Отключение обхода DPI"""
        if not self.bypass_active:
            return
            
        logger.info("ОТКЛЮЧЕНИЕ ОБХОДА DPI...")
        
        try:
            if self.proxy_server:
                await self.proxy_server.stop()
                self.proxy_server = None
            
            self.bypass_active = False
            logger.info("ОБХОД DPI ОТКЛЮЧЕН")
            logger.info("   Не забудь отключить прокси в настройках программ!")
            
        except Exception as e:
            logger.error(f"Ошибка отключения обхода: {e}")
    
    async def cleanup(self):
        """Очистка ресурсов"""
        if self.runner:
            await self.runner.cleanup()
    
    async def run(self):
        """Запуск монитора"""
        logger.info("=" * 60)
        logger.info("DPI BYPASS MONITOR v2.0")
        logger.info("=" * 60)
        
        try:
            # Запускаем мониторинг
            await self.monitor_resources()
        finally:
            await self.cleanup()

async def main():
    monitor = FragmentedTCPProxy(listen_port=8080, fragment_size=200)
    
    try:
        await monitor.run()
    except KeyboardInterrupt:
        logger.info("\nОстановка программы...")
        if monitor.bypass_active:
            await monitor.disable_bypass()
        await monitor.cleanup()
        logger.info("Программа завершена")

if __name__ == "__main__":
    asyncio.run(main())