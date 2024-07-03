import aiohttp
import asyncio
import re

class ProxyFinder:
    def __init__(self, proxy_sources=None, test_url='http://httpbin.org/ip'):
        if proxy_sources is None:
            self.proxy_sources = [
                'https://www.sslproxies.org/',
                'https://free-proxy-list.net/',
                'https://www.proxynova.com/proxy-server-list/',
                'https://www.proxy-list.download/api/v1/get?type=https',
                'https://www.proxy-list.download/api/v1/get?type=http',
                'https://www.proxy-list.download/api/v1/get?type=socks4',
                'https://www.proxy-list.download/api/v1/get?type=socks5',
                'https://www.socks-proxy.net/',
                'https://www.proxysource.org/',
                'https://hidemy.name/en/proxy-list/',
                'https://www.socks-proxy.net/',
                'https://www.proxydocker.com/en/proxylist/country/US',
                'https://spys.one/en/',
                'https://www.freeproxylists.net/',
                'https://www.proxy-list.org/english/index.php',
                'https://www.us-proxy.org/',
                'https://proxyscrape.com/free-proxy-list',
                'https://www.proxyscan.io/',
                'https://www.proxydocker.com/en/proxylist/',
                'https://www.proxy-list.download/SOCKS5',
                'https://free-proxy-list.net/anonymous-proxy.html',
                'https://www.my-proxy.com/',
                'https://proxy-rack.com/',
                'https://www.proxyrack.com/proxy-lists/',
                'https://proxyscrape.com/',
                'https://premproxy.com/',
                'https://free-proxy.cz/',
                'https://free-proxy-list.net/uk-proxy.html',
                'https://free-proxy-list.net/anonymous-proxy.html',
                'https://www.proxy-list.net/anonymous-proxy-lists.shtml',
                'https://www.proxy-listen.de/Proxy/Proxyliste.html',
                'https://www.proxyserverlist24.top/',
                'https://www.proxy-daily.com/',
                'https://www.proxylists.net/',
                'https://www.proxyservers.pro/',
                'https://www.proxy-list.download/HTTP',
                'https://www.proxy-list.download/HTTPS',
                'https://www.proxy-list.download/SOCKS4',
                'https://www.proxy-list.download/SOCKS5',
                'https://www.proxyscrape.com/',
                'https://www.proxy-list.download/anonymous-proxy-list',
                'https://www.proxyscan.io/',
                'https://www.proxy-daily.com/',
                'https://www.proxy-listen.de/Proxy/Proxyliste.html',
                'https://www.proxyserverlist24.top/',
                'https://www.my-proxy.com/',
                'https://free-proxy-list.net/',
                'https://www.proxy-list.org/',
                'https://www.sslproxies.org/',
                'https://hidemy.name/en/proxy-list/',
                'https://www.socks-proxy.net/',
                'https://proxyscrape.com/free-proxy-list',
                'https://www.freeproxylists.net/',
                'https://spys.one/en/',
                'https://www.us-proxy.org/',
                'https://www.proxydocker.com/en/proxylist/',
                'https://checkerproxy.net/',
                'https://proxy-rack.com/',
                'https://www.proxyrack.com/proxy-lists/',
                'https://premproxy.com/'
            ]
        else:
            self.proxy_sources = proxy_sources

        self.test_url = test_url
        self.proxies = set()
        self.working_proxies = []

    async def fetch_proxies(self, session, url):
        tries = 3
        for attempt in range(tries):
            try:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        text = await response.text(errors='ignore')
                        proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', text)
                        self.proxies.update(proxies)
                        return
            except aiohttp.ClientError as e:
                pass  # Silently handle the error and continue

    async def check_proxy(self, session, proxy):
        proxy_url = f'http://{proxy}'
        try:
            async with session.get(self.test_url, proxy=proxy_url, timeout=20) as response:
                if response.status == 200:
                    self.working_proxies.append(proxy)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass  # Silently handle the error and continue

    async def find_proxies(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_proxies(session, url) for url in self.proxy_sources]
            await asyncio.gather(*tasks)

    async def check_proxies(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_proxy(session, proxy) for proxy in self.proxies]
            await asyncio.gather(*tasks)

    def remove_duplicates(self):
        self.working_proxies = list(set(self.working_proxies))

    async def run(self):
        await self.find_proxies()
        await self.check_proxies()
        self.remove_duplicates()

        # Output the working proxies
        print(f'Found {len(self.working_proxies)} working proxies:')
        for proxy in self.working_proxies:
            proxy_type = self.get_proxy_type(proxy)
            protocol = self.get_proxy_protocol(proxy)
            anonymity = await self.get_proxy_anonymity(proxy)  # Assuming you implement this method
            print(f'{proxy} - Type: {proxy_type}, Protocol: {protocol}, Anonymity: {anonymity}')

    async def get_proxy_anonymity(self, proxy):
        proxy_url = f'http://{proxy}'
        headers = {
            'X-Forwarded-For': '1.1.1.1',
            'Via': '1.1 proxy'
        }
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.test_url, proxy=proxy_url, headers=headers, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        origin = data.get('origin', '')
                        x_forwarded_for = data.get('headers', {}).get('X-Forwarded-For', '')
                        via = data.get('headers', {}).get('Via', '')

                        if x_forwarded_for and via:
                            return 'Transparent'
                        elif x_forwarded_for:
                            return 'Anonymous'
                        else:
                            return 'Elite'
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass  # Silently handle the error and continue
        return 'Unknown'

    def get_proxy_type(self, proxy):
        if proxy.startswith('http://'):
            return 'HTTP Proxy'
        elif proxy.startswith('https://'):
            return 'HTTPS Proxy'
        elif proxy.startswith('socks4://'):
            return 'SOCKS4 Proxy'
        elif proxy.startswith('socks5://'):
            return 'SOCKS5 Proxy'
        else:
            return 'Unknown'

    def get_proxy_protocol(self, proxy):
        if proxy.startswith('http://'):
            return 'HTTP'
        elif proxy.startswith('https://'):
            return 'HTTPS'
        elif proxy.startswith('socks4://') or proxy.startswith('socks5://'):
            return 'SOCKS'
        else:
            return 'Unknown'

if __name__ == '__main__':
    proxy_finder = ProxyFinder()
    asyncio.run(proxy_finder.run())
