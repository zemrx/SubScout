import aiohttp
import asyncio
from typing import Optional, Dict, Any
from config import get_config

class HTTPClient:
    
    def __init__(self):
        self.config = get_config()
        self.session: Optional[aiohttp.ClientSession] = None
        self.timeout = aiohttp.ClientTimeout(total=self.config.get_http_timeout())
    
    async def __aenter__(self):
        headers = {'User-Agent': self.config.get_user_agent()}
        self.session = aiohttp.ClientSession(headers=headers, timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        retry: Optional[int] = None
    ) -> Optional[str]:
        if retry is None:
            retry = self.config.get_retry_attempts()
        
        for attempt in range(retry + 1):
            try:
                async with self.session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        return await response.text()
                    elif response.status == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retry:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                return None
        
        return None
    
    async def get_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        retry: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:

        if retry is None:
            retry = self.config.get_retry_attempts()
        
        for attempt in range(retry + 1):
            try:
                async with self.session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retry:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                return None
        
        return None
    
    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        retry: Optional[int] = None
    ) -> Optional[str]:

        if retry is None:
            retry = self.config.get_retry_attempts()
        
        for attempt in range(retry + 1):
            try:
                async with self.session.post(url, data=data, json=json, headers=headers) as response:
                    if response.status == 200:
                        return await response.text()
                    elif response.status == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retry:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                return None
        
        return None
