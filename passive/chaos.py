from typing import List, Optional
from passive.base import PassiveSource
from utils.http_client import HTTPClient


class Chaos(PassiveSource):


    def __init__(self, api_key: Optional[str] = None, header_name: str = "Authorization"):
        super().__init__("chaos")
        self.api_key = api_key
        self.header_name = header_name
        self.requires_api_key = True

    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:

        if not self.api_key:
            raise ValueError("Chaos source requires an API key. Provide it when constructing Chaos(...)")

        subdomains = []
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"

        headers = {self.header_name: f"Bearer {self.api_key}"} if self.header_name.lower() == "authorization" else {self.header_name: self.api_key}

        try:
            data = await http_client.get_json(url, headers=headers)
            if data and isinstance(data, dict) and "subdomains" in data:
                for sd in data["subdomains"]:
                    if not isinstance(sd, str):
                        continue
                    if "." in sd:
                        subdomains.append(sd)
                    else:
                        subdomains.append(f"{sd}.{domain}")

            elif isinstance(data, list):
                for sd in data:
                    if not isinstance(sd, str):
                        continue
                    if "." in sd:
                        subdomains.append(sd)
                    else:
                        subdomains.append(f"{sd}.{domain}")

            else:
                try:
                    for item in (data or []):
                        if isinstance(item, str):
                            if "." in item:
                                subdomains.append(item)
                            else:
                                subdomains.append(f"{item}.{domain}")
                except Exception:
                    pass

        except Exception as exc:
            print(f"[chaos] warning: error while querying Chaos API: {exc}")
            return []

        normalized = set()
        for s in subdomains:
            s = s.strip().lower()
            if s.endswith(f".{domain.lower()}"):
                normalized.add(s)
        return sorted(normalized)
