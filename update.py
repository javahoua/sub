import time
import json
import jdatetime
import pytz
from datetime import datetime, timedelta
import os
import base64
import re
import dns.resolver
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
from telethon import TelegramClient
from telethon.errors import (
    ChannelPrivateError,
    ChannelInvalidError,
    UsernameInvalidError,
    UsernameNotOccupiedError,
    FloodWaitError,
)
from telethon.sessions import StringSession
from validator import validate
from threading import Lock
import asyncio

dns_lock = Lock()

resolver = dns.resolver.Resolver()

resolver.nameservers = [
    "1.1.1.1",    # Cloudflare
    "8.8.8.8",    # Google
    "9.9.9.9"     # Quad9 
]

resolver.lifetime = 6
resolver.timeout = 2

CHANNEL_OUTPUT_DIR = "channels"
os.makedirs(CHANNEL_OUTPUT_DIR, exist_ok=True)

SUB_OUTPUT_DIR = "sub"
os.makedirs(SUB_OUTPUT_DIR, exist_ok=True)

API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
SESSION = os.environ["TG_SESSION"]

client = TelegramClient(
    StringSession(SESSION),
    API_ID,
    API_HASH
)

# =========================
# CONFIG (EDIT THIS ONLY)
# =========================
CHANNELS = {
    
    -1003744627358: {"limit": 500, "name": "persianvpnhub"},
    -1001268460826: {"limit": 150, "name": "prrofile_purple" },
    -1001836809801: {"limit": 1000, "name": "FreakConfig" },
    
}

CHANNEL_ACTIVITY_DAYS = 3
DNS_WORKERS = 32
MAX_FILENAME_LENGTH = 100
LIMIT_MODE = "UNIQUE"  # MESSAGES or CONFIGS or UNIQUE
CONFIGS_MODE_MAX_MESSAGES_SCAN_BEFORE_EXHAUSTION = 2500
UNIQUE_MODE_MAX_MESSAGES_SCAN_BEFORE_EXHAUSTION = 3500
DNS_CACHE_TTL = 30 * 24 * 60 * 60   # 30 days
CHANNEL_WORKERS = 5
# =========================

PATTERN = re.compile(
    r'((?:vmess|vless|trojan|ss|ssr|hy2|hysteria|tuic)://\S+)'
)

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4",
    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

def collect_domains(configs):

    domains = set()

    for config in configs:

        try:
            parts = urlsplit(config)

            if parts.scheme.lower() == "vmess":

                obj = json.loads(
                    base64.urlsafe_b64decode(parts.netloc + "===")
                )

                values = [
                    obj.get("add", ""),
                    obj.get("host", ""),
                    obj.get("sni", "")
                ]

            else:

                params = dict(parse_qsl(parts.query))

                values = [
                    parts.hostname or "",
                    params.get("host", ""),
                    params.get("sni", "")
                ]

            for value in values:

                if not value:
                    continue

                value = value.strip().lower().rstrip(".")

                if "." in value and not value.endswith(".ir"):

                    try:
                        ipaddress.ip_address(value.strip("[]"))
                        continue   # skip all IP addresses
                    except ValueError:
                        pass

                    domains.add(value)

        except Exception:
            pass

    return domains

def remove_ech_parameter(config):
    """
    Remove only the ech query parameter from proxy URLs.
    Keeps everything else unchanged.
    """

    try:
        parts = urlsplit(config)

        if not parts.query:
            return config

        params = parse_qsl(parts.query, keep_blank_values=True)

        params = [
            (key, value)
            for key, value in params
            if key.lower() != "ech"
        ]

        new_query = urlencode(params)

        return urlunsplit((
            parts.scheme,
            parts.netloc,
            parts.path,
            new_query,
            parts.fragment
        ))

    except Exception:
        return config

def sanitize_filename(name):
    if not name:
        return "unnamed"

    # remove invalid Windows filename characters
    invalid = '<>:"/\\|?*'

    name = "".join(
        c for c in name
        if c not in invalid and ord(c) >= 32
    )

    # trim spaces and trailing dots
    name = name.strip().rstrip(".")

    # prevent empty filename
    if not name:
        return "unnamed"

    # Windows reserved names
    if name.upper() in WINDOWS_RESERVED_NAMES:
        name += "_"

    # cap length
    if len(name) > MAX_FILENAME_LENGTH:
        name = name[:MAX_FILENAME_LENGTH]

    name = name.rstrip(" .")
    
    return name

def extract_configs(text):
    if not text:
        return []

    configs = []

    for config in PATTERN.findall(text):
        config = config.rstrip("`")      # Remove trailing backticks
        config = config.replace("`", "") # Remove any remaining backticks
        configs.append(config)

    return configs
    
def normalize_config(config: str) -> str:
    """
    Normalize a config for duplicate detection.

    Removes:
      - remark (#...)
      - backticks
      - whitespace

    Canonicalizes:
      - query parameter order

    Keeps:
      - protocol
      - host/IP
      - port
      - path
      - sni
      - host
      - uuid/password
      - every functional parameter
    """

    config = config.replace("`", "").strip()

    parts = urlsplit(config)

    # Parse query parameters and sort them alphabetically
    params = parse_qsl(parts.query, keep_blank_values=True)
    params = [
    (k, v.lower() if k.lower() in ("host", "sni") else v)
    for k, v in params
    ]
    params.sort()

    normalized_query = urlencode(params)

    # Remove remark (#...)
    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        normalized_query,
        ""
    ))
    
def deduplicate_configs(configs):
    seen = set()
    result = []

    for config in configs:
        key = normalize_config(config)

        if key not in seen:
            seen.add(key)
            result.append(config)

    return result

def add_unique_config(config, configs, seen):
    key = normalize_config(config)

    if key in seen:
        return False

    seen.add(key)
    configs.append(config)

    return True

def load_ir_networks_ripe():
    url = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"

    networks = []

    with urllib.request.urlopen(url, timeout=20) as r:
        text = r.read().decode("utf-8")

    for line in text.splitlines():

        if line.startswith("#"):
            continue

        parts = line.split("|")

        if len(parts) < 7:
            continue

        registry, cc, typ, start, value = parts[:5]

        cc = cc.strip().upper()
        typ = typ.strip().lower()

        if cc != "IR":
            continue

        if typ not in ("ipv4", "ipv6"):
            continue

        if typ == "ipv4":
            network = ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start),
                ipaddress.IPv4Address(
                    int(ipaddress.IPv4Address(start)) + int(value) - 1
                )
            )
        else:
            network = [
                ipaddress.ip_network(f"{start}/{value}")
            ]

        networks.extend(network)

    return networks
    
def load_ir_networks_ipdeny():
    url = "https://www.ipdeny.com/ipblocks/data/countries/ir.zone"

    with urllib.request.urlopen(url, timeout=20) as r:
        return [
            ipaddress.ip_network(line.decode().strip())
            for line in r
            if line.strip()
        ]
        
def load_ir_networks_local():
    networks = []

    with open("ir-range.txt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            networks.append(
                ipaddress.ip_network(line)
            )

    return networks

DNS_CACHE_FILE = "dns_cache.json"
DNS_CACHE = {}

if os.path.exists(DNS_CACHE_FILE):
    try:
        with open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
            DNS_CACHE = json.load(f)

            for domain, value in list(DNS_CACHE.items()):
                if isinstance(value, bool):
                    DNS_CACHE[domain] = {
                        "is_ir": value,
                        "checked": time.time()
                    }
        print(f"Loaded {len(DNS_CACHE)} cached DNS entries")
    except Exception:
        DNS_CACHE = {}

IR_NETWORK_SOURCE = None

try:
    IR_NETWORKS = load_ir_networks_ripe()

    if not IR_NETWORKS:
        raise Exception("RIPE returned zero networks")

    IR_NETWORK_SOURCE = "RIPE NCC"

except Exception:
    try:
        IR_NETWORKS = load_ir_networks_ipdeny()

        if not IR_NETWORKS:
            raise Exception("IPDeny returned zero networks")

        IR_NETWORK_SOURCE = "IPDeny"

    except Exception:
        IR_NETWORKS = load_ir_networks_local()
        IR_NETWORK_SOURCE = "local ir-range.txt"

def is_iran_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return any(ip in net for net in IR_NETWORKS)
    
def resolves_to_iran_ip(hostname):
    try:
        answers = resolver.resolve(hostname, "A")    #IPv4 only

        for answer in answers:
            if is_iran_ip(answer.to_text()):
                return True

    except Exception:
        pass

    return False
    
def is_iran_host(value):
    if not value:
        return False

    value = value.strip().rstrip(".").lower()

    # direct IP check
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
        return is_iran_ip(str(ip))
    except ValueError:
        pass

    # .ir domains are always considered Iranian
    if value.endswith(".ir"):
        return True

    if "." in value:

        entry = DNS_CACHE.get(value)

        if entry is None:
            result = resolves_to_iran_ip(value)

            with dns_lock:
                DNS_CACHE[value] = {
                    "is_ir": result,
                    "checked": time.time()
                }

            return result

        return entry["is_ir"]

    return False
   
    
def config_iran_flags(config):
    """
    Returns:
        (is_ir, server_is_ir)
    """

    try:
        parts = urlsplit(config)
        scheme = parts.scheme.lower()

        if scheme == "vmess":
            obj = json.loads(
                base64.urlsafe_b64decode(parts.netloc + "===")
            )

            server = obj.get("add", "")
            server_is_ir = is_iran_host(server)

            if server_is_ir:
                return True, True

            for key in ("host", "sni"):
                if is_iran_host(obj.get(key, "")):
                    return True, False

            return False, False

        params = dict(parse_qsl(parts.query))

        server = parts.hostname or ""
        server_is_ir = is_iran_host(server)

        if server_is_ir:
            return True, True

        for key in ("host", "sni"):
            if is_iran_host(params.get(key, "")):
                return True, False

    except Exception:
        pass

    return False, False
    

channel_lock = Lock()


async def process_channel(channel_ref, info, cutoff, tehran):

    channel_start = time.time()

    try:
        if isinstance(info, int):
            limit = info
            custom_name = None
        else:
            limit = int(info["limit"])
            custom_name = info.get("name")

        entity = await client.get_entity(channel_ref)

        if getattr(entity, "username", None):
            channel_display = entity.username
        else:
            channel_display = entity.title

        channel_configs = []
        latest_config_date = None


        if LIMIT_MODE == "MESSAGES":

            async for msg in client.iter_messages(entity, limit=limit):

                configs = extract_configs(msg.text)

                if configs:
                    channel_configs.extend(configs)

                    if latest_config_date is None:
                        latest_config_date = msg.date.astimezone(tehran)


        elif LIMIT_MODE == "CONFIGS":

            async for msg in client.iter_messages(
                entity,
                limit=CONFIGS_MODE_MAX_MESSAGES_SCAN_BEFORE_EXHAUSTION
            ):

                configs = extract_configs(msg.text)

                if configs:
                    channel_configs.extend(configs)

                    if latest_config_date is None:
                        latest_config_date = msg.date.astimezone(tehran)

                if len(channel_configs) >= limit:
                    break


        elif LIMIT_MODE == "UNIQUE":

            seen_configs = set()

            async for msg in client.iter_messages(
                entity,
                limit=UNIQUE_MODE_MAX_MESSAGES_SCAN_BEFORE_EXHAUSTION
            ):

                configs = extract_configs(msg.text)

                if configs:

                    if latest_config_date is None:
                        latest_config_date = msg.date.astimezone(tehran)

                    for cfg in configs:
                        add_unique_config(
                            cfg,
                            channel_configs,
                            seen_configs
                        )

                        if len(channel_configs) >= limit:
                            break

                if len(channel_configs) >= limit:
                    break


        channel_configs = channel_configs[:limit]

        channel_configs = [
            cfg for cfg in channel_configs
            if validate(cfg)
        ]

        channel_configs = deduplicate_configs(channel_configs)


        # filename
        if custom_name:
            filename = custom_name
        elif getattr(entity, "username", None):
            filename = entity.username
        else:
            filename = str(entity.id)

        filename = sanitize_filename(filename)

        with open(
            os.path.join(CHANNEL_OUTPUT_DIR, f"{filename}.txt"),
            "w",
            encoding="utf-8"
        ) as f:
            f.write("\n".join(channel_configs))


        active = (
            latest_config_date is not None
            and latest_config_date >= cutoff
        )


        print(
            f"{channel_display}: "
            f"{len(channel_configs)} configs "
            f"{'ACTIVE' if active else 'INACTIVE'} "
            f"({time.time()-channel_start:.2f}s)"
        )


        return {
            "display": channel_display,
            "configs": channel_configs,
            "stats": {
                "configs": len(channel_configs),
                "active": active,
                "last_config": (
                    jdatetime.datetime.fromgregorian(
                        datetime=latest_config_date
                    ).strftime("%Y/%m/%d %H:%M")
                    if latest_config_date else None
                )
            }
        }


    except (
        ChannelPrivateError,
        ChannelInvalidError,
        UsernameInvalidError,
        UsernameNotOccupiedError,
        ValueError,
        TypeError,
        FloodWaitError,
    ) as e:
        print(f"Skipping {channel_ref}: {type(e).__name__}: {e}")
        return None

    except Exception as e:
        print(
            f"Unexpected error in {channel_ref}: "
            f"{type(e).__name__}: {e}"
        )
        return None

async def main():
    
    start = time.time() ##might remove later

    all_configs = []
    channel_stats = {}
    tehran = pytz.timezone("Asia/Tehran")
    
    telegram_start = time.time() ##might remove later
    
    cutoff = datetime.now(tehran) - timedelta(days=CHANNEL_ACTIVITY_DAYS)
    
    sem = asyncio.Semaphore(CHANNEL_WORKERS)


    async def limited_process(channel_ref, info):

        async with sem:
            return await process_channel(
                channel_ref,
                info,
                cutoff,
                tehran
            )


    tasks = [
        limited_process(channel_ref, info)
        for channel_ref, info in CHANNELS.items()
    ]


    results = await asyncio.gather(*tasks)


    for result in results:

        if result is None:
            continue

        channel_display = result["display"]

        channel_stats[channel_display] = result["stats"]

        if result["stats"]["active"]:
            all_configs.extend(result["configs"])
        else:
            print(f"{channel_display}: INACTIVE (not merged)")


    # global dedupe
    
    print(f"Telegram processing took {time.time()-telegram_start:.2f}s") ##might remove later
    
    x = time.time() ##might remove later
    merged = deduplicate_configs(all_configs)
    print(f"Global dedupe took {time.time()-x:.2f}s") ##might remove later
    
    x = time.time() ##might remove later
    domains = collect_domains(merged)
    print(f"collect_domains took {time.time()-x:.2f}s") ##might remove later
    
    x = time.time() ##might remove later
    
    now = time.time()

    new_domains = []

    for domain in domains:
        entry = DNS_CACHE.get(domain)

        if entry is None:
            new_domains.append(domain)
            continue

        if now - entry["checked"] > DNS_CACHE_TTL:
            new_domains.append(domain)

    print(f"Unique domains found: {len(domains)}")
    print(f"Cached domains      : {len(DNS_CACHE)}")
    print(f"New domains         : {len(new_domains)}")

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:

        dns_results = executor.map(
            lambda d: (d, resolves_to_iran_ip(d)),
            new_domains
        )

        now = time.time()

        for domain, result in dns_results:
            with dns_lock:
                DNS_CACHE[domain] = {
                    "is_ir": result,
                    "checked": now
                }
            
    print(f"DNS lookup took {time.time()-x:.2f}s") ##might remove later
    
    x = time.time() ##might remove later
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:

        ir_results = executor.map(config_iran_flags, merged)

        ir_configs = []
        ir_actual_configs = []
        ir_configs_echless = []

        for cfg, (is_ir, server_is_ir) in zip(merged, ir_results):
            if is_ir:
                ir_configs.append(cfg)
                ir_configs_echless.append(remove_ech_parameter(cfg))

            if server_is_ir:
                ir_actual_configs.append(cfg)
    print(f"config_iran_flags took {time.time()-x:.2f}s") ##might remove later
    
    if new_domains:
        with open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(DNS_CACHE, f, indent=2, sort_keys=True)
    
    # create sub (base64)
    write_start = time.time() ##might remove later
    def write_subscription(filename, configs):
        encoded = base64.b64encode(
            "\n".join(configs).encode()
        ).decode()

        with open(filename, "w", encoding="utf-8") as f:
            f.write(encoded)
            
    def write_plaintext(filename, configs):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(configs))

    write_subscription(os.path.join(SUB_OUTPUT_DIR, "sub-full-base64.txt"), merged)
    write_subscription(os.path.join(SUB_OUTPUT_DIR, "sub-medium-base64.txt"), merged[:1500])
    write_subscription(os.path.join(SUB_OUTPUT_DIR, "sub-lite-base64.txt"), merged[:750])
    write_subscription(os.path.join(SUB_OUTPUT_DIR, "sub-tiny-base64.txt"), merged[:300])

    merged_echless = [
        remove_ech_parameter(cfg)
        for cfg in merged
    ]

    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "sub-full-plaintxt.txt"), merged)
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "sub-full-plaintxt-echless.txt"), merged_echless)
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "sub-medium-plaintxt.txt"), merged[:1500])
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "sub-lite-plaintxt.txt"), merged[:750])
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "sub-tiny-plaintxt.txt"), merged[:300])
    
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "ir.txt"), ir_configs)
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "ir-echless.txt"), ir_configs_echless)
    write_plaintext(os.path.join(SUB_OUTPUT_DIR, "ir-actual.txt"), ir_actual_configs)

    now = datetime.now(tehran)
    jalali = jdatetime.datetime.fromgregorian(datetime=now)

    stats = {
        "updated": jalali.strftime("%Y/%m/%d %H:%M"),
        "ir_filter": {
            "source": IR_NETWORK_SOURCE,
            "cidr_network_count": len(IR_NETWORKS),
            "ipv4_network_count": sum(
                1 for n in IR_NETWORKS
                if isinstance(n, ipaddress.IPv4Network)
            ),
            "ipv6_network_count": sum(
                1 for n in IR_NETWORKS
                if isinstance(n, ipaddress.IPv6Network)
            ),
        },
        "subscriptions": {
            "sub-full": len(merged),
            "sub-medium": min(1500, len(merged)),
            "sub-lite": min(750, len(merged)),
            "sub-tiny": min(300, len(merged)),
            "ir": len(ir_configs),
            "ir-actual": len(ir_actual_configs)
        },
        "channels": channel_stats
    }

    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)

        print(f"TOTAL UNIQUE CONFIGS: {len(merged)}")

        commit_message = (
            f"Update subscription | "
            f"{jalali.strftime('%Y/%m/%d %H:%M')}"
        )
    
    print(f"Writing files took {time.time()-write_start:.2f}s") ##might remove later
    with open("commit_message.txt", "w", encoding="utf-8") as f:
        f.write(commit_message)
    print(f"TOTAL update.py runtime: {time.time()-start:.2f}s") ##might remove later


with client:
    client.loop.run_until_complete(main())
