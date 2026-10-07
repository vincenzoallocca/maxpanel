import json
import logging
import multiprocessing
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

logger = logging.getLogger("minecraft_scanner")
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO)

TIMEOUT = 2.5
PROTOCOL_VERSION = 767

@dataclass
class Player:
    name: str
    id: str

@dataclass
class Players:
    max: int
    online: int
    sample: Optional[List[Player]] = field(default_factory=list)

@dataclass
class Version:
    name: str
    protocol: int

@dataclass
class FinalResponse:
    players: Players
    version: Version
    description: str
    favicon: Optional[str] = None

    def __str__(self):
        cleaned_motd = strip_minecraft_formatting(self.description)
        cleaned_motd = cleaned_motd.replace('[[', '[').replace(']]', ']').strip()
        return f"({self.players.online}/{self.players.max})({self.version.name})({cleaned_motd})"

def strip_minecraft_formatting(text: str) -> str:
    if not text:
        return ""
    return re.sub(r'§[0-9a-fk-or]', '', text, flags=re.IGNORECASE)

def clean_description(motd: Any) -> str:
    if isinstance(motd, str):
        return motd
    if isinstance(motd, dict):
        text = motd.get('text', '')
        if 'extra' in motd and isinstance(motd['extra'], list):
            for part in motd['extra']:
                text += clean_description(part)
        return text
    if isinstance(motd, list):
        return "".join(clean_description(part) for part in motd)
    return str(motd)

def read_varint(sock):
    i = 0
    j = 0
    while True:
        k = sock.recv(1)
        if not k:
            return -1
        k = struct.unpack('B', k)[0]
        i |= (k & 0x7F) << (j * 7)
        j += 1
        if j > 5:
            return -1
        if not (k & 0x80):
            break
    return i

def write_varint(value):
    data = b''
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        data += struct.pack('B', byte)
        if value == 0:
            break
    return data

def write_packet(packet_id, data):
    full_data = struct.pack('B', packet_id) + data
    return write_varint(len(full_data)) + full_data

def fetch_data(hostname, port):
    sock = None
    try:
        hostname = str(hostname)[:150]
        port = int(port)
        if port < 1 or port > 65535:
            return None
        sock = socket.create_connection((hostname, port), timeout=TIMEOUT)
        data = b''
        data += write_varint(PROTOCOL_VERSION)
        data += write_varint(len(hostname))
        data += hostname.encode('utf8')
        data += struct.pack('>H', port)
        data += write_varint(1)
        sock.sendall(write_packet(0x00, data))
        sock.sendall(write_packet(0x00, b''))
        packet_len = read_varint(sock)
        packet_id = read_varint(sock)
        if packet_id == 0x00 and packet_len > 0:
            json_len = read_varint(sock)
            if json_len > 0:
                json_data = sock.recv(json_len)
                return json_data.decode('utf8')
        return None
    except Exception as e:
        logger.debug(f"fetch_data error for {hostname}:{port}: {e}")
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

def normalize_json_response(json_str: str) -> Optional[FinalResponse]:
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.debug(f"JSON decode error: {e}")
        return None
    players_data = data.get('players', {})
    version_data = data.get('version', {})
    favicon = data.get('favicon')
    motd_raw = data.get('description', '')
    modinfo_data = data.get('modinfo')
    players = Players(
        max=players_data.get('max', 0),
        online=players_data.get('online', 0),
        sample=[Player(**p) for p in players_data.get('sample', []) if isinstance(p, dict) and 'id' in p and 'name' in p]
    )
    version = Version(
        name=version_data.get('name', 'N/A'),
        protocol=version_data.get('protocol', -1)
    )
    if modinfo_data and isinstance(modinfo_data.get('modList'), list):
        n_mods = len(modinfo_data['modList'])
        version.name = f"{version.name} FML with {n_mods} mods"
    description_clean = clean_description(motd_raw)
    return FinalResponse(
        players=players,
        version=version,
        description=description_clean,
        favicon=favicon
    )

def check_server(server_line: str) -> Optional[Tuple[str, str]]:
    server_line = server_line.strip()
    if not server_line or ':' not in server_line:
        return None
    try:
        hostname, port_str = server_line.split(':')
        port = int(port_str)
    except ValueError:
        return None
    json_data = fetch_data(hostname, port)
    if json_data:
        final_response = normalize_json_response(json_data)
        if final_response:
            formatted_string = f"({server_line}){final_response}"
            return (server_line, formatted_string)
    return None

def batch_minecraft_check(ip_ports, job_status, max_processes=128):
    t0 = time.time()
    total_ips = len(ip_ports)
    successful_results = []
    START_PCT = 50
    END_PCT = 99
    RANGE_PCT = END_PCT - START_PCT
    def update_progress(idx, found_count):
        relative_progress = idx / total_ips
        global_progress = START_PCT + int(relative_progress * RANGE_PCT)
        job_status["progress"] = min(global_progress, END_PCT)
        job_status["message"] = f"Checker: {idx}/{total_ips} ({found_count} trovati)"

    with multiprocessing.Pool(processes=max_processes) as pool:
        iterator = pool.imap_unordered(check_server, ip_ports, chunksize=16)
        checked_count = 0
        found_count = 0
        for result in iterator:
            checked_count += 1
            if result:
                successful_results.append(result)
                found_count += 1
            update_progress(checked_count, found_count)
    t1 = time.time()
    duration = t1 - t0
    ips_per_sec = total_ips/duration if duration>0 else 0
    job_status["progress"] = 99
    job_status["message"] = f"Checker completato: {found_count}/{total_ips}, {duration:.2f}s ({ips_per_sec:.2f} IP/s)"
    bench = {
        "duration": duration,
        "ips_per_sec": ips_per_sec,
        "found_count": found_count
    }
    logger.info(f"Checker: {total_ips} targets in {duration:.2f}s ({ips_per_sec:.2f}/s), {found_count} responded")
    return successful_results, bench