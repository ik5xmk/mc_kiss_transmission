#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mc_kiss_transmission.py
=======================

see:
https://github.com/icssw-org/MeshCom-Firmware

PURPOSE
-------
Bidirectional transfer of short text files between two computers connected
to LoRa MeshCom nodes through the MeshCom KISS/TCP interface. The primary
focus is emergency and low-bandwidth operation: short TXT/CSV lists, status
reports, instructions, coordinates and other compact operational data.

FEATURES AND SAFETY/RELIABILITY CONTROLS
----------------------------------------
- Same program works as sender or receiver on Linux, Windows and macOS.
- Uses only the Python standard library.
- Connects to the local MeshCom node by KISS/TCP using an IP address or DNS.
- Supports optional MeshCom KISS/TCP authentication through kiss_auth_password.
- Requires a mandatory application READY handshake before every transfer.
  START/DATA/END are never sent unless the remote Python receiver answers READY.
- READY attempts use the existing max_retries setting and cannot be disabled.
- Uses addressed APRS/MeshCom messages and native MeshCom/APRS ACKs for the
  transport confirmation of application records.
- Reuses the same client message number when retrying the same logical record.
- Uses a unique random Transfer ID for each new transmission.
- Splits transport data into small configurable blocks suitable for LoRa.
- Can automatically compress data with zlib; compressed data are used only
  when they are smaller than the original data.
- Can encrypt and authenticate the transport payload when encryption_password
  is configured on both endpoints. Keys are derived with PBKDF2-HMAC-SHA256.
- Uses a random salt and nonce for each encrypted transfer and verifies an
  HMAC-SHA256 authentication tag before accepting encrypted data.
- Encodes binary transport data with URL-safe Base64 for safe text transport.
- Handles duplicate START and DATA records caused by radio retries.
- Reconstructs the original file only after all DATA blocks are available.
- Verifies original size and SHA-256 before saving the received file.
- Rejects wrong passwords, altered encrypted data, decompression failures,
  invalid sizes, incomplete transfers and SHA-256 mismatches.
- Restricts maximum file size and accepted file extensions through JSON.
- Adds the Transfer ID to the received filename, providing a persistent marker
  for a completed transfer and preventing ambiguity with retransmissions.
- Prints packet events and progress on separate console lines.

RELIABILITY MODEL
-----------------
A KISS TX-result only confirms that the local MeshCom node accepted a frame
for LoRa transmission. A native MeshCom/APRS ACK confirms delivery of the
addressed message through the MeshCom network. The mandatory READY handshake
is an additional application-level prerequisite: it confirms that the remote
Python receiver is running, connected to its MeshCom node through KISS and
able to answer before the file transfer begins.

Compression, encryption and READY do not replace native MeshCom ACK handling.
File encryption is also independent from optional KISS/TCP node authentication.

Application protocol: MCF1
--------------------------
Q|handshake_id                         readiness request
R|handshake_id                         receiver READY response
S|transfer_id|filename_b64|original_size|transport_size|blocks|sha256|C|E
D|transfer_id|sequence|payload_b64
E|transfer_id|sha256

C is 1 when zlib compression is used; E is 1 when encryption is used.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import sys
import time
import uuid
import zlib
from pathlib import Path

PROTO = "MCF1"

# KISS / SLIP
FEND  = 0xC0
FESC  = 0xDB
TFEND = 0xDC
TFESC = 0xDD

DEFAULT_CONFIG = {
    "meshcom_ip": "192.168.1.120",
    "meshcom_port": 8001,
    "mycall": "IU5AAA-1",
    "download_dir": "./received",
    "block_size": 60,
    "tx_interval": 3.0,
    "ack_timeout": 45.0,
    "tx_result_timeout": 5.0,
    "max_retries": 5,
    "max_file_size": 10240,
    "allowed_extensions": [".txt", ".csv"],
    "connect_timeout": 10.0,
    "show_packets": True,
    "auto_compress": True,
    "encryption_password": "",
    "encryption_iterations": 200000,
    "kiss_auth_password": ""
}


def load_config(path):
    """Load JSON configuration and fill missing keys with defaults."""
    cfg = DEFAULT_CONFIG.copy()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Configuration file not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        user_cfg = json.load(f)
    if not isinstance(user_cfg, dict):
        raise ValueError("JSON configuration must be an object.")
    cfg.update(user_cfg)

    # Controlli essenziali per evitare configurazioni pericolose/errate.
    cfg["meshcom_port"] = int(cfg["meshcom_port"])
    cfg["block_size"] = int(cfg["block_size"])
    cfg["tx_interval"] = float(cfg["tx_interval"])
    cfg["ack_timeout"] = float(cfg["ack_timeout"])
    cfg["tx_result_timeout"] = float(cfg["tx_result_timeout"])
    cfg["max_retries"] = int(cfg["max_retries"])
    cfg["max_file_size"] = int(cfg["max_file_size"])
    cfg["connect_timeout"] = float(cfg["connect_timeout"])
    cfg["auto_compress"] = bool(cfg.get("auto_compress", True))
    cfg["encryption_iterations"] = int(cfg.get("encryption_iterations", 200000))
    if cfg["encryption_iterations"] < 10000:
        raise ValueError("encryption_iterations must be at least 10000.")

    if not 1 <= cfg["block_size"] <= 70:
        raise ValueError("block_size deve essere compreso in 1 e 70 byte (consigliato 60).")
    if cfg["tx_interval"] < 0:
        raise ValueError("tx_interval cannot be negative.")
    if cfg["max_retries"] < 1:
        raise ValueError("max_retries deve essere almeno 1.")
    validate_source_call(cfg["mycall"])
    return cfg


def split_call(call):
    call = call.strip().upper()
    if "-" in call:
        base, ssid_s = call.rsplit("-", 1)
        try:
            ssid = int(ssid_s)
        except ValueError:
            raise ValueError(f"SSID non valido nel callsign: {call}")
    else:
        base, ssid = call, 0
    return base, ssid


def validate_source_call(call):
    base, ssid = split_call(call)
    if not re.fullmatch(r"[A-Z0-9]{1,6}", base):
        raise ValueError("mycall: base callsign AX.25 non valido (max 6 caratteri A-Z/0-9).")
    if not 0 <= ssid <= 15:
        raise ValueError("mycall: l'SSID sorgente KISS/AX.25 deve essere 0..15.")


def validate_destination(call):
    """The textual APRS addressee is at most 9 characters long."""
    call = call.strip().upper()
    if not call or len(call) > 9:
        raise ValueError("Destinazione non valida: massimo 9 caratteri.")
    if not re.fullmatch(r"[A-Z0-9-]+", call):
        raise ValueError("Destinazione non valida.")
    return call


def encode_ax25_call(call, top, last):
    """Codifica un indirizzo AX.25 a 7 byte."""
    base, ssid = split_call(call)
    base = (base.upper() + "      ")[:6]
    first6 = bytes((ord(c) << 1) & 0xFF for c in base)
    seventh = top | 0x60 | ((ssid & 0x0F) << 1) | (1 if last else 0)
    return first6 + bytes([seventh])


def decode_ax25_call(a):
    base = "".join(chr(x >> 1) for x in a[:6]).strip()
    ssid = (a[6] >> 1) & 0x0F
    return f"{base}-{ssid}" if ssid else base


def kiss_wrap(payload, frame_type=0x00):
    out = bytearray([FEND, frame_type])
    for x in payload:
        if x == FEND:
            out += bytes([FESC, TFEND])
        elif x == FESC:
            out += bytes([FESC, TFESC])
        else:
            out.append(x)
    out.append(FEND)
    return bytes(out)


def kiss_unescape(raw):
    out = bytearray()
    esc = False
    for x in raw:
        if esc:
            if x == TFEND:
                out.append(FEND)
            elif x == TFESC:
                out.append(FESC)
            else:
                out.append(x)
            esc = False
        elif x == FESC:
            esc = True
        else:
            out.append(x)
    return bytes(out)


def build_message_ax25(mycall, tocall, addressee, text, msg_no=None):
    """Costruisce AX.25 UI + info APRS MeshCom."""
    dst = encode_ax25_call(tocall, 0x80, False)
    src = encode_ax25_call(mycall, 0x00, True)
    target = addressee.upper().ljust(9)
    info = f":{target}:{text}"
    if msg_no is not None:
        info += "{" + str(msg_no)
    return dst + src + bytes([0x03, 0xF0]) + info.encode("ascii")


def decode_data_frame(frame, real_src=None):
    """Decodifica un frame KISS type 0x00 e restituisce src, dst, info."""
    b = frame[1:]
    p = 0
    addrs = []
    while p + 7 <= len(b):
        a = b[p:p+7]
        addrs.append(a)
        p += 7
        if a[6] & 1:
            break
    if len(addrs) < 2 or p + 2 > len(b):
        return None
    if b[p] != 0x03 or b[p+1] != 0xF0:
        return None
    dst = decode_ax25_call(addrs[0])
    src = real_src or decode_ax25_call(addrs[1])
    info = b[p+2:].decode("latin1", "replace")
    return src, dst, info


def parse_aprs_message(info):
    """
    Estrae addressee, testo e numero messaggio da:
        :ADDRESSEE :testo{123
    """
    if not info.startswith(":") or len(info) < 11 or info[10] != ":":
        return None
    addressee = info[1:10].strip()
    body = info[11:]
    msg_no = None
    m = re.search(r"\{([A-Za-z0-9]{1,5})(?:\}..)?$", body)
    if m:
        msg_no = m.group(1)
        body = body[:m.start()]
    return addressee, body, msg_no


class KissConnection:
    """TCP connection and incremental KISS frame parser."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.sock = None
        self.buf = bytearray()
        self.in_frame = False
        self.real_src = None

    def connect(self):
        host = self.cfg["meshcom_ip"]
        port = self.cfg["meshcom_port"]
        print(f"Connecting KISS/TCP to {host}:{port} ...")
        self.sock = socket.create_connection(
            (host, port), timeout=self.cfg["connect_timeout"]
        )
        self.sock.settimeout(0.5)

        # Autenticazione opzionale KISS, se configurata nel firmware.
        password = str(self.cfg.get("kiss_auth_password", ""))
        if password:
            self._authenticate(password)

        print("KISS/TCP connected.")

    def _recv_line(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        data = bytearray()
        old = self.sock.gettimeout()
        try:
            self.sock.settimeout(0.5)
            while time.monotonic() < deadline:
                try:
                    b = self.sock.recv(1)
                except socket.timeout:
                    continue
                if not b:
                    raise ConnectionError("Connection closed during authentication.")
                data += b
                if data.endswith(b"\n"):
                    return bytes(data)
        finally:
            self.sock.settimeout(old)
        raise TimeoutError("Timeout autenticazione KISS.")

    def _authenticate(self, password):
        line = self._recv_line(15.0).decode("ascii", "replace").strip()
        if not line.startswith("NONCE: "):
            raise ConnectionError("Handshake KISS auth non riconosciuto.")
        nonce = bytes.fromhex(line.split()[1])
        mac = hmac.new(password.encode("utf-8"), nonce, hashlib.sha256).hexdigest()
        self.sock.sendall((mac + "\r\n").encode("ascii"))
        reply = self._recv_line(15.0).decode("ascii", "replace").strip()
        if not reply.startswith("OK"):
            raise ConnectionError("Autenticazione KISS fallita.")
        print("Autenticazione KISS: OK")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_ax25(self, ax25):
        self.sock.sendall(kiss_wrap(ax25))

    def read_frame(self, timeout=0.5):
        """
        Return one de-escaped KISS frame, including the type as byte 0.
        TCP is a stream; frames may be split across multiple recv() calls.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # First try to extract a frame from already buffered data.
            while self.buf:
                b = self.buf.pop(0)
                if b == FEND:
                    if self.in_frame and hasattr(self, "_frame") and self._frame:
                        raw = bytes(self._frame)
                        self._frame.clear()
                        self.in_frame = True
                        return kiss_unescape(raw)
                    self.in_frame = True
                    self._frame = bytearray()
                elif self.in_frame:
                    if not hasattr(self, "_frame"):
                        self._frame = bytearray()
                    self._frame.append(b)

            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                raise ConnectionError("KISS/TCP connection closed by node.")
            self.buf.extend(data)
        return None

    def wait_tx_and_ack(self, expected_ack):
        """
        Attende il TX-result KISS e l'ACK end-to-end rimappato dal firmware.

        Il numero atteso resta invariato durante i retry dello stesso record.
        A late ACK for the current record can therefore still be accepted.
        """
        tx_ok = False
        started = time.monotonic()
        tx_deadline = started + self.cfg["tx_result_timeout"]
        ack_deadline = started + self.cfg["ack_timeout"]

        while time.monotonic() < ack_deadline:
            frame = self.read_frame(0.5)
            if frame is None:
                if not tx_ok and time.monotonic() >= tx_deadline:
                    return False, "nessun TX-result KISS"
                continue
            if not frame:
                continue

            ftype = frame[0]

            if ftype == 0x20:
                self.real_src = frame[1:].decode("latin1", "replace")
                continue

            if ftype == 0xF0:
                if len(frame) < 2:
                    continue
                status = frame[1]
                if status == 0x01:
                    if not tx_ok and self.cfg.get("show_packets", True):
                        print(f"  KISS TX accepted [{expected_ack}]")
                    tx_ok = True
                else:
                    reasons = {
                        0x02: "source callsign rejected",
                        0x03: "KISS TX disabilitato",
                        0x04: "frame/payload non valido o troppo lungo",
                        0x05: "limite velocita TX superato",
                    }
                    return False, reasons.get(status, f"TX-result status {status}")
                continue

            if ftype != 0x00:
                # 0x10 e altri metadati non sono errori.
                continue

            decoded = decode_data_frame(frame, self.real_src)
            self.real_src = None
            if not decoded:
                continue

            src, _dst, info = decoded
            parsed = parse_aprs_message(info)
            if not parsed:
                continue

            _addressee, body, _msg_no = parsed
            m = re.fullmatch(r"ack([A-Za-z0-9]{1,5})", body, flags=re.IGNORECASE)
            if not m:
                continue

            observed = m.group(1)
            elapsed = time.monotonic() - started
            if observed.lower() == str(expected_ack).lower():
                if self.cfg.get("show_packets", True):
                    print(f"  ACK RX <- {src}: ack{observed} ({elapsed:.1f} s)")
                return True, "ACK received"

            # It may be a late ACK belonging to a previous record.
            if self.cfg.get("show_packets", True):
                print(f"  ACK RX <- {src}: ack{observed} (atteso ack{expected_ack}: ignored)")

        return False, f"ACK {expected_ack} not received within {self.cfg['ack_timeout']:.0f} s"

def safe_filename(name):
    """Remove directory components and unsafe characters; receiver writes only to download_dir."""
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    if name in ("", ".", ".."):
        name = "received.txt"
    return name[:120]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()



def _derive_encryption_keys(password, salt, iterations):
    """Derive two independent keys from the password: one for the stream and one for the MAC."""
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=64
    )
    return material[:32], material[32:]


def _xor_hmac_stream(data, key, nonce):
    """Encrypt/decrypt with a counter-based HMAC-SHA256 pseudorandom stream."""
    out = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        take = min(len(block), len(data) - offset)
        for i in range(take):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += take
        counter += 1
    return bytes(out)


def encrypt_payload(data, password, iterations):
    """
    Encrypt and authenticate the payload.
    Formato binario: salt(16) + nonce(16) + ciphertext + HMAC-SHA256(32).
    """
    salt = os.urandom(16)
    nonce = os.urandom(16)
    enc_key, mac_key = _derive_encryption_keys(password, salt, iterations)
    ciphertext = _xor_hmac_stream(data, enc_key, nonce)
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    return salt + nonce + ciphertext + tag


def decrypt_payload(blob, password, iterations):
    """Authenticate and decrypt the payload; reject a wrong password."""
    if len(blob) < 64:
        raise ValueError("encrypted payload is too short")
    salt = blob[:16]
    nonce = blob[16:32]
    ciphertext = blob[32:-32]
    received_tag = blob[-32:]
    enc_key, mac_key = _derive_encryption_keys(password, salt, iterations)
    expected_tag = hmac.new(
        mac_key, salt + nonce + ciphertext, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("wrong password or encrypted data was altered")
    return _xor_hmac_stream(ciphertext, enc_key, nonce)


def prepare_transport_data(data, cfg):
    """
    Prepare bytes for transmission.
    Compression is used only when it actually reduces payload size.
    Encryption is applied after compression when configured.
    """
    payload = data
    compressed = False

    if cfg.get("auto_compress", True) and data:
        candidate = zlib.compress(data, level=9)
        if len(candidate) < len(data):
            payload = candidate
            compressed = True

    password = str(cfg.get("encryption_password", ""))
    encrypted = bool(password)
    if encrypted:
        payload = encrypt_payload(
            payload, password, cfg.get("encryption_iterations", 200000)
        )

    return payload, compressed, encrypted


def restore_transport_data(payload, compressed, encrypted, cfg):
    """Restore original bytes in reverse order: decrypt, then decompress."""
    data = payload
    if encrypted:
        password = str(cfg.get("encryption_password", ""))
        if not password:
            raise ValueError("transfer is encrypted but encryption_password is empty")
        data = decrypt_payload(
            data, password, cfg.get("encryption_iterations", 200000)
        )
    if compressed:
        data = zlib.decompress(data)
    return data


def print_progress(prefix, done, total):
    """Print every progress update on its own line to keep the console readable."""
    pct = 100.0 if total == 0 else (done / total * 100.0)
    width = 30
    filled = int(width * pct / 100.0)
    bar = "#" * filled + "-" * (width - filled)
    print(f"{prefix} [{bar}] {pct:6.1f}%  {done}/{total}", flush=True)


class MessageNumber:
    """Short APRS message numbers: 1..99999."""
    def __init__(self):
        self.n = int(time.time()) % 90000 + 10000

    def next(self):
        self.n += 1
        if self.n > 99999:
            self.n = 1
        return str(self.n)


def send_record(conn, cfg, destination, record, numbers, label="RECORD", attempts=None):
    """
    Send an MCF1 record reliably.

    The APRS/KISS message number is assigned ONCE to each logical record.
    Retries of that record reuse the same msg_no, so a delayed ACK remains valid.
    """
    msg_no = numbers.next()
    retry_count = cfg["max_retries"] if attempts is None else max(1, int(attempts))
    ax = build_message_ax25(
        cfg["mycall"], "APMESH", destination,
        f"{PROTO}|{record}", msg_no
    )

    for attempt in range(1, retry_count + 1):
        print(f"{label} [{msg_no}] attempt {attempt}/{retry_count}")
        if cfg.get("show_packets", True):
            print(f"  PKT TX {label} | MSG={msg_no}")
        conn.send_ax25(ax)
        ok, reason = conn.wait_tx_and_ack(msg_no)
        if ok:
            return True

        print(f"  No confirmation: {reason}")
        if attempt < retry_count:
            print(f"  Retrying the SAME record/message number [{msg_no}] "
                  f"in {cfg['tx_interval']:.1f} s...")
            time.sleep(cfg["tx_interval"])
    return False



def wait_ready_response(conn, cfg, expected_source, handshake_id):
    """
    Attende la risposta applicativa READY del programma remoto.
    Non sostituisce gli ACK nativi MeshCom: conferma che il software RX
    sia effettivamente attivo e collegato alla propria scheda via KISS.
    """
    deadline = time.time() + cfg["ack_timeout"]

    while time.time() < deadline:
        frame = conn.read_frame(max(0.1, deadline - time.time()))
        if frame is None or not frame:
            continue

        ftype = frame[0]
        if ftype == 0x20:
            conn.real_src = frame[1:].decode("latin1", "replace")
            continue
        if ftype != 0x00:
            continue

        decoded = decode_data_frame(frame, conn.real_src)
        conn.real_src = None
        if not decoded:
            continue

        src, _dst, info = decoded
        parsed = parse_aprs_message(info)
        if not parsed:
            continue
        addressee, body, _msg_no = parsed

        if addressee.upper() != cfg["mycall"].upper():
            continue

        fields = parse_protocol(body)
        if not fields:
            continue

        if (len(fields) == 2 and fields[0] == "R"
                and fields[1] == handshake_id
                and src.upper() == expected_source.upper()):
            print(f"  READY RX <- {src}: ID={handshake_id}")
            return True

    return False


def receiver_ready_handshake(conn, cfg, destination, numbers):
    """
    Mandatory handshake before START.
    The total number of handshake attempts is exactly max_retries.
    If the remote program does not answer READY, START/DATA/END are not sent.
    """
    handshake_id = uuid.uuid4().hex[:8].upper()

    print("Checking receiver availability...")
    print(f"Handshake ID : {handshake_id}")

    for attempt in range(1, cfg["max_retries"] + 1):
        # Each READY? is one application handshake attempt and one radio send.
        # There is deliberately no nested retry loop here.
        print(f"HANDSHAKE attempt {attempt}/{cfg['max_retries']}")

        request = f"Q|{handshake_id}"
        if not send_record(
            conn, cfg, destination, request, numbers, "READY?", attempts=1
        ):
            print("  READY? request not delivered.")
        else:
            if wait_ready_response(conn, cfg, destination, handshake_id):
                print("Receiver ready: handshake completed.")
                return True
            print(f"  No READY response from receiver software within "
                  f"{cfg['ack_timeout']:.0f} s.")

        if attempt < cfg["max_retries"]:
            print(f"  Retrying handshake in {cfg['tx_interval']:.1f} s...")
            time.sleep(cfg["tx_interval"])

    print()
    print("TRANSMISSION ABORTED.")
    print("The receiver software did not confirm readiness.")
    print("No START/DATA/END packet was sent.")
    return False


def send_file(cfg, file_path, destination):
    destination = validate_destination(destination)
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    ext = path.suffix.lower()
    allowed = [str(x).lower() for x in cfg["allowed_extensions"]]
    if allowed and ext not in allowed:
        raise ValueError(
            f"Extension {ext or '(none)'} is not allowed. Allowed: {', '.join(allowed)}"
        )

    size = path.stat().st_size
    if size > cfg["max_file_size"]:
        raise ValueError(
            f"File too large: {size} bytes; limit {cfg['max_file_size']} bytes."
        )

    data = path.read_bytes()
    digest = sha256_bytes(data)

    transport_data, compressed, encrypted = prepare_transport_data(data, cfg)
    transport_size = len(transport_data)

    bs = cfg["block_size"]
    chunks = [transport_data[i:i+bs] for i in range(0, len(transport_data), bs)]
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    transfer_id = uuid.uuid4().hex[:8].upper()
    name64 = base64.urlsafe_b64encode(path.name.encode("utf-8")).decode("ascii")

    print("=" * 60)
    print(" MeshCom KISS Transmission - SEND")
    print("=" * 60)
    print(f"File         : {path.name}")
    print(f"Original size: {size} byte")
    print(f"Destination  : {destination}")
    print(f"Transport    : {transport_size} byte")
    print(f"Compression  : {'ZLIB' if compressed else 'NO'}")
    print(f"Encryption   : {'YES' if encrypted else 'NO'}")
    print(f"Data blocks  : {total} x max {bs} byte")
    print(f"TX interval  : {cfg['tx_interval']:.1f} s")
    print(f"Transfer ID  : {transfer_id}")
    print(f"SHA-256      : {digest}")
    print("=" * 60)

    conn = KissConnection(cfg)
    numbers = MessageNumber()
    try:
        conn.connect()

        # Prima di qualsiasi START/DATA/END il software remoto deve
        # explicitly confirm that it is active and ready.
        if not receiver_ready_handshake(conn, cfg, destination, numbers):
            return

        # START
        start_record = (f"S|{transfer_id}|{name64}|{size}|{transport_size}|{total}|"
                        f"{digest}|{1 if compressed else 0}|{1 if encrypted else 0}")
        print("Sending START record...")
        if not send_record(conn, cfg, destination, start_record, numbers, "START"):
            raise RuntimeError("Unable to deliver the file START record.")

        time.sleep(cfg["tx_interval"])

        # DATA
        for i, chunk in enumerate(chunks, start=1):
            payload = base64.urlsafe_b64encode(chunk).decode("ascii")
            record = f"D|{transfer_id}|{i}|{payload}"
            if not send_record(conn, cfg, destination, record, numbers, f"DATA {i}/{total}"):
                raise RuntimeError(f"Transfer interrupted at block {i}/{total}.")
            print_progress("TX", i, total)
            if i < total:
                time.sleep(cfg["tx_interval"])

        time.sleep(cfg["tx_interval"])

        # END
        print("Sending END record...")
        end_record = f"E|{transfer_id}|{digest}"
        if not send_record(conn, cfg, destination, end_record, numbers, "END"):
            raise RuntimeError("Chiusura non confermata.")

        print("\nTRANSMISSION COMPLETED.")
        print("All transfer messages were confirmed by the MeshCom network.")
        print("Decryption, SHA-256 verification and file saving are finally checked")
        print("by the receiver software.")
    finally:
        conn.close()


class IncomingTransfer:
    def __init__(self, transfer_id, filename, size, transport_size, total,
                 digest, source, compressed=False, encrypted=False):
        self.id = transfer_id
        self.filename = filename
        self.size = size
        self.transport_size = transport_size
        self.total = total
        self.digest = digest
        self.source = source
        self.compressed = compressed
        self.encrypted = encrypted
        self.parts = {}
        self.started = time.time()


def parse_protocol(body):
    prefix = PROTO + "|"
    if not body.startswith(prefix):
        return None
    return body[len(prefix):].split("|")



def filename_with_transfer_id(filename, transfer_id):
    """Restituisce ad esempio miofile_63D64D24.txt."""
    p = Path(filename)
    return f"{p.stem}_{transfer_id.upper()}{p.suffix}"


def completed_file_for_transfer(receive_dir, transfer_id):
    """Cerca su disco un file gia' completato con lo stesso Transfer ID."""
    suffix = "_" + transfer_id.upper()
    directory = Path(receive_dir)
    if not directory.exists():
        return None
    for p in directory.iterdir():
        if p.is_file() and p.stem.upper().endswith(suffix):
            return p
    return None


def packet_log(cfg, direction, kind, tid, detail=""):
    """Mostra i pacchetti in modo sintetico se show_packets e' attivo."""
    if not cfg.get("show_packets", True):
        return
    tail = f" | {detail}" if detail else ""
    print(f"  PKT {direction} {kind} | ID={tid}{tail}")



def receive_loop(cfg):
    outdir = Path(cfg["download_dir"])
    outdir.mkdir(parents=True, exist_ok=True)
    transfers = {}
    numbers = MessageNumber()

    print("=" * 60)
    print(" MeshCom KISS Transmission - RECEIVE")
    print("=" * 60)
    print(f"Receive dir  : {outdir.resolve()}")
    print(f"File limit   : {cfg['max_file_size']} byte")
    print("Press CTRL+C to stop.")
    print("=" * 60)

    conn = KissConnection(cfg)
    conn.connect()

    try:
        while True:
            frame = conn.read_frame(1.0)
            if frame is None or not frame:
                continue

            ftype = frame[0]
            if ftype == 0x20:
                conn.real_src = frame[1:].decode("latin1", "replace")
                continue
            if ftype != 0x00:
                continue

            decoded = decode_data_frame(frame, conn.real_src)
            conn.real_src = None
            if not decoded:
                continue
            src, _dst, info = decoded
            parsed = parse_aprs_message(info)
            if not parsed:
                continue
            addressee, body, msg_no = parsed

            # Accetta solo messaggi diretti al callsign configurato.
            if addressee.upper() != cfg["mycall"].upper():
                continue

            fields = parse_protocol(body)
            if not fields:
                continue

            # nessun ACK applicativo aggiuntivo.
            # Osserviamo il comportamento nativo MeshCom/KISS senza interferire.
            kind = fields[0]
            if cfg.get("show_packets", True):
                tid_preview = fields[1] if len(fields) > 1 else "?"
                print(f"  PKT RX {kind} | ID={tid_preview} | SRC={src} | MSG={msg_no or '-'}")

            # Q = richiesta di disponibilita'. La risposta R viene generata
            # only by the Python program while it is actually in receive mode.
            if kind == "Q" and len(fields) == 2:
                _, handshake_id = fields
                if not re.fullmatch(r"[0-9A-Fa-f]{8}", handshake_id):
                    print(f"  HANDSHAKE ignored: ID non valido from {src}")
                    continue

                print(f"  READY? RX <- {src}: ID={handshake_id}")
                reply = f"R|{handshake_id}"
                print(f"  Sending READY -> {src}: ID={handshake_id}")
                if not send_record(conn, cfg, src, reply, numbers, "READY"):
                    print(f"  WARNING: READY not confirmed to {src}.")
                continue

            # An R response never opens a transfer in receive mode.
            if kind == "R" and len(fields) == 2:
                continue

            if kind == "S" and len(fields) == 9:
                _, tid, name64, size_s, transport_size_s, total_s, digest, comp_s, enc_s = fields
                try:
                    size = int(size_s)
                    transport_size = int(transport_size_s)
                    total = int(total_s)
                    compressed = comp_s == "1"
                    encrypted = enc_s == "1"
                    rawname = base64.urlsafe_b64decode(name64.encode("ascii"))
                    filename = safe_filename(rawname.decode("utf-8", "replace"))
                except Exception:
                    print(f"\nSTART non valido from {src}; ignored.")
                    continue

                if (size < 0 or size > cfg["max_file_size"] or total < 1
                        or transport_size < 0
                        or transport_size > cfg["max_file_size"] + 4096):
                    print(f"\nFile rejected from {src}: size/block count outside configured limits.")
                    continue
                if Path(filename).suffix.lower() not in [
                    str(x).lower() for x in cfg["allowed_extensions"]
                ]:
                    print(f"\nFile rejected from {src}: estensione non ammessa ({filename}).")
                    continue

                already = completed_file_for_transfer(cfg["download_dir"], tid)
                if already is not None:
                    packet_log(cfg, "RX", "START", tid, "gia' completato - ignored")
                    continue

                if tid in transfers:
                    tr_old = transfers[tid]
                    if (tr_old.filename == filename and tr_old.size == size
                            and tr_old.transport_size == transport_size
                            and tr_old.total == total
                            and tr_old.digest == digest.lower()
                            and tr_old.source == src
                            and tr_old.compressed == compressed
                            and tr_old.encrypted == encrypted):
                        print(f"\nDEBUG RX: duplicate START {tid} from {src}; "
                              f"transfer retained ({len(tr_old.parts)}/{tr_old.total} blocks).")
                        continue
                    else:
                        print(f"\nATTENZIONE: Transfer ID {tid} riutilizzato con metadati diversi; ignored.")
                        continue

                transfers[tid] = IncomingTransfer(
                    tid, filename, size, transport_size, total, digest.lower(),
                    src, compressed, encrypted
                )
                print("\n" + "-" * 60)
                print(f"New file from  : {src}")
                print(f"File           : {filename}")
                print(f"Original size  : {size} byte")
                print(f"Transport size : {transport_size} byte")
                print(f"Compression    : {'ZLIB' if compressed else 'NO'}")
                print(f"Encryption     : {'YES' if encrypted else 'NO'}")
                print(f"Data blocks    : {total}")
                print(f"Transfer ID    : {tid}")
                print("-" * 60)
                print_progress("RX", 0, total)

            elif kind == "D" and len(fields) == 4:
                _, tid, seq_s, payload = fields
                tr = transfers.get(tid)
                if not tr:
                    if completed_file_for_transfer(cfg["download_dir"], tid) is not None:
                        packet_log(cfg, "RX", "DATA", tid, "gia' completato - ignored")
                    continue
                try:
                    seq = int(seq_s)
                    if not 1 <= seq <= tr.total:
                        continue
                    chunk = base64.urlsafe_b64decode(payload.encode("ascii"))
                except Exception:
                    continue
                if seq in tr.parts:
                    if tr.parts[seq] == chunk:
                        print(f"\nDEBUG RX: duplicate DATA {seq}/{tr.total} per {tid}; ignored.")
                    else:
                        print(f"\nRX ERROR: DATA {seq}/{tr.total} duplicate but different; ignored.")
                    continue
                tr.parts[seq] = chunk
                print_progress("RX", len(tr.parts), tr.total)

            elif kind == "E" and len(fields) == 3:
                _, tid, remote_digest = fields
                tr = transfers.get(tid)
                if not tr:
                    if completed_file_for_transfer(cfg["download_dir"], tid) is not None:
                        packet_log(cfg, "RX", "END", tid, "gia' completato - ignored")
                    continue

                missing = [i for i in range(1, tr.total + 1) if i not in tr.parts]
                if missing:
                    print(f"\nEND received but blocks are missing: {missing}")
                    print("The file will NOT be saved.")
                    del transfers[tid]
                    continue

                transport_data = b"".join(
                    tr.parts[i] for i in range(1, tr.total + 1)
                )
                if len(transport_data) != tr.transport_size:
                    print(f"\nERROR: transport size {len(transport_data)} "
                          f"!= expected {tr.transport_size}.")
                    del transfers[tid]
                    continue

                try:
                    data = restore_transport_data(
                        transport_data, tr.compressed, tr.encrypted, cfg
                    )
                except Exception as e:
                    print(f"\nDATA RESTORE ERROR: {e}")
                    print("The file will NOT be saved.")
                    del transfers[tid]
                    continue

                local_digest = sha256_bytes(data)

                if len(data) != tr.size:
                    print(f"\nERROR: final size {len(data)} != expected {tr.size}.")
                    del transfers[tid]
                    continue
                if local_digest.lower() != tr.digest or local_digest.lower() != remote_digest.lower():
                    print("\nSHA-256 ERROR: received file integrity check failed.")
                    print("The file will NOT be saved.")
                    del transfers[tid]
                    continue

                dest = outdir / safe_filename(filename_with_transfer_id(tr.filename, tid))
                # Evita di sovrascrivere un file esistente.
                if dest.exists():
                    stem, suffix = dest.stem, dest.suffix
                    n = 1
                    while True:
                        candidate = outdir / f"{stem}_{n}{suffix}"
                        if not candidate.exists():
                            dest = candidate
                            break
                        n += 1

                dest.write_bytes(data)
                elapsed = max(0.1, time.time() - tr.started)
                print("\nFILE RECEIVED SUCCESSFULLY.")
                print(f"Saved to       : {dest.resolve()}")
                print(f"SHA-256        : OK")
                print(f"Elapsed time   : {elapsed:.1f} s")
                print("\nReady for another file...")

                del transfers[tid]

    except KeyboardInterrupt:
        print("\nReceive mode stopped by user.")
    finally:
        conn.close()


def make_parser():
    p = argparse.ArgumentParser(
        description="Short text-file transfer over MeshCom KISS/TCP."
    )
    p.add_argument(
        "--config", default="mc_kiss_transmission.json",
        help="JSON configuration file (default: mc_kiss_transmission.json)"
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--send", metavar="FILE", help="File to send.")
    mode.add_argument("--receive", action="store_true", help="Run in receive mode.")
    p.add_argument("--to", metavar="CALL", help="MeshCom destination callsign for --send.")
    return p


def main():
    args = make_parser().parse_args()
    try:
        cfg = load_config(args.config)
        if args.send:
            if not args.to:
                raise ValueError("--send also requires --to CALL")
            send_file(cfg, args.send, args.to)
        else:
            receive_loop(cfg)
        return 0
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"CONFIGURATION ERROR: {e}", file=sys.stderr)
        return 2
    except (ConnectionError, TimeoutError, OSError) as e:
        print(f"CONNECTION ERROR: {e}", file=sys.stderr)
        return 3
    except RuntimeError as e:
        print(f"TRANSFER ERROR: {e}", file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        print("\nOperation interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
