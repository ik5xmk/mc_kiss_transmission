# mc_kiss_transmission.py

## Project focus

`mc_kiss_transmission.py` is a small, portable Python utility designed to transfer **short text files through a LoRa MeshCom network using the MeshCom KISS/TCP interface**.

The main use case is communication in **emergency, field, low-bandwidth or infrastructure-limited situations**, where two operators need to exchange compact files such as:

- short TXT notes and instructions;
- emergency or operational lists;
- CSV lists;
- coordinates or status information;
- small configuration or structured-text data.

It is intentionally **not a general-purpose large-file transfer system**. The design favors reliability, simple operation, conservative LoRa traffic and end-to-end integrity checks.

The same Python file is used on both computers. One side runs in **send mode**, the other in **receive mode**.

No external Python packages are required.

---

## MeshCom KISS references

This project is based on the KISS/TCP implementation documented by the MeshCom Firmware project:

- KISS/TCP client protocol:  
  https://github.com/icssw-org/MeshCom-Firmware/blob/dev/docs/kiss_tcp_protocol.md

- MeshCom KISS mode analysis:  
  https://github.com/icssw-org/MeshCom-Firmware/blob/dev/docs/kiss_mode_analysis.md

The firmware documentation should always be considered the authoritative reference for the MeshCom KISS implementation.

Important MeshCom requirements include:

- KISS/TCP normally listens on TCP port `8001`.
- `--kiss on` must be enabled on the MeshCom node.
- `--kiss tx on` is required when the KISS client must inject messages for transmission.
- Only one KISS/TCP client can be connected to a node at a time.
- The AX.25 source base callsign must match the base callsign configured on the MeshCom node.
- A KISS TX-result with status `0x01` means that the local node accepted the frame and queued it for LoRa transmission. It does **not** mean that the remote node received it.
- End-to-end delivery of addressed messages is confirmed by the normal MeshCom/APRS message ACK mechanism.
- Optional KISS/TCP authentication is supported by MeshCom and can be used by this program through `kiss_auth_password`.

---

## Communication model

Typical installation:

```text
Computer A                 MeshCom A
mc_kiss_transmission.py <-- KISS/TCP -->
                                  |
                                  | LoRa / MeshCom network
                                  |
Computer B                 MeshCom B
mc_kiss_transmission.py <-- KISS/TCP -->
```

The program does not replace the MeshCom radio protocol. It uses KISS/TCP only as the local interface between each computer and its own MeshCom node.

---

## Mandatory receiver readiness handshake

Before a file transfer is allowed to start, the sender performs an application-level readiness check.

```text
Sender                         Receiver

READY?  ---------------------->
        <---------------------- READY

START   ---------------------->
DATA    ---------------------->
...
END     ---------------------->
```

The sender does **not** transmit START, DATA or END until the remote Python program answers `READY`.

This is mandatory and cannot be disabled in the JSON configuration.

The number of readiness attempts uses the existing `max_retries` value.

This check is intentionally separate from native MeshCom ACKs:

- a native ACK confirms delivery of an addressed MeshCom message;
- the application `READY` response confirms that the **remote Python receiver is actually running and connected through KISS**.

Therefore a reachable MeshCom node alone is not sufficient to start a file transfer.

If the readiness handshake fails, the program aborts the operation before sending the file.

---

## Application protocol

The application protocol identifier is `MCF1`.

The main records are:

```text
Q|handshake_id
R|handshake_id

S|transfer_id|filename_base64|original_size|transport_size|blocks|sha256|C|E
D|transfer_id|sequence|payload_base64
E|transfer_id|sha256
```

Where:

- `Q` = readiness request;
- `R` = receiver ready response;
- `S` = transfer start and metadata;
- `D` = one data block;
- `E` = transfer end;
- `C=1` means zlib compression is being used;
- `E=1` means payload encryption is being used.

Each new transmission receives a random Transfer ID.

---

## Reliability and native MeshCom ACKs

START, DATA and END records are sent as numbered addressed APRS/MeshCom messages.

For each logical record the sender checks:

1. the KISS TX-result from its local MeshCom node;
2. the corresponding native MeshCom/APRS ACK.

If confirmation is not received within `ack_timeout`, the same logical record is retried.

The same client message number is retained when retrying that record. A new number is assigned only when moving to the next logical record.

Late ACKs belonging to previous records are ignored when they do not match the currently expected message number.

Duplicate START or DATA records caused by radio retries are safely handled by the receiver.

---

## Automatic compression

Compression is controlled by:

```json
"auto_compress": true
```

When enabled, the program tries zlib compression before transmission.

Compression is used **only when the compressed representation is smaller than the original data**. If compression would provide no benefit, the original data are transmitted instead.

This is particularly useful on LoRa because reducing the number of DATA blocks can substantially reduce radio traffic and transfer time.

Set:

```json
"auto_compress": false
```

to disable compression.

---

## Optional payload encryption

File payload encryption is enabled by setting the same non-empty password on both endpoints:

```json
"encryption_password": "your-secret-password"
```

Leave it empty to disable file encryption:

```json
"encryption_password": ""
```

The program:

1. optionally compresses the original file;
2. derives encryption/authentication keys from the password with PBKDF2-HMAC-SHA256;
3. uses a new random salt and nonce for every encrypted transfer;
4. encrypts the transport payload;
5. adds an HMAC-SHA256 authentication tag;
6. Base64-encodes the resulting binary data for text transport.

The receiver performs the reverse operations.

If the receiver has no password for an encrypted transfer, or uses the wrong password, authentication fails and **the file is not saved**.

`encryption_iterations` controls the PBKDF2 work factor:

```json
"encryption_iterations": 200000
```

The value must be the same on sender and receiver when encryption is used.

### Important distinction

`encryption_password` protects the **file payload**.

`kiss_auth_password` is different: it is used only when optional MeshCom KISS/TCP node authentication has been enabled in the MeshCom firmware.

---

## SHA-256 integrity verification

SHA-256 is calculated from the **original file**, before compression or encryption.

After receiving all blocks, the receiver:

1. reconstructs the transport payload;
2. authenticates and decrypts it when required;
3. decompresses it when required;
4. verifies the original size;
5. calculates SHA-256;
6. compares the result with the SHA-256 announced by the sender.

The file is saved only when all required checks succeed.

---

## Received filenames and Transfer ID

A received file is saved with its Transfer ID appended to the original name.

Example:

```text
report.txt
```

may be stored as:

```text
report_02C9A10F.txt
```

The Transfer ID helps distinguish separate transmissions and also provides a persistent indication that a particular transfer was already completed.

Sending the same file again normally generates a new Transfer ID and is therefore treated as a new transfer.

---

# Configuration

A JSON configuration file is required for each endpoint.

Example:

```json
{
    "_comment": "mc_kiss_transmission.py configuration",
    "meshcom_ip": "192.168.1.120",
    "meshcom_port": 8001,
    "mycall": "IU5AAA-1",
    "download_dir": "received",

    "block_size": 60,
    "max_file_size": 10240,
    "allowed_extensions": [
        ".txt",
        ".csv"
    ],

    "connect_timeout": 10.0,
    "tx_result_timeout": 5.0,
    "ack_timeout": 45.0,
    "tx_interval": 3.0,
    "max_retries": 5,

    "show_packets": true,
    "auto_compress": true,

    "encryption_password": "",
    "encryption_iterations": 200000,

    "kiss_auth_password": ""
}
```

## Configuration parameters

| Parameter | Purpose |
|---|---|
| `meshcom_ip` | IP address or DNS hostname of the local MeshCom node |
| `meshcom_port` | KISS/TCP port; normally `8001` |
| `mycall` | Local callsign used by the KISS/AX.25 client |
| `download_dir` | Directory where successfully received files are saved |
| `block_size` | Maximum raw transport bytes placed in each DATA block |
| `max_file_size` | Maximum accepted original file size in bytes |
| `allowed_extensions` | File extensions allowed for transfer |
| `connect_timeout` | TCP connection timeout |
| `tx_result_timeout` | Time allowed for the local KISS TX-result |
| `ack_timeout` | Time allowed for the expected native MeshCom/APRS ACK |
| `tx_interval` | Delay between transmissions/retries |
| `max_retries` | Retry limit; also used by the mandatory READY handshake |
| `show_packets` | Shows application packet activity on the console |
| `auto_compress` | Enables intelligent zlib compression |
| `encryption_password` | Optional file-payload encryption password |
| `encryption_iterations` | PBKDF2 iteration count |
| `kiss_auth_password` | Optional password for MeshCom KISS/TCP authentication |

---

# MeshCom node preparation

On each MeshCom node, enable KISS.

At minimum:

```text
--kiss on
```

For a node used by the program to transmit messages, also enable:

```text
--kiss tx on
```

Because both endpoints send messages during operation — including the mandatory READY response and native message exchanges — the recommended configuration is to enable KISS TX on **both MeshCom nodes**.

Verify that:

- the computer can reach its local MeshCom node over TCP;
- the configured KISS port is correct;
- no other KISS client is already occupying the single KISS connection;
- `mycall` uses the same base callsign as the corresponding MeshCom node;
- firewall rules allow the TCP connection.

If MeshCom KISS authentication is enabled on the node, configure the same password in:

```json
"kiss_auth_password": "node-kiss-password"
```

Otherwise leave:

```json
"kiss_auth_password": ""
```

---

# Sender configuration

Assume Computer A is connected to MeshCom node `IK5XMK-14`.

Example:

```json
{
    "meshcom_ip": "192.168.2.30",
    "meshcom_port": 8001,
    "mycall": "IK5XMK-14",
    "download_dir": "received",

    "block_size": 60,
    "max_file_size": 10240,
    "allowed_extensions": [".txt", ".csv"],

    "connect_timeout": 10.0,
    "tx_result_timeout": 5.0,
    "ack_timeout": 45.0,
    "tx_interval": 3.0,
    "max_retries": 5,

    "show_packets": true,
    "auto_compress": true,

    "encryption_password": "shared-file-password",
    "encryption_iterations": 200000,

    "kiss_auth_password": ""
}
```

To send `file.txt` to `IK5XMK-12`:

```bash
python mc_kiss_transmission.py --config mc_kiss_transmission-14.json --to IK5XMK-12 --send file.txt
```

Before START is transmitted, the program performs the mandatory READY handshake.

If the receiver does not answer, the file transfer is aborted.

---

# Receiver configuration

Assume Computer B is connected to MeshCom node `IK5XMK-12`.

Example:

```json
{
    "meshcom_ip": "YOUR_PUBBLIC_IP",
    "meshcom_port": 8001,
    "mycall": "IK5XMK-12",
    "download_dir": "received",

    "block_size": 60,
    "max_file_size": 10240,
    "allowed_extensions": [".txt", ".csv"],

    "connect_timeout": 10.0,
    "tx_result_timeout": 5.0,
    "ack_timeout": 45.0,
    "tx_interval": 3.0,
    "max_retries": 5,

    "show_packets": true,
    "auto_compress": true,

    "encryption_password": "shared-file-password",
    "encryption_iterations": 200000,

    "kiss_auth_password": ""
}
```

Start the receiver before starting the sender:

```bash
python mc_kiss_transmission.py --config mc_kiss_transmission-12.json --receive
```

The receiver remains connected to the local KISS/TCP interface and can answer the mandatory READY request.

After a successful transfer it verifies the data and saves the file in `download_dir`.

---

# Recommended operating sequence

1. Configure KISS/TCP on both MeshCom nodes.
2. Prepare one JSON configuration for each computer.
3. If file encryption is required, configure the same `encryption_password` and `encryption_iterations` on both sides.
4. Start `--receive` on the destination computer.
5. Start `--send` on the source computer.
6. Confirm that the READY handshake succeeds.
7. The program sends START, DATA and END records.
8. Native MeshCom/APRS ACKs control transport retries.
9. The receiver authenticates/decrypts and decompresses when required.
10. SHA-256 is verified.
11. Only a valid file is written to disk.

---

# Notes for emergency operation

LoRa is a low-bandwidth radio medium. Keep files short.

TXT and compact CSV files are ideal. Avoid using this utility for large documents, images, archives or other bulk data.

Automatic compression is recommended because repetitive text and structured data can often be reduced substantially before transmission.

Encryption adds overhead, but it can still be useful when the content must not be readable by intermediate monitoring systems.

The READY handshake prevents the sender from beginning a file transfer merely because the destination MeshCom node is reachable: the remote Python receiver must also be operational.

---

# Security notes

Payload encryption protects file content but does not hide all transfer metadata. Callsigns, MeshCom/APRS addressing and some MCF1 transfer metadata remain visible to the radio/network infrastructure.

Use a strong, non-trivial `encryption_password`.

Do not confuse payload encryption with MeshCom KISS/TCP authentication. They protect different parts of the system.

---

# Requirements

- Python 3.9 or newer recommended
- MeshCom node with KISS/TCP support
- Network connectivity between each computer and its local MeshCom node
- LoRa/MeshCom connectivity between the participating MeshCom nodes

No third-party Python libraries are required.

---

## Disclaimer

This is an application-layer utility built on top of the MeshCom KISS/TCP interface. `MCF1`, the READY handshake, compression, payload encryption, block management and file reconstruction are application features of this program and are not part of the MeshCom KISS protocol itself.
