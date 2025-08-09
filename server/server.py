#!/usr/bin/env python3
"""
Single-file HTTP upload server.

- Prompts for a port and checks that the chosen port is free (repeats until valid).
- Detects the machine LAN/Wi-Fi IP automatically.
- Generates a send.sh in the same directory that clients can fetch and pipe to bash.
- Serves only:
    GET /send.sh   -> returns the generated client script
    POST /upload   -> accepts a raw binary POST containing a tar.gz (header X-Filename set by client)
- Saves uploads under ./uploads/<client_ip>_<dd-mm-YYYY_HH-MM-SS>/ and extracts the tarball there
  (then deletes the tarball).
- Cleans up send.sh when the server is stopped with Ctrl+C.
- Uses only Python standard library (works on Python 3.8+; compatible with 3.13+).
"""

import os
import socket
import tarfile
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime

HERE = Path(__file__).resolve().parent
UPLOADS = HERE / "uploads"
SEND_SH = HERE / "send.sh"


def get_local_ip():
    """Return a LAN IP by creating a UDP socket to a public IP (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't have to be reachable; kernel picks the right interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        # fallback to localhost if something weird happens
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def port_is_free(ip, port):
    """Return True if port is bindable on the given ip (TCP)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, port))
        return True
    except OSError:
        return False


def sanitize_name(s):
    """Make a filesystem-safe string for client IPs, etc."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(s))


def create_send_sh(ip, port):
    """
    Generate send.sh in the same directory as this script.
    The script:
      - tar.gz's the current directory (the folder itself)
      - POSTs the binary tar.gz to http://<ip>:<port>/upload
      - sends X-Filename header with the tarball name
      - deletes the local tarball after sending
    """
    content = f"""#!/bin/bash
set -euo pipefail

# send.sh -- created by server
# Usage:  curl http://{ip}:{port}/send.sh | bash
# Or download it and run: bash send.sh

# Determine current folder
FOLDER="$(basename "$PWD")"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
ARCHIVE="${{FOLDER}}_${{TIMESTAMP}}.tar.gz"

# Go up one directory
cd ..

# Create a tarball that contains the folder itself
# -C to parent so the archive contains the top-level folder
echo "These files are getting zipped to send:"
tar -czvf "$ARCHIVE" "$FOLDER"
wait

# Upload as raw binary with filename header
curl -sS -X POST \\
     -H "Content-Type: application/gzip" \\
     -H "X-Filename: $ARCHIVE" \\
     --data-binary @"$ARCHIVE" \\
     "http://{ip}:{port}/upload"

# Clean up local archive
rm -f "$ARCHIVE"
echo "Upload attempted (archive: $ARCHIVE)"
cd "$FOLDER"
"""
    SEND_SH.write_text(content)
    SEND_SH.chmod(0o755)
    print(
        f"[+] send.sh created at: {SEND_SH} (clients: curl http://{ip}:{port}/send.sh | bash)")


def safe_extract(tar: tarfile.TarFile, path: Path):
    """
    Safely extract tar members into `path`, preventing path traversal.
    """
    abs_target = str(path.resolve())

    def is_safe(member, extraction_path):
        member_path = path / member.name
        abs_member_path = str(member_path.resolve())
        if not abs_member_path.startswith(abs_target + os.sep) and abs_member_path != abs_target:
            print(f"[!] Unsafe tar path detected and skipped: {member.name}")
            return None  # filter out this member
        return member  # safe member, keep it
    tar.extractall(path=str(path), filter=is_safe)


class UploadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/send.sh":
            try:
                data = SEND_SH.read_bytes()
            except FileNotFoundError:
                self.send_error(404, "send.sh not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-sh")
            self.send_header("Content-Length", str(len(data)))
            # Encourage download, but pipe-to-bash will still work
            self.send_header("Content-Disposition",
                             'attachment; filename="send.sh"')
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(404, "Only GET /send.sh is allowed")

    def do_POST(self):
        print(f"\n[>] Incoming POST request from {
              self.client_address[0]} to {self.path}")

        if self.path != "/upload":
            print(f"[!] Invalid POST path: {self.path}")
            self.send_error(404, "Only POST /upload is allowed")
            return

        # Read content-length
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except Exception:
            print("[!] Missing or invalid Content-Length header")
            self.send_error(411, "Content-Length required")
            return

        if content_length <= 0:
            print("[!] Upload request had zero length")
            self.send_error(400, "Empty upload")
            return

        # Get filename from header (client sets this)
        raw_filename = self.headers.get("X-Filename", "")
        filename = sanitize_name(raw_filename) if raw_filename else None
        print(f"[i] Filename from client: {
              raw_filename} (sanitized: {filename})")

        # Prepare per-client directory
        client_ip_raw = self.client_address[0]
        client_ip = sanitize_name(client_ip_raw)
        ts = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        dest_dir = UPLOADS / f"{client_ip}_{ts}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        print(f"[i] Saving upload to: {dest_dir}")

        if filename:
            save_path = dest_dir / filename
        else:
            save_path = dest_dir / f"upload_{ts}.tar.gz"

        try:
            with open(save_path, "wb") as out_f:
                remaining = content_length
                while remaining > 0:
                    chunk_size = min(64 * 1024, remaining)
                    chunk = self.rfile.read(chunk_size)
                    if not chunk:
                        print("[!] Unexpected end of stream")
                        break
                    out_f.write(chunk)
                    remaining -= len(chunk)
            print(f"[+] File saved to disk: {save_path}")
        except Exception as e:
            print(f"[!] Failed saving upload: {e}")
            if save_path.exists():
                try:
                    save_path.unlink()
                    print(f"[i] Removed partial file {save_path}")
                except Exception:
                    pass
            self.send_error(500, f"Failed saving upload: {e}")
            return

        # Extraction
        name_lower = save_path.name.lower()
        try:
            if name_lower.endswith(".tar.gz") or name_lower.endswith(".tgz"):
                try:
                    with tarfile.open(save_path, "r:gz") as tf:
                        safe_extract(tf, dest_dir)
                    print(f"[+] Extracted archive into {dest_dir}")
                    save_path.unlink()
                    print(f"[i] Deleted tarball {save_path}")
                except Exception as e:
                    print(f"[!] Extraction failed: {e}")
                    self.send_error(500, f"Extraction failed: {e}")
                    return
            else:
                print(f"[!] Uploaded file is not a tar.gz: {
                      save_path}")
        except Exception as e:
            print(f"[!] Unexpected error handling upload: {e}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"File uploaded and processed successfully.\n")
        print(f"[+] Completed upload from {client_ip_raw}")


def main():
    print("\n--- Simple LAN upload server (single file) ---\n")
    # Ensure uploads exists
    UPLOADS.mkdir(parents=True, exist_ok=True)

    # Detect IP
    ip = get_local_ip()
    print(f"[i] Detected local IP: {ip}")

    # Prompt for port until free
    while True:
        try:
            port_input = input("Enter port to listen on (>=1024): ").strip()
            if not port_input:
                continue
            port = int(port_input)
            if not (1 <= port <= 65535):
                print("[!] Port must be in range 1-65535.")
                continue
            if port < 1024:
                print("[!] Ports below 1024 may require root. Please choose >=1024.")
                continue
        except ValueError:
            print("[!] Please enter a valid integer port.")
            continue

        if port_is_free(ip, port):
            break
        else:
            print(f"[!] Port {port} is not free on {ip}. Choose another port.")

    # Create send.sh with chosen ip:port
    create_send_sh(ip, port)

    # Start server bound to the detected IP (not 0.0.0.0) per spec
    server_address = (ip, port)
    httpd = HTTPServer(server_address, UploadHandler)
    print(f"[+] Server will listen at http://{ip}:{port}")
    print(f"[+] Clients can run: curl http://{ip}:{port}/send.sh | bash")
    print("[+] Uploads will be saved/extracted under:", UPLOADS)
    print("[+] Press Ctrl+C to stop the server and remove send.sh\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received - shutting down server...")
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass
        # remove the generated send.sh file on shutdown
        try:
            if SEND_SH.exists():
                SEND_SH.unlink()
                print("[+] Removed send.sh")
        except Exception as e:
            print(f"[!] Could not remove send.sh: {e}")
        print("[+] Server stopped. Goodbye.")


if __name__ == "__main__":
    main()
