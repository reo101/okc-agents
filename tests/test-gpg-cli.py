#!/usr/bin/env python3
"""Exercise the CLI through a fake Android broadcast and real TCP callbacks."""
import base64
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

DATA = bytes(range(256)) * 10


def frame(value):
    return struct.pack(">H", len(value)) + value


def callback(port, arguments):
    with socket.create_connection(("127.0.0.1", int(port)), timeout=3) as control:
        if arguments == ["ssh"]:
            request = b""
            while len(request) < 5:
                part = control.recv(5 - len(request))
                assert part, "SSH request was truncated"
                request += part
            assert request == b"\x00\x00\x00\x01\x0b", request
            control.sendall(b"\x00\x00\x00\x05\x0c\x00\x00\x00\x00")
            return
        control.sendall(b"\x00")
        if "--metadata" in arguments:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=3) as input_connection:
                input_connection.sendall(b"\x01" + frame(b"-"))
                time.sleep(0.2)
                control.sendall(b"\x00\x00\x00")
            return
        if "--check-permission" in arguments:
            control.sendall(b"\x00\x00\x00")
            return
        with socket.create_connection(("127.0.0.1", int(port)), timeout=3) as output:
            output.sendall(b"\x02" + frame(b"-") + frame(DATA) + b"\x00\x00")
        control.sendall(frame(b"[GNUPG:] SIG_CREATED") + b"\x00\x00\x00")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "callback":
        callback(sys.argv[2], sys.argv[3:])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "broadcast":
        arguments = sys.argv[1:]
        assert "--user" in arguments, arguments
        assert arguments[arguments.index("--user") + 1] == "0", arguments
        port = arguments[arguments.index("org.ddosolitary.okcagent.extra.PROXY_PORT") + 1]
        if any("SshProxyReceiver" in item for item in arguments):
            forwarded = ["ssh"]
        else:
            assert arguments[arguments.index("org.ddosolitary.okcagent.extra.GPG_PROTO_VER") + 1] == "2"
            encoded = arguments[arguments.index("org.ddosolitary.okcagent.extra.GPG_ARGS") + 1]
            forwarded = [base64.b64decode(item).decode() for item in encoded.split(",")]
        subprocess.Popen([sys.executable, __file__, "callback", port, *forwarded], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Broadcast completed: result=0")
        return
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as directory:
        broadcast = Path(directory) / "am"
        broadcast.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(Path(__file__).resolve())!r}, run_name='__main__')\n")
        broadcast.chmod(0o755)
        environment = {**os.environ, "AM": str(broadcast), "RUST_LOG": "debug"}
        for arguments in [["--check-permission"], ["--export", "0123456789ABCDEF"], ["--detach-sign", "--status-fd", "2"]]:
            result = subprocess.run([str(binary), *arguments], env=environment, input=b"", capture_output=True, timeout=10)
            assert result.returncode == 0, result.stderr
            assert result.stdout == (b"" if "--check-permission" in arguments else DATA), result.stdout
            assert b"Broadcast completed" not in result.stdout
            if "--status-fd" in arguments:
                assert b"\n[GNUPG:] SIG_CREATED\n" in result.stderr, result.stderr
        early = subprocess.Popen([str(binary), "--decrypt", "--metadata"], env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert early.wait(timeout=5) == 0, early.stderr.read()
            assert early.stdout.read() == b""
        finally:
            early.stdin.close()
            if early.poll() is None:
                early.kill()
                early.wait()
        result = subprocess.run([str(binary), "--list-secret-keys"], env=environment, capture_output=True, timeout=10)
        assert result.returncode != 0 and result.stdout == b"", result
        assert b"not supported" in result.stderr, result.stderr
        if len(sys.argv) > 2:
            endpoint = str(Path(directory) / "agent.sock")
            agent = subprocess.Popen([str(Path(sys.argv[2]).resolve()), "start", "--foreground", "--addr", endpoint], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not Path(endpoint).exists():
                    assert agent.poll() is None, agent.communicate()
                    assert time.monotonic() < deadline, "SSH agent startup timeout"
                    time.sleep(0.02)
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5)
                    client.connect(endpoint)
                    client.sendall(b"\x00\x00\x00\x01\x0b")
                    response = b""
                    while len(response) < 9:
                        part = client.recv(9 - len(response))
                        assert part, "SSH agent closed before returning identities"
                        response += part
                    assert response == b"\x00\x00\x00\x05\x0c\x00\x00\x00\x00", response
                agent.terminate()
                assert agent.wait(timeout=5) == 0
                assert not Path(endpoint).exists()
            finally:
                if agent.poll() is None:
                    agent.kill()
                    agent.wait()
    print("GPG stdout, broadcast capture, status, lazy streams and SSH transport tests passed")


if __name__ == "__main__":
    main()
