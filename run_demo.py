#!/usr/bin/env python3
"""
SDN Firewall Demo Runner - compact menu UI with auto Mininet test execution.
"""

import getpass
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

WORKDIR = Path.home() / "cn"
ASKPASS_PATH = Path.home() / ".cn_sudo_askpass.sh"
WRAPPER_PATH = Path.home() / ".cn_mininet_wrapper.sh"
TMUX_SESSION = "cn_mininet"

CONTROLLER_TITLE = "CN-CONTROLLER"
MININET_TITLE = "CN-MININET"
TERMINAL_PROCS = {}


class C:
    H = "\033[95m"
    B = "\033[94m"
    C_ = "\033[96m"
    G = "\033[92m"
    W = "\033[93m"
    R = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


TESTS = {
    "a": ("Test 1: Allowed traffic", "h1 ping -c 3 10.0.0.2", C.G),
    "b": ("Test 2: Blocked IP (ICMP)", "h1 ping -c 3 10.0.0.3", C.R),
    "c": ("Test 3: Start iperf :5001", "h1 iperf -s -p 5001 &", C.W),
    "d": ("Test 4: Blocked port", "h1 iperf -s -p 5001 & ; h2 iperf -c 10.0.0.1 -p 5001 -t 5", C.R),
    "e": ("Test 5: Start iperf :5002", "h1 iperf -s -p 5002 &", C.W),
    "f": ("Test 6: Allowed port", "h1 iperf -s -p 5002 & ; h2 iperf -c 10.0.0.1 -p 5002 -t 5", C.G),
    "g": ("Test 7: Flow table", "sh ovs-ofctl -O OpenFlow13 dump-flows s1", C.C_),
    "h": ("Test 8: Blocked logs", "sh cat blocked_packets.log", C.C_),
}

# Commands to run for each test key. Multi-step tests run in sequence.
TEST_STEPS = {
    "a": ["h1 ping -c 3 10.0.0.2"],
    "b": ["h1 ping -c 3 10.0.0.3"],
    "c": ["h1 pkill -f iperf", "h1 iperf -s -p 5001 &"],
    "d": [
        "h1 pkill -f iperf",
        "h1 iperf -s -p 5001 &",
        "h2 iperf -c 10.0.0.1 -p 5001 -t 5",
    ],
    "e": ["h1 pkill -f iperf", "h1 iperf -s -p 5002 &"],
    "f": [
        "h1 pkill -f iperf",
        "h1 iperf -s -p 5002 &",
        "h2 iperf -c 10.0.0.1 -p 5002 -t 5",
    ],
    "g": ["sh ovs-ofctl -O OpenFlow13 dump-flows s1"],
    "h": ["sh cat blocked_packets.log"],
}

def header(text):
    print(f"\n{C.H}{C.BOLD}{'=' * 60}{C.END}")
    print(f"{C.H}{C.BOLD}{text.center(60)}{C.END}")
    print(f"{C.H}{C.BOLD}{'=' * 60}{C.END}\n")


def ok(msg):
    print(f"{C.G}+ {msg}{C.END}")


def info(msg):
    print(f"{C.C_}i {msg}{C.END}")


def warn(msg):
    print(f"{C.W}! {msg}{C.END}")


def err(msg):
    print(f"{C.R}x {msg}{C.END}")


def open_term(title, cmd):
    close_term(title)

    terms = [
        ["gnome-terminal", f"--title={title}", "--", "bash", "-lc", cmd],
        ["xterm", "-T", title, "-e", f"bash -lc \"{cmd}\""],
        ["konsole", "--new-tab", "-p", f"tabtitle={title}", "-e", "bash", "-lc", cmd],
        ["xfce4-terminal", "--title", title, "-e", f"bash -lc \"{cmd}\""],
    ]
    for term_cmd in terms:
        try:
            TERMINAL_PROCS[title] = subprocess.Popen(term_cmd, start_new_session=True)
            ok(f"Terminal opened: {title}")
            return True
        except FileNotFoundError:
            continue
    warn("No supported terminal emulator found")
    return False


def close_term(title):
    proc = TERMINAL_PROCS.pop(title, None)
    if proc is not None:
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
        except Exception:
            pass
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass

    # Best-effort fallback for terminal clients not represented by live Popen handles.
    subprocess.run(
        ["pkill", "-f", title],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def stop_controller_process():
    subprocess.run(
        ["pkill", "-f", "ryu-manager --ofp-tcp-listen-port 6633 controller/firewall_controller.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def write_scripts(password):
    askpass = f"#!/bin/sh\nprintf %s {shlex.quote(password)}\n"
    ASKPASS_PATH.write_text(askpass)
    os.chmod(ASKPASS_PATH, 0o700)

    wrapper = f"""#!/bin/bash
cd \"{WORKDIR}\" || exit 1
export SUDO_ASKPASS=\"{ASKPASS_PATH}\"
sudo -A python3 topology/simple_topology.py
"""
    WRAPPER_PATH.write_text(wrapper)
    os.chmod(WRAPPER_PATH, 0o700)


def tmux_session_exists():
    result = subprocess.run(
        ["tmux", "has-session", "-t", TMUX_SESSION],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def tmux_send(cmd):
    result = subprocess.run(
        ["tmux", "send-keys", "-t", TMUX_SESSION, cmd, "C-m"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def tmux_send_literal(cmd):
    result = subprocess.run(
        ["tmux", "send-keys", "-t", TMUX_SESSION, "-l", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def tmux_enter():
    result = subprocess.run(
        ["tmux", "send-keys", "-t", TMUX_SESSION, "Enter"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def wait_for_mininet_prompt(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        capture = subprocess.run(
            ["tmux", "capture-pane", "-p", "-t", TMUX_SESSION, "-S", "-120"],
            capture_output=True,
            text=True,
            check=False,
        )
        if capture.returncode == 0:
            tail = capture.stdout.rstrip()
            if tail.endswith("mininet>"):
                return True
        time.sleep(0.2)
    return False


def start_controller():
    cmd = "cd ~/cn && ryu-manager --ofp-tcp-listen-port 6633 controller/firewall_controller.py"
    return open_term(CONTROLLER_TITLE, cmd)


def start_mininet(password):
    write_scripts(password)
    subprocess.run(
        ["tmux", "kill-session", "-t", TMUX_SESSION],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    cmd = f"tmux new-session -A -s {TMUX_SESSION} 'bash {shlex.quote(str(WRAPPER_PATH))}'"
    return open_term(MININET_TITLE, cmd)


def prelaunch_cleanup(password):
    """Best-effort cleanup so launch does not fail on stale Mininet links."""
    try:
        subprocess.run(
            ["sudo", "-S", "mn", "-c"],
            input=(password + "\n").encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=12,
            check=False,
        )
    except Exception:
        pass

    # Extra safety for stale interface pairs from interrupted runs.
    stale_ifaces = ["h1-eth0", "h2-eth0", "h3-eth0", "s1-eth1", "s1-eth2", "s1-eth3"]
    for iface in stale_ifaces:
        try:
            subprocess.run(
                ["sudo", "-S", "ip", "link", "del", iface],
                input=(password + "\n").encode(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except Exception:
            pass


def launch(password):
    header("Launching")
    prelaunch_cleanup(password)
    start_controller()
    time.sleep(1)
    start_mininet(password)
    info("Ready for tests (select a-h after mininet> appears)")


def run_steps(steps):
    for i, cmd in enumerate(steps):
        if not wait_for_mininet_prompt(timeout=20):
            return False

        shown = tmux_send_literal(f"sh echo '[AUTO CMD] {cmd}'") and tmux_enter()
        if not shown:
            return False

        if not wait_for_mininet_prompt(timeout=10):
            return False

        ran = tmux_send_literal(cmd) and tmux_enter()
        if not ran:
            return False

        cmd_timeout = 50 if ("ping -c" in cmd or "iperf -c" in cmd) else 20
        if not wait_for_mininet_prompt(timeout=cmd_timeout):
            return False

        # Give a tiny gap between sequenced commands.
        if i < len(steps) - 1:
            time.sleep(0.8)
    return True


def send_cmd_to_mininet(test_key):
    if not tmux_session_exists():
        warn("Mininet session not found. Use option 1 first.")
        return

    steps = TEST_STEPS.get(test_key, [])
    if not steps:
        warn("No commands configured for this test key.")
        return

    if run_steps(steps):
        ok(f"Executed {len(steps)} command(s) for test {test_key}")
    else:
        warn("Failed to send command to Mininet session. Relaunch with option 1.")


def cleanup(password):
    header("Cleanup")

    try:
        if tmux_session_exists():
            tmux_send("exit")
            time.sleep(0.4)
            subprocess.run(
                ["tmux", "kill-session", "-t", TMUX_SESSION],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    except Exception:
        pass

    stop_controller_process()

    try:
        subprocess.run(
            ["sudo", "-S", "mn", "-c"],
            input=(password + "\n").encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=12,
            check=False,
        )
        ok("Mininet cleaned")
    except Exception as ex:
        warn(f"Cleanup warning: {ex}")

    close_term(MININET_TITLE)
    close_term(CONTROLLER_TITLE)

    for path in (
        ASKPASS_PATH,
        WRAPPER_PATH,
        Path("/tmp/cn_mininet_tty"),
        Path("/tmp/cn_mininet_cmd.fifo"),
        Path("/tmp/cn_mininet_mux.fifo"),
        Path("blocked_packets.log"),
    ):
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def show_tests():
    print(f"\n{C.B}{C.BOLD}Tests (auto-run in Mininet; choose a-h):{C.END}\n")
    for key, (name, cmd, color) in TESTS.items():
        print(f"  {C.BOLD}{key}{C.END} - {name}")
        print(f"       {color}{cmd}{C.END}")


def show_menu():
    print(f"\n{C.B}{C.BOLD}{'=' * 60}{C.END}")
    print(f"{C.B}{C.BOLD}{'SDN FIREWALL DEMO'.center(60)}{C.END}")
    print(f"{C.B}{C.BOLD}{'=' * 60}{C.END}\n")

    print(f"{C.BOLD}Main:{C.END}")
    print(f"  {C.G}1{C.END} - Launch controller + Mininet")
    print(f"  {C.W}2{C.END} - Cleanup")
    print(f"  {C.W}3{C.END} - Restart")
    show_tests()
    print(f"\n{C.BOLD}Exit:{C.END}")
    print(f"  {C.R}q{C.END} - Quit\n")
    print(f"{C.B}{C.BOLD}{'=' * 60}{C.END}\n")


def main():
    header("SDN Firewall Demo")
    password = getpass.getpass(f"{C.BOLD}Enter sudo password:{C.END} ")
    ok("Ready to start demo")

    while True:
        show_menu()
        choice = input(f"{C.BOLD}Enter choice:{C.END} ").strip().lower()

        if choice == "1":
            launch(password)
        elif choice == "2":
            cleanup(password)
        elif choice == "3":
            header("Restarting")
            cleanup(password)
            time.sleep(1)
            launch(password)
        elif choice in TESTS:
            name, cmd, _color = TESTS[choice]
            header(name)
            send_cmd_to_mininet(choice)
        elif choice == "q":
            header("Exiting")
            cleanup(password)
            print(f"{C.W}Done{C.END}\n")
            break
        else:
            err("Invalid choice")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.W}Interrupted{C.END}\n")
        sys.exit(0)
