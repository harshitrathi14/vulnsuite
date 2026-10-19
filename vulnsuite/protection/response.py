"""IP-only, expiring nftables response. No shell or remotely supplied commands."""
import ipaddress
import subprocess


def allowed_ip(value: str, protected: list[str], permitted: list[str]) -> str:
    ip = ipaddress.ip_address(value)
    if (ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local
            or ip.is_reserved):
        raise ValueError("non-unicast or special address")
    if any(ip in ipaddress.ip_network(net) for net in protected):
        raise ValueError("protected address")
    if not any(ip in ipaddress.ip_network(net) for net in permitted):
        raise ValueError("address outside response policy")
    return str(ip)


def block_ip(ip: str, seconds: int, protected: list[str], permitted: list[str]):
    ip = allowed_ip(ip, protected, permitted)
    if not 60 <= seconds <= 3600:
        raise ValueError("invalid duration")
    name = "blocked_v4" if ipaddress.ip_address(ip).version == 4 else "blocked_v6"
    # The named set must already exist and support timeout; never alter unrelated rules.
    subprocess.run(
        ["/usr/sbin/nft", "add", "element", "inet", "vulnsuite", name,
         "{", ip, "timeout", f"{seconds}s", "}"],
        check=True, capture_output=True, timeout=10,
    )
