from abc import ABC, abstractmethod

# Common OS / shell variables that are almost never application secrets.
# Probers can optionally strip these before the diff to reduce noise.
SYSTEM_KEYS: frozenset[str] = frozenset({
    "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
    "PWD", "OLDPWD", "LOGNAME", "MAIL", "SHLVL", "_",
    "HOSTNAME", "LS_COLORS", "LESS", "PAGER", "EDITOR",
    "XDG_RUNTIME_DIR", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS",
    "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "COLORTERM",
    "TERM_PROGRAM", "TERM_PROGRAM_VERSION",
})


class BaseProber(ABC):
    type: str = "base"

    @abstractmethod
    async def probe(self) -> dict[str, str]:
        """Return live environment variables as a key->value dict."""
        ...

    @staticmethod
    def filter_env(
        raw: dict[str, str],
        strip_system: bool = False,
        extra_strip: set[str] | None = None,
    ) -> dict[str, str]:
        """Remove noise keys from a raw env dict.

        Args:
            raw:          The unfiltered env dict from probe().
            strip_system: If True, remove well-known OS variables (SYSTEM_KEYS).
            extra_strip:  Any additional key names to remove.
        """
        blocked = (SYSTEM_KEYS if strip_system else set()) | (extra_strip or set())
        return {k: v for k, v in raw.items() if k not in blocked}

    @staticmethod
    def _parse_env_output(raw: str) -> dict[str, str]:
        """Parse newline-separated KEY=VALUE output (docker exec env, kubectl exec env)."""
        env: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
        return env
