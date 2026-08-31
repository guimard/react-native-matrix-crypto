// The third-party counterparty for verification by scanning a code.
//
// # Why a second counterparty, and why Go
//
// `nio_party.py` is the counterparty for every other level 2 proof, and it
// cannot serve this one. matrix-nio 0.26.0 contains no QR vocabulary and no
// cross-signing vocabulary at all, established by grepping the installed
// wheel; a code carries cross-signing keys, so an implementation with
// neither cannot scan even in principle.
//
// mautrix-go v0.30.0 carries `crypto/verificationhelper`, which implements
// all three modes the specification defines, on both sides: it builds the
// payload in `qrcode.go` against the byte layout in section 11.12.2.4.1, and
// `reciprocate.go` reads one, checks the keys mode by mode, and refuses with
// `m.key_mismatch` when they do not match. Its cross-signing lives in
// `crypto/cross_sign*.go` and it publishes a master key over the real
// client-server API.
//
// None of that is Rust and none of it is `matrix-sdk-crypto`, so what this
// process and this library agree on is the wire rather than a shared
// implementation of it.
//
// # Protocol
//
// Newline-delimited JSON on stdin, one JSON reply per line on stdout. The
// Rust test owns the sequencing; this process only does what it is told, so
// a failure is attributable to a step rather than to a race between two
// long-running clients. The same shape `nio_party.py` uses, for the same
// reason.
//
// Nothing is ever printed on stdout outside that protocol. Diagnostics go to
// stderr, which the Rust harness captures and prints only when a step fails.
//
// # Credentials
//
// The password arrives in the environment (`MATRIX_INTEROP_PASSWORD`) and is
// read once, into a local, at login. It is never written to a file, never
// echoed into a reply, and never placed on a command line, where `ps` would
// show it.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// The environment variable the account password arrives in. Named once.
const passwordEnv = "MATRIX_INTEROP_PASSWORD"

// Not a credential: the crypto store is in memory and dies with this
// process, so the pickle key protects nothing that outlives the run.
var pickleKey = []byte("level-two-scanned")

// party holds the whole of this process's state. One client, one machine,
// one verification helper: this counterparty is a single device, and every
// operation below acts on it.
type party struct {
	client *mautrix.Client
	mach   *crypto.OlmMachine
	helper *verificationhelper.VerificationHelper

	// What the helper's callbacks have seen, in arrival order, drained by
	// the `events` operation. A test asserts on this rather than on a
	// state the helper exposes, because the callbacks are the whole of
	// what a client using this library would be told.
	mu       sync.Mutex
	observed []map[string]any

	// The code this party is being shown, per flow, as handed to the
	// `VerificationReady` callback. `nil` there is a real answer and is
	// kept as one: it means the helper declined to build a code, and the
	// `code` operation reports which of the two it was.
	shown map[string]*verificationhelper.QRCode

	// Which flows the other side has scanned, from `QRCodeScanned`.
	scanned map[string]bool

	// The sync token, threaded through every `sync` operation.
	since string
}

func (p *party) record(entry map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observed = append(p.observed, entry)
}

// The four callbacks `RequiredCallbacks` demands, plus the one
// `ShowQRCodeCallbacks` demands. Recording rather than acting: every
// decision belongs to the Rust test driving this process.

func (p *party) VerificationRequested(ctx context.Context, txnID id.VerificationTransactionID, from id.UserID, fromDevice id.DeviceID) {
	p.record(map[string]any{
		"event":       "requested",
		"flow":        txnID.String(),
		"from":        from.String(),
		"from_device": fromDevice.String(),
	})
}

func (p *party) VerificationReady(ctx context.Context, txnID id.VerificationTransactionID, otherDeviceID id.DeviceID, supportsSAS, supportsScanQRCode bool, qrCode *verificationhelper.QRCode) {
	p.mu.Lock()
	p.shown[txnID.String()] = qrCode
	p.mu.Unlock()
	entry := map[string]any{
		"event":            "ready",
		"flow":             txnID.String(),
		"their_device":     otherDeviceID.String(),
		"supports_sas":     supportsSAS,
		"supports_scan":    supportsScanQRCode,
		"code_was_offered": qrCode != nil,
	}
	if qrCode != nil {
		entry["mode"] = int(qrCode.Mode)
	}
	p.record(entry)
}

func (p *party) VerificationCancelled(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string) {
	p.record(map[string]any{
		"event":  "cancelled",
		"flow":   txnID.String(),
		"code":   string(code),
		"reason": reason,
	})
}

func (p *party) VerificationDone(ctx context.Context, txnID id.VerificationTransactionID, method event.VerificationMethod) {
	p.record(map[string]any{
		"event":  "done",
		"flow":   txnID.String(),
		"method": string(method),
	})
}

func (p *party) QRCodeScanned(ctx context.Context, txnID id.VerificationTransactionID) {
	p.mu.Lock()
	p.scanned[txnID.String()] = true
	p.mu.Unlock()
	p.record(map[string]any{"event": "our_code_scanned", "flow": txnID.String()})
}

// ShowSAS is required only because this party announces `m.sas.v1` as well.
// It announces it because a counterparty that offered nothing but a code
// would make the negotiation trivially agree, and the thing being proven is
// that two implementations negotiate a code out of a list that has both.
func (p *party) ShowSAS(ctx context.Context, txnID id.VerificationTransactionID, emojis []rune, emojiDescriptions []string, decimals []int) {
	p.record(map[string]any{"event": "sas_shown", "flow": txnID.String()})
}

func stringField(cmd map[string]any, name string) (string, error) {
	raw, ok := cmd[name]
	if !ok {
		return "", fmt.Errorf("the command has no %q field", name)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("the %q field is not a string", name)
	}
	return value, nil
}

func (p *party) login(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	homeserver, err := stringField(cmd, "homeserver")
	if err != nil {
		return nil, err
	}
	user, err := stringField(cmd, "user")
	if err != nil {
		return nil, err
	}
	displayName, err := stringField(cmd, "display_name")
	if err != nil {
		return nil, err
	}
	password := os.Getenv(passwordEnv)
	if password == "" {
		return nil, fmt.Errorf("%s is unset or empty", passwordEnv)
	}

	client, err := mautrix.NewClient(homeserver, "", "")
	if err != nil {
		return nil, err
	}
	if _, err = client.Login(ctx, &mautrix.ReqLogin{
		Type:                     mautrix.AuthTypePassword,
		Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: user},
		Password:                 password,
		InitialDeviceDisplayName: displayName,
		StoreCredentials:         true,
	}); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	client.StateStore = mautrix.NewMemoryStateStore()
	helper, err := cryptohelper.NewCryptoHelper(client, pickleKey, crypto.NewMemoryStore(nil))
	if err != nil {
		return nil, err
	}
	client.Crypto = helper
	if err = helper.Init(ctx); err != nil {
		return nil, err
	}
	p.client = client
	p.mach = helper.Machine()

	// The device keys and one-time keys, without which nothing can address
	// this device.
	if err = p.mach.ShareKeys(ctx, 50); err != nil {
		return nil, fmt.Errorf("failed to publish keys: %w", err)
	}

	// Announced: showing a code, scanning one, and the short string. The
	// helper derives `m.reciprocate.v1` from the first two itself.
	p.helper = verificationhelper.NewVerificationHelper(
		client, p.mach, verificationhelper.NewInMemoryVerificationStore(), p, true, true, true,
	)
	if err = p.helper.Init(ctx); err != nil {
		return nil, err
	}

	return map[string]any{
		"user_id":    client.UserID.String(),
		"device_id":  client.DeviceID.String(),
		"ed25519":    p.mach.OwnIdentity().SigningKey.String(),
		"curve25519": p.mach.OwnIdentity().IdentityKey.String(),
	}, nil
}

// bootstrapIdentity publishes a cross-signing identity for this account and,
// unless told otherwise, signs the master key with this device's own key.
//
// That signature is the whole of what decides which self mode this party
// produces: `generateQRCode` asks `IsKeySignedBy(user, masterKey, user,
// ownDeviceKey)` and picks mode 0x01 when it holds and 0x02 when it does
// not. A test that wants the untrusted mode asks for the signature to be
// withheld, which is what a device that has just logged in actually looks
// like.
func (p *party) bootstrapIdentity(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	password := os.Getenv(passwordEnv)
	if password == "" {
		return nil, fmt.Errorf("%s is unset or empty", passwordEnv)
	}
	if _, _, err := p.mach.GenerateAndUploadCrossSigningKeysWithPassword(ctx, password, ""); err != nil {
		return nil, fmt.Errorf("failed to publish a cross-signing identity: %w", err)
	}
	if err := p.mach.SignOwnDevice(ctx, p.mach.OwnIdentity()); err != nil {
		return nil, fmt.Errorf("failed to sign own device: %w", err)
	}
	if err := p.mach.SignOwnMasterKey(ctx); err != nil {
		return nil, fmt.Errorf("failed to sign own master key: %w", err)
	}
	return p.identityState(ctx)
}

// identityState reports the two facts every mode decision here turns on:
// which master key this party sees for its own account, and whether this
// device has signed it.
func (p *party) identityState(ctx context.Context) (map[string]any, error) {
	keys, err := p.mach.GetOwnCrossSigningPublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		return map[string]any{"master_key": nil, "master_key_trusted": false}, nil
	}
	trusted, err := p.mach.CryptoStore.IsKeySignedBy(
		ctx, p.client.UserID, keys.MasterKey, p.client.UserID, p.mach.OwnIdentity().SigningKey,
	)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"master_key":         keys.MasterKey.String(),
		"master_key_trusted": trusted,
	}, nil
}

// fetchKeys asks the homeserver for a user's devices and cross-signing keys,
// which is what a client does when it learns the user exists.
func (p *party) fetchKeys(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	user, err := stringField(cmd, "user")
	if err != nil {
		return nil, err
	}
	userID := id.UserID(user)
	keys, err := p.mach.FetchKeys(ctx, []id.UserID{userID}, true)
	if err != nil {
		return nil, err
	}
	devices := []string{}
	for deviceID := range keys[userID] {
		devices = append(devices, deviceID.String())
	}
	result := map[string]any{"devices": devices}
	if signing, err := p.mach.GetCrossSigningPublicKeys(ctx, userID); err == nil && signing != nil {
		result["master_key"] = signing.MasterKey.String()
	} else {
		result["master_key"] = nil
	}
	return result, nil
}

// sync runs one /sync and dispatches what came back, which is how every
// to-device event this party acts on reaches it.
func (p *party) sync(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	timeout := 0
	if raw, ok := cmd["timeout_ms"]; ok {
		if value, ok := raw.(float64); ok {
			timeout = int(value)
		}
	}
	resp, err := p.client.SyncRequest(ctx, timeout, p.since, "", false, event.PresenceOnline)
	if err != nil {
		return nil, err
	}
	delivered := len(resp.ToDevice.Events)
	if err = p.client.Syncer.ProcessResponse(ctx, resp, p.since); err != nil {
		return nil, err
	}
	p.since = resp.NextBatch
	return map[string]any{"to_device_events": delivered}, nil
}

func (p *party) startFlow(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	user, err := stringField(cmd, "user")
	if err != nil {
		return nil, err
	}
	txnID, err := p.helper.StartVerification(ctx, id.UserID(user))
	if err != nil {
		return nil, err
	}
	return map[string]any{"flow": txnID.String()}, nil
}

func (p *party) acceptFlow(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	flow, err := stringField(cmd, "flow")
	if err != nil {
		return nil, err
	}
	if err = p.helper.AcceptVerification(ctx, id.VerificationTransactionID(flow)); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

// code hands back the payload this party is showing for a flow, base64 so it
// survives the JSON line. The bytes are what a camera would read off its
// screen.
func (p *party) code(cmd map[string]any) (map[string]any, error) {
	flow, err := stringField(cmd, "flow")
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	qrCode, known := p.shown[flow]
	p.mu.Unlock()
	if !known {
		return nil, fmt.Errorf("this party was never told a flow named %q was ready", flow)
	}
	if qrCode == nil {
		return map[string]any{"offered": false}, nil
	}
	return map[string]any{
		"offered": true,
		"mode":    int(qrCode.Mode),
		"payload": hex.EncodeToString(qrCode.Bytes()),
	}, nil
}

// scan hands this party a payload as though a camera had read it. Hexadecimal
// rather than base64 so the transport needs no dependency on either side; the
// bytes are what a camera would read off a screen. The error
// is reported rather than raised: a refusal is a result this proof asks for
// on purpose, and a transport that turned it into a failed command could not
// tell it apart from a broken step.
func (p *party) scan(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	flow, err := stringField(cmd, "flow")
	if err != nil {
		return nil, err
	}
	encoded, err := stringField(cmd, "payload")
	if err != nil {
		return nil, err
	}
	payload, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("the payload is not hexadecimal: %w", err)
	}
	// `flow` is carried only so a caller can name what it meant; the
	// identifier this party acts on is the one inside the payload, which
	// is the whole point of the format.
	_ = flow
	if err = p.helper.HandleScannedQRData(ctx, payload); err != nil {
		return map[string]any{"accepted": false, "refusal": err.Error()}, nil
	}
	return map[string]any{"accepted": true}, nil
}

func (p *party) confirm(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	flow, err := stringField(cmd, "flow")
	if err != nil {
		return nil, err
	}
	if err = p.helper.ConfirmQRCodeScanned(ctx, id.VerificationTransactionID(flow)); err != nil {
		return map[string]any{"confirmed": false, "refusal": err.Error()}, nil
	}
	return map[string]any{"confirmed": true}, nil
}

// deviceTrust reports what this party now believes about a device, which is
// the only end-state assertion that matters: a verification that completes
// and leaves the peer untrusted has not verified anything.
func (p *party) deviceTrust(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	user, err := stringField(cmd, "user")
	if err != nil {
		return nil, err
	}
	device, err := stringField(cmd, "device")
	if err != nil {
		return nil, err
	}
	identity, err := p.mach.GetOrFetchDevice(ctx, id.UserID(user), id.DeviceID(device))
	if err != nil {
		return nil, err
	}
	// Two different facts, and the second is the one a cross-user
	// verification is for. `Trust` is what the store records for that one
	// device; `ResolveTrustContext` also follows the cross-signing chain,
	// so a device this party never touched reads verified once its owner's
	// master key is signed.
	resolved, err := p.mach.ResolveTrustContext(ctx, identity)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"trust":          identity.Trust.String(),
		"resolved_trust": resolved.String(),
		"ed25519":        identity.SigningKey.String(),
	}
	userTrusted, err := p.mach.IsUserTrusted(ctx, id.UserID(user))
	if err != nil {
		return nil, err
	}
	result["user_trusted"] = userTrusted
	return result, nil
}

func (p *party) events() (map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	drained := p.observed
	p.observed = nil
	if drained == nil {
		drained = []map[string]any{}
	}
	return map[string]any{"events": drained}, nil
}

func (p *party) logout(ctx context.Context) (map[string]any, error) {
	if p.client == nil {
		return map[string]any{}, nil
	}
	if _, err := p.client.Logout(ctx); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

func (p *party) dispatch(ctx context.Context, cmd map[string]any) (map[string]any, error) {
	op, err := stringField(cmd, "op")
	if err != nil {
		return nil, err
	}
	switch op {
	case "login":
		return p.login(ctx, cmd)
	case "bootstrap_identity":
		return p.bootstrapIdentity(ctx, cmd)
	case "identity_state":
		return p.identityState(ctx)
	case "fetch_keys":
		return p.fetchKeys(ctx, cmd)
	case "sync":
		return p.sync(ctx, cmd)
	case "start_flow":
		return p.startFlow(ctx, cmd)
	case "accept_flow":
		return p.acceptFlow(ctx, cmd)
	case "code":
		return p.code(cmd)
	case "scan":
		return p.scan(ctx, cmd)
	case "confirm":
		return p.confirm(ctx, cmd)
	case "device_trust":
		return p.deviceTrust(ctx, cmd)
	case "events":
		return p.events()
	case "logout":
		return p.logout(ctx)
	default:
		return nil, fmt.Errorf("unknown operation %q", op)
	}
}

func main() {
	// Everything this library logs goes to stderr. stdout carries the
	// protocol and nothing else, so a stray log line cannot be read as a
	// reply.
	logger := zerolog.New(os.Stderr).Level(zerolog.WarnLevel).With().Timestamp().Logger()
	ctx := logger.WithContext(context.Background())

	p := &party{
		shown:   map[string]*verificationhelper.QRCode{},
		scanned: map[string]bool{},
	}

	out := bufio.NewWriter(os.Stdout)
	reader := bufio.NewReader(os.Stdin)
	// A code payload is about 126 bytes and a reply carrying one is well
	// under a kilobyte, but a device list is not bounded by anything this
	// process controls, so the line length is not either.
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var cmd map[string]any
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			writeReply(out, map[string]any{"ok": false, "error": fmt.Sprintf("unparseable command: %v", err)})
			continue
		}
		if op, _ := cmd["op"].(string); op == "quit" {
			writeReply(out, map[string]any{"ok": true})
			return
		}
		// Each command gets its own deadline so a homeserver that stops
		// answering fails the step that touched it rather than hanging
		// the whole run.
		stepCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		reply, err := p.dispatch(stepCtx, cmd)
		cancel()
		if err != nil {
			writeReply(out, map[string]any{"ok": false, "error": err.Error()})
			continue
		}
		if reply == nil {
			reply = map[string]any{}
		}
		reply["ok"] = true
		writeReply(out, reply)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "stdin failed: %v\n", err)
		os.Exit(1)
	}
}

func writeReply(out *bufio.Writer, reply map[string]any) {
	encoded, err := json.Marshal(reply)
	if err != nil {
		// The only way this fails is a value the protocol should never
		// have carried, and answering nothing would hang the caller.
		encoded = []byte(`{"ok":false,"error":"the reply could not be encoded"}`)
	}
	out.Write(encoded)
	out.WriteByte('\n')
	out.Flush()
}
