// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replaytest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
)

// SuiteVersion identifies the contract version this suite verifies. A
// compliant adapter exposes ConformsTo() string returning this value; a host
// compares the two for equality at assembly time. The value is versioned on
// its own and does not follow the storagetest, sessiontest and keymgmttest
// versions.
const SuiteVersion = "1.0.0"

// Option configures a suite run.
type Option func(*options)

type options struct {
	may bool
}

// WithMay enables the MAY-graded cases. Without it only the MUST cases are
// registered.
func WithMay(enabled bool) Option {
	return func(o *options) { o.may = enabled }
}

type suiteCase struct {
	name string
	run  func(t *testing.T, newRegistry func() replay.Registry)
}

// RunRegistrySuite runs the conformance cases against registries produced by
// newRegistry, which must return a new, empty registry on every call.
func RunRegistrySuite(t *testing.T, newRegistry func() replay.Registry, opts ...Option) {
	t.Helper()

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	for _, c := range mustCases {
		t.Run("MUST/"+c.name, func(t *testing.T) { c.run(t, newRegistry) })
	}
	if !o.may {
		return
	}
	for _, c := range mayCases {
		t.Run("MAY/"+c.name, func(t *testing.T) { c.run(t, newRegistry) })
	}
}

// The suite's whole notion of time. baseInstant lies far enough ahead that
// every instant derived from it is in the real future whenever the suite
// runs; pastInstant is in the real past. Only
// ExpiredButUnreclaimedIsStillDuplicate uses pastInstant, and it uses nothing
// else.
var (
	baseInstant = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	pastInstant = time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// at returns baseInstant shifted by offset.
func at(offset time.Duration) time.Time {
	return baseInstant.Add(offset)
}

// concurrencyTimeout bounds a whole concurrency case, so a registry that
// blocks fails the case instead of hanging the run.
const concurrencyTimeout = 30 * time.Second

// Keys used by the single-goroutine cases. firstCharKey and lastCharKey
// differ from plainKey in exactly their first and their last character.
const (
	plainKey     = "a583f602d9fca64f00c09764beca891b0ab02dcc70c010c2dd2e84542519d82a"
	firstCharKey = "b583f602d9fca64f00c09764beca891b0ab02dcc70c010c2dd2e84542519d82a"
	lastCharKey  = "a583f602d9fca64f00c09764beca891b0ab02dcc70c010c2dd2e84542519d82b"
	secondKey    = "e7f695328fd198be5f15861c109609a1117c2e574bcf17b813e032c946beef05"
	thirdKey     = "a3a8199baf2b548d50f50cd5d03aabdf05564ffcb78433dab0912f23e7a2ba8c"
)

// contentionKeys feeds the concurrency cases: one key per round where all
// goroutines share a key, one key per goroutine where they do not.
var contentionKeys = [64]string{
	"464181a9e5b747b2a4482e63b1dc57fe54c4ab9a186d7c449d5c363119e143d3",
	"050f21edd4c3e454eb4b0d8df4029f3f4a9db14f11c556520c0cf74652daf279",
	"ddad33b680e5751fb01359d5cd1d57721d6a28b5210f8b92ddec316a3279f098",
	"2a5e3c73396e234ff7918ca81098b527a6e558ede146496dcfa0a5482c2f0b67",
	"9a1cf895c45b209fa80c8bb3ab27975302194bb08fe4faf36ceb5856aa5f7ada",
	"d9165b63eb70d0580acf00aaeae4832f1c371e83f74d4806d03e7a75524774dd",
	"c1f25420217d39c547de89022c44a65b097d4cecd0867acec6594d789ba4a9fd",
	"73e7e4fc46f276874248f78877b06d16dc8f48409ac6e9e24dbe43ee163209b4",
	"fd4fa38c98767184029f6d2b2e109a88ff11e2e9f6f98d71899fbe63511f78d2",
	"1e5913f997ddd2538f97a3c2f8faa47c388766e2848ea21681cc782ce1adbd1b",
	"d35e757d8667e77943326b7b0d8613635c2dea4b2773a1c57eba933105e18965",
	"eec8953de88544923f55832d158fc1bb1e1924765e49afbefba001fc60d6ca51",
	"a3c0512012aa342a96fb3e79d0cd268edbc6467f2e50dd02e2fb3741e141f4e2",
	"2e91181bc60dc131e42d6d027d14760d060714428a3ceb3886e861677beb18f6",
	"31243027bfc918ca8cb7afe177965c937443577ce99d90dd6d73b45fc7e7af82",
	"9b02a4e6117ed7e123e9befe547c4f721bc1ae6d49d2d4cdbb21101dce39a9a6",
	"aa8d7844407486a0e2f3479a224ddf379c2c8869f3885b85392f495f0ab35440",
	"66f6b215c1e4731629c7ef3a37772cbe4ee292a9e82c3a0d0584611b8e7dd7ab",
	"0e373a340cf6c35fa82a171538fc63201ed4b0d4ba82b57dcdf9365759074b1f",
	"825d6fdb9fff62660e425221f7ea98a6c4a2ef5c4698814a9a5e4a04dd42caf0",
	"e97cc03b9096127188f6131b621cf8c76450b52881fe3dd1dce0e47c0b7ab429",
	"e805c042e07bce985fe31869009d7b117891ecd13521d44135adf2bef7eca66a",
	"3cecb9449d22738993d7901c79e35bc0e79ea276388a23e0054ef02e0152ba15",
	"b3773c1574d78af17caa6232588e558fb3178a4d6d906ef9dd9564002d929a23",
	"3ba94dae594425afef8dd5c9f16859c0ac3ded2cdf7065802ece83789b1e860c",
	"29cbdb451a363515db105bef8fa50f6a7d51c98532b5c7d8bc7ef9c7f3bc9e62",
	"0024053dd160fd77359c9f71bf04ac7fcc1b34b7fef815ea1da4a1e34e4331d9",
	"5fffb95e5f0c8c40ccd6c1b379d6dd48d1d37a08c763bb0d9ac980276187ccf9",
	"174a3d85e4a646e2b1d0b74ab393a40c1c17a102dbe6b5ce6201c59214c1cabc",
	"ccd47ddeb0d381c4f0d5b13a584a112f72dabab3a9a75d55e5e90ecb3c2d71ca",
	"a6e85adb72916c0735fe7ead4671842790883716e13de55492c3c65f54d098eb",
	"27ecd1d9e1fd7030c9d9a2222b3702d27f996e7b470c1cbd933e6988a32bf422",
	"e24fd423e0b00988399e10f2acad62e2696fa31c65648a6bcfd52460810ce97b",
	"fc5aa9b457d9143decc4ea00a0b5da70589c713e802ba37f9ee04d47060ee855",
	"e9d40c7fa9018998fc0a3b770b198100da5aaed29cb6608f2c95773693903441",
	"5360aaa848fba348e3dac16fd61da74c556990fd70c957f6af12d4779a12227d",
	"20b29710d7ea70502f9b01d81d5c3c8b490c751fa3124dbd91952dc76e3b03fe",
	"11b8fbb2f71a77b5d67082afa4457fe7e780bf58ffe4539a09ada75d234b8eeb",
	"2c57e6a6e69c5205e8d9b8b0eb1b5eef1e2c8c20cf06c0c987f4d07252c0bf72",
	"2778ea0cac9f71671f9c38ac13f3e6402c14f01bfe87756163f6b8910ae048e5",
	"436d62721f75ff281db5273f527545829abd532bbdac6281518452926983e1cd",
	"057de957c9a75330aca49f0bb5d6fef5c68b8f3d2a41bebf7d50a04601155cb1",
	"969786b1245e89919c22d05acb3b25d0f108044b1a95bb2ff9a7eea2e9ad7ac1",
	"f690ac15ed69bbdfa6a2467720d047fd4940cc0b2fc446d80be90fb0fdf2d59b",
	"f28c8f26ae1ff281bf9f2841eae6c5364e1731a14b4ae39af172d4838d7b8801",
	"a840a8f8da9070db8861e20de649e758b3de9e8d9b459296e2d57cda5e93b784",
	"c1fc483225371e75f8ebd402b500332e680d555a3eb56f1fa68ae3e10f97b962",
	"8b6958fc918a77d60f5ad57c864fd76d1580fd28f5c2b61298c804920151938f",
	"8e4b8a98c6c971911b841ae5de49e0d538ff13f14a508e07bff82543abd731c7",
	"bb876103ddb0b3c11f0d8b56f34760cb4503a75618b45a1003e3d14e3fa53908",
	"a2238c4ebcc3942988b8613144f05c7af88f2d5766a6ee66e6050943300f2655",
	"1111cba4e1dfdf3333edb14e4b9c0d37dd84205ae3ef22a672d578fe08bb7d8b",
	"89b01fd5e76c1828193185e8d0b51e44b9f4d82c3da684dfc92cf802453f176d",
	"3c5eb4060fa5407eab4e392b7b1403c6f9b94d17dbbf4da6c8876b2c1663f0e8",
	"49d63efdcfc18127438378c9c6dbb83257acc319a2e2a5af843d58ffb1446a44",
	"f0f7fdf1ed62efc6963167d646a7cfa3d14e59b3d2eef2eb8a27cc5b1ee62d81",
	"e78139f90b71ab4e827b06be176975dd5c5935c5aed691f53c1666a3d79c928c",
	"8f5c8d2e8b10f2abc2591fbb409235d034532b5d62148ed92dd0540ac5e072b2",
	"39f767eb8205c8f5c57569fd3609f56517fbe253c064abb8c1dac8f42aaff46e",
	"e77624e5d49099cb5bdaecd65cff37afda4339c3b867d964c105bcd85ec54fb2",
	"24183c31ea3771b24d6c93955d7834ffeeca6682759330384ffffbfe8ca784c4",
	"0d11b356cbeb72b16433844a6bb80a9aef50a31038d017a3530951cde3b859b0",
	"d9aa360c5ad62de80eecbd138459bd093f2e8b4c2d12e6da225905645e215553",
	"89233292b0955078fc22b575d2954baf367074262006fe94fdacf9a9681b62f3",
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// registerFirst registers a key that must not be registered yet.
func registerFirst(t *testing.T, registry replay.Registry, key string, expiresAt time.Time) {
	t.Helper()
	if err := registry.Register(context.Background(), key, expiresAt); err != nil {
		t.Fatalf("Register of an unregistered key = %v, want nil", err)
	}
}

// registerDuplicate registers a key that must already be registered.
func registerDuplicate(t *testing.T, registry replay.Registry, key string, expiresAt time.Time) {
	t.Helper()
	err := registry.Register(context.Background(), key, expiresAt)
	if !errors.Is(err, replay.ErrDuplicateHandle) {
		t.Fatalf("Register of a registered key = %v, want an error matching replay.ErrDuplicateHandle", err)
	}
}

// removeExpired reclaims at cutoff and checks the reported count.
func removeExpired(t *testing.T, registry replay.Registry, cutoff time.Time, want int) {
	t.Helper()
	removed, err := registry.RemoveExpired(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("RemoveExpired = (%d, %v), want (%d, nil)", removed, err, want)
	}
	if removed != want {
		t.Fatalf("RemoveExpired removed %d records, want %d", removed, want)
	}
}

// registerTogether registers through registry from n goroutines at the same
// moment and returns every result. Each goroutine reports that it is ready
// and then blocks on one gate; the gate opens only after all n have reported.
// keyFor picks the key of goroutine i. The call fails the test when deadline
// fires before all goroutines have returned.
func registerTogether(t *testing.T, registry replay.Registry, n int, keyFor func(i int) string, deadline <-chan time.Time) []error {
	t.Helper()

	expiresAt := at(time.Hour)
	ready := make(chan struct{}, n)
	gate := make(chan struct{})
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		key := keyFor(i)
		go func() {
			ready <- struct{}{}
			<-gate
			results <- registry.Register(context.Background(), key, expiresAt)
		}()
	}
	for i := 0; i < n; i++ {
		<-ready
	}
	close(gate)

	errs := make([]error, 0, n)
	for len(errs) < n {
		select {
		case err := <-results:
			errs = append(errs, err)
		case <-deadline:
			t.Fatalf("%d of %d concurrent Register calls had not returned after %s", n-len(errs), n, concurrencyTimeout)
		}
	}
	return errs
}

// singleWinnerRounds runs rounds of n goroutines registering one key, on a
// new registry and a new key each round, and requires exactly one nil and
// n-1 duplicates per round.
func singleWinnerRounds(t *testing.T, newRegistry func() replay.Registry, n, rounds int) {
	t.Helper()

	deadline := time.NewTimer(concurrencyTimeout)
	defer deadline.Stop()

	for round := 0; round < rounds; round++ {
		key := contentionKeys[round%len(contentionKeys)]
		errs := registerTogether(t, newRegistry(), n, func(int) string { return key }, deadline.C)

		won, duplicate := 0, 0
		var other []error
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, replay.ErrDuplicateHandle):
				duplicate++
			default:
				other = append(other, err)
			}
		}
		if won != 1 || duplicate != n-1 || len(other) != 0 {
			t.Fatalf("round %d: %d goroutines registering one key got %d nil, %d duplicates and %d other errors %v; want 1 nil, %d duplicates, no other error",
				round, n, won, duplicate, len(other), other, n-1)
		}
	}
}
