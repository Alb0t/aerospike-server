# Defrag Autotune — Design Spec

**Date:** 2026-04-20
**Author:** Albert Autin (ala)
**Status:** Design approved; ready for implementation planning
**Base:** This work is planned against the latest `aerospike/aerospike-server` upstream master. The existing fork state at `Alb0t/aerospike-server` (including PR #1) is superseded and will be discarded; no code from PR #1 is carried forward.

## Motivation

TTD currently runs an out-of-process Ruby script (`auto_adjust_lwm.rb`, scheduled via a 60 s systemd timer) that shells out to `asinfo` to read storage stats and issue `set-config` commands that adjust each disk-backed namespace's `defrag-lwm-pct` and `defrag-sleep`. The goal is to keep each namespace inside a target `avail_pct` window without manual tuning, while respecting an IO-pressure guardrail.

The external-script approach has known problems:

- `asinfo` round-trip per stat read is expensive relative to the underlying numbers, which live in-process.
- A Chef cookbook must deploy and manage the script and its systemd timer on every host.
- Heterogeneous clusters (e.g., 800 GB SLC drives mixed with 15 TB QLC drives in the same deployment) need the logic to react faster and more uniformly than a minute-cadence cron can provide.

Moving the logic into `asd` as a per-namespace background thread eliminates the external dependency, lets the control loop observe and react at whatever cadence the operator configures, and is the right home for the behavior long-term.

This work is intended to be **upstreamed** to `aerospike/aerospike-server`. It must therefore be:

- **Off by default.** Zero behavior change for existing deployments.
- **Self-contained.** New code lives in its own module; existing files see only minimal, surgical edits.
- **Observable.** Actions produce stats that operators and dashboards can consume.
- **Documented.** Config keys, semantics, and observable stats are described.

## Scope

**In scope:**

- A per-namespace `defrag-autotune { ... }` sub-stanza inside the `namespace` block of `aerospike.conf`.
- A per-namespace background thread that, when enabled, periodically reads `avail_pct` and `defrag_q` depth, then adjusts `defrag-lwm-pct` and `defrag-sleep` within operator-configured bounds.
- A shared setter helper so the tuner and the existing `set-config` info command share one place that validates, clamps, and assigns these two fields.
- Six new per-namespace info stats exposing tuner activity.
- Runtime enable/disable via `set-config:context=namespace;id=X;defrag-autotune.enabled=<bool>`.

**Out of scope for this work:**

- Automated integration tests (upstream does not currently maintain such a suite for similar features; manual reproduction steps are included below).
- A `write-q` IO-pressure gate (present in an earlier prototype but dropped — not in the Ruby script that's been running in production).
- Any controller more sophisticated than the ±step algorithm below (PID / state machine / hysteresis cooldown). Explicitly deferred to a follow-up if real-world behavior warrants it.
- Any changes to `drv_ssd.c` defrag-sweep logic, `namespace.c` defaults, or any other unrelated area.

## Design

### Module layout

New files:

- `as/include/base/defrag_autotune.h` — public API (`as_defrag_autotune_start`, runtime toggle helpers).
- `as/src/base/defrag_autotune.c` — per-namespace thread, control loop, logging.

Touched existing files (minimal):

- `as/src/base/as.c` — `as_run()` calls `as_defrag_autotune_start()` after `as_nsup_start()`.
- `as/src/base/cfg.c` / `as/src/base/cfg.h` — parse the new sub-stanza; register set-config field handlers; new `defrag_autotune_cfg` struct embedded in `as_namespace`.
- `as/include/base/datamodel.h` — declares the embedded cfg struct on `as_namespace`.
- `as/src/base/cfg_info.c` (or a new thin `cfg_setters.c`) — shared setter helpers `as_ns_set_defrag_lwm_pct` / `as_ns_set_defrag_sleep_us` with a caller-supplied `(min, max)` clamp pair. Called from both the existing operator set-config path and the tuner.
- `as/src/base/thr_info.c` — adds six new fields to the `namespace/X` info dump.

### Per-namespace config struct

```c
typedef struct defrag_autotune_cfg_s {
    // user-configurable (via aerospike.conf + runtime set-config)
    bool     enabled;                 // default: false
    uint32_t tick_interval_sec;       // default: 60, must be >= 5 (rejected at parse otherwise)
    uint32_t target_avail_pct_min;    // default: 28
    uint32_t target_avail_pct_max;    // default: 31
    uint32_t defrag_lwm_pct_min;      // default: 2
    uint32_t defrag_lwm_pct_max;      // default: 55
    uint32_t defrag_lwm_step;         // default: 1
    uint32_t target_defrag_q;         // default: 1000
    uint32_t defrag_q_io_threshold;   // default: 1300 (>= 1.2 * target)
    uint32_t defrag_sleep_min_us;     // default: 2000
    uint32_t defrag_sleep_max_us;     // default: 30000

    // runtime state (not user-configurable; written by tuner)
    uint32_t exit_flag;               // set to 1 to make thread exit
    uint64_t n_lwm_up;
    uint64_t n_lwm_down;
    uint64_t n_sleep_up;
    uint64_t n_sleep_down;
    uint64_t last_action_ms;          // monotonic ms timestamp of last applied change
    uint8_t  last_action_kind;        // enum: none / lwm_up / lwm_down / sleep_up / sleep_down / noop
} defrag_autotune_cfg;
```

### Config file syntax

```
namespace ttd-ip {
    storage-engine device { ... }

    defrag-autotune {
        enabled true
        tick-interval 60
        target-avail-pct-min 28
        target-avail-pct-max 31
        defrag-lwm-pct-min 2
        defrag-lwm-pct-max 55
        defrag-lwm-step 1
        target-defrag-q 1000
        defrag-q-io-threshold 1300
        defrag-sleep-min 2000
        defrag-sleep-max 30000
    }
}
```

Omitting the stanza entirely leaves `enabled=false` and no thread is ever spawned — zero behavior change vs upstream.

### Parse-time validation

Reject config and abort startup with a clear error if any of:

- `target-avail-pct-min >= target-avail-pct-max`
- `defrag-lwm-pct-min >= defrag-lwm-pct-max`
- `defrag-sleep-min >= defrag-sleep-max`
- `defrag-q-io-threshold < target-defrag-q * 1.2` (mirrors Ruby's check)
- `tick-interval < 5`

### Runtime set-config

All fields are mutable via `set-config:context=namespace;id=X;defrag-autotune.<field>=<val>`. Each setter re-runs the same validation. The `enabled` setter additionally handles thread spawn/exit — see Lifecycle below.

Runtime edits to non-`enabled` fields take effect on the running thread's next tick (values are re-read from the cfg struct on every iteration).

### Control loop

Each per-namespace thread runs:

```c
static void *
run_autotuner(void *udata)
{
    as_namespace *ns = (as_namespace *)udata;
    defrag_autotune_cfg *c = &ns->autotune;

    while (as_load_uint32(&c->exit_flag) == 0) {
        sleep(c->tick_interval_sec);
        if (as_load_uint32(&c->exit_flag) != 0) break;
        if (!c->enabled) continue;

        adjust_defrag_lwm(ns);
        adjust_defrag_sleep(ns);
    }
    return NULL;
}
```

**`adjust_defrag_lwm`** — faithful port of the Ruby script's `adjust_defrag_lwm`:

```
avail         = as_storage_stats(ns).avail_pct
defrag_q_max  = max over devices of as_storage_device_stats(ns, i).defrag_q_sz
current_lwm   = ns->storage_defrag_lwm_pct

lwm_can_be_reduced = (current_lwm > c->defrag_lwm_pct_min)
                  && (avail > c->target_avail_pct_max)
lwm_should_increase = (current_lwm < c->defrag_lwm_pct_max)
                   && (avail < c->target_avail_pct_min)
                   && (defrag_q_max < c->defrag_q_io_threshold)

if lwm_can_be_reduced:
    set_lwm_clamped(ns, current_lwm - c->defrag_lwm_step); n_lwm_down++
elif lwm_should_increase:
    set_lwm_clamped(ns, current_lwm + c->defrag_lwm_step); n_lwm_up++
else:
    (no-op; debug log)
```

**`adjust_defrag_sleep`** — faithful port of the Ruby script's `adjust_defrag_sleep`:

```
defrag_q_max  = same as above
current_sleep = ns->storage_defrag_sleep

too_low  = defrag_q_max < target_defrag_q * 0.8
too_high = defrag_q_max > target_defrag_q * 1.2

if too_high:
    set_sleep_clamped(ns, current_sleep * 7 / 10); n_sleep_down++
elif too_low:
    set_sleep_clamped(ns, current_sleep * 11 / 10); n_sleep_up++
else:
    (no-op; debug log)
```

### Shared setter helpers

```c
bool as_ns_set_defrag_lwm_pct(as_namespace *ns, uint32_t val,
                              uint32_t min, uint32_t max);
bool as_ns_set_defrag_sleep_us(as_namespace *ns, uint32_t val,
                               uint32_t min, uint32_t max);
```

Validate `val` against `[min, max]`. On reject, log WARNING and return `false`; do not assign. On accept, assign to the namespace field and return `true`.

**Callers supply their own `(min, max)`:**

- Tuner passes the autotune-configured bounds (so it cannot exceed the operator's declared autotune limits).
- Existing operator `set-config` path passes aerospike's built-in legal range (so operator edits are not constrained by autotune bounds; the operator remains authoritative).

### Lifecycle

**Startup.** `as_defrag_autotune_start()` runs in `as_run()` after `as_nsup_start()`. For each ns with `enabled == true && storage_type == AS_STORAGE_ENGINE_SSD`, it spawns one detached thread via `cf_thread_create_detached(run_autotuner, ns)`. Non-device namespaces and disabled namespaces get no thread.

**Runtime toggle on `enabled`:**

- `false → true` on a device-backed ns, no live thread: reset `exit_flag = 0`, set `enabled = true`, spawn thread.
- `false → true` on a device-backed ns with a thread already live (race-guard): no-op.
- `true → false`: set `enabled = false`, set `exit_flag = 1`. Thread exits on its next wake.
- On a non-device ns: setter returns an error (same convention as other context-inappropriate set-config attempts).

A per-ns `cf_mutex` on the autotune cfg struct serializes spawn/exit decisions.

**Shutdown.** Aerospike's shutdown path is abrupt; detached threads simply die with the process. No join, no cleanup — same pattern as `run_nsup_histograms` and the ticker.

### Error handling

- Storage-stats API misuse is a programming error, not a runtime condition; no handling.
- Setter helper rejects → log WARNING, continue the loop. Tuner does not disable itself on a rejected value.
- `storage_type` re-checked each tick (defensive, though it cannot change today).

### Thread safety

Tuner reads `avail_pct` and `defrag_q_sz` through existing live-counter APIs (`as_storage_stats`, `as_storage_device_stats`) which do not take locks today — they read atomic counters. Tuner writes to `ns->storage_defrag_lwm_pct` and `ns->storage_defrag_sleep` are plain `uint32_t` assignments, identical to what the existing operator `set-config` path does. Readers of these fields in hot paths already tolerate the racy read. No new locks introduced.

### Observability

Six new stats per namespace, surfaced via `asinfo -v 'namespace/X'`:

- `defrag_autotune_n_lwm_up`
- `defrag_autotune_n_lwm_down`
- `defrag_autotune_n_sleep_up`
- `defrag_autotune_n_sleep_down`
- `defrag_autotune_last_action_ms`
- `defrag_autotune_last_action` (string: `none` / `lwm_up` / `lwm_down` / `sleep_up` / `sleep_down` / `noop`)

Logging:

- INFO — emitted once per applied change, including namespace, field, old value, new value, and the signal values (`avail_pct`, `defrag_q_max`) that drove the decision.
- DEBUG — emitted on no-op evaluations so steady-state is quiet by default.

## Testing

**Build environment note.** This design session was conducted on macOS. `aerospike-server` builds only on Linux, so all compile and runtime verification must be performed in a Linux environment (CI or a dev VM). The implementation plan will produce a self-contained branch that a Linux environment can build and exercise; none of the verification below is expected to run on the Mac host.

### Static / build checks

- Clean build on Linux with default config (autotune absent/disabled everywhere): zero diff in behavior vs upstream master. Smoke-test that `asd` starts, serves traffic, shuts down cleanly.
- Build and startup with `defrag-autotune { enabled true }` on a test namespace.

### Manual integration checklist (PR body)

1. **Config parse rejects** — each invalid-config case (each `min >= max` pair, `tick-interval < 5`, `io-threshold < 1.2× target`) produces a clear parse error and prevents startup.
2. **Off-by-default** — existing config file with no `defrag-autotune` stanza: ns starts normally, no tuner thread, no log spam.
3. **Steady-state no-op** — `enabled=true` with `avail_pct` inside the target window and `defrag_q` near target: no changes applied over several ticks; DEBUG log only.
4. **LWM raise path** — drive `avail_pct` below `target-avail-pct-min`: `storage_defrag_lwm_pct` climbs by `step` per tick up to `defrag-lwm-pct-max`; `n_lwm_up` stat increments.
5. **LWM lower path** — stop load, wait for avail to climb above max: LWM drops back toward min; `n_lwm_down` increments.
6. **Defrag-sleep adjust** — force `defrag_q` above 1.2× target: `storage_defrag_sleep` drops ~30% per tick down to min; `n_sleep_down` increments. Reverse: low `defrag_q`, sleep climbs ~10% per tick up to max; `n_sleep_up` increments.
7. **IO gate** — raise `defrag_q` above `defrag-q-io-threshold` while `avail_pct` is below min: LWM is *not* raised.
8. **Runtime toggle** — `asinfo set-config:context=namespace;id=X;defrag-autotune.enabled=false`: thread exits within one tick, no further changes. Flip back on: thread spawns, resumes.
9. **Runtime field edits** — change `tick-interval` and `target-avail-pct-max` via set-config: next tick honors new values (no thread restart).
10. **Stats surface** — `asinfo -v 'namespace/X'` shows the six new tuner stats with expected values.

## Migration

When this ships to a TTD host:

- Delete the Chef-managed systemd timer and `/usr/local/ttd/bin/auto_adjust_lwm.rb` artifact from `ttd-aerospike` cookbook (`recipes/tuning.rb` block under `if node['ttd-aerospike']['auto_adjust_lwm']`).
- Set `defrag-autotune { enabled true ... }` on the same per-ns set that was previously in `enabled_and_lwm_allowlisted_namespaces` (disk-backed minus disallowlist).
- The `vaf` datacenter's Ruby overrides (`--max-defrag-sleep 100_000`, `--target-defrag-queue 5_000`, `--defrag-lwm-pct-max 80`) map directly onto `defrag-sleep-max 100000`, `target-defrag-q 5000`, `defrag-lwm-pct-max 80` in the per-ns stanza for hosts in that datacenter.

The migration is out of scope for this PR but is called out here so the upstream maintainers see that the feature has a concrete consumer.
