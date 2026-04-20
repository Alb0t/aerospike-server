# Defrag Autotune Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move TTD's out-of-process Ruby defrag-lwm autotuner into aerospike-server as an opt-in per-namespace background thread, suitable for upstream contribution.

**Architecture:** One new self-contained module (`base/defrag_autotune.{c,h}`) providing a per-namespace thread that reads live storage stats and writes `defrag-lwm-pct` / `defrag-sleep` via a shared setter helper used by both the tuner and the existing `set-config` info command. Configuration lives under a new per-namespace `defrag-autotune { ... }` sub-stanza, off by default. No changes to existing defrag / storage code. See companion spec at `docs/superpowers/specs/2026-04-20-defrag-autotune-design.md`.

**Tech Stack:** C, aerospike-server codebase, standard aerospike build system (`make`), no new dependencies.

**Environment note:** This plan was written on macOS. `aerospike-server` does not build on macOS, so compile/run verification for every task must happen in a Linux environment (dev VM, CI, or remote host). Every task's "Verify" step assumes a Linux build environment. If working from the Mac host, commit + push, then verify on Linux.

**Coding conventions followed in this codebase (observed, not unit-tested):**

- No unit test framework for C in-tree. Verification is manual/integration.
- Tabs for indentation, K&R brace style, snake_case identifiers.
- Static helpers in `.c`; public functions in `.h` with `as_` prefix.
- Logging via `cf_info(AS_INFO, ...)`, `cf_warning(...)`, `cf_detail(...)`.
- Atomic reads/writes on `uint32_t` via `as_load_uint32`, `as_store_uint32`, etc. from `<citrusleaf/cf_atomic.h>` (check includes in `nsup.c` for pattern).
- Config parsing in `cfg.c` uses: `cfg_u32(&line, min, max)`, `cfg_u32_no_checks(&line)`, `cfg_bool(&line)`. Sub-stanzas use `cfg_begin_context(&state, CTX_NAME)`.
- Namespace info stats exposed in `info_get_namespace_info()` via `info_append_uint32(db, "name", value)` / `info_append_uint64(...)` / `info_append_string(...)`.

---

## File Structure

**New files:**
- `as/include/base/defrag_autotune.h` — public API: `as_defrag_autotune_start`, the per-ns cfg struct type, a couple of runtime-toggle helpers.
- `as/src/base/defrag_autotune.c` — implementation: per-ns thread, control loop, logging, stats bump helpers.

**Modified files:**
- `as/include/base/datamodel.h` — include new header, embed `defrag_autotune_cfg` on `as_namespace`.
- `as/src/base/namespace.c` — initialize the embedded cfg's defaults in `as_namespace_create`.
- `as/src/base/cfg.c` — new `defrag-autotune` sub-stanza parser + cross-field validation.
- `as/src/base/cfg_info.c` — new shared setter helpers `as_ns_set_defrag_lwm_pct_bounded` / `as_ns_set_defrag_sleep_us_bounded`; new set-config handlers for each autotune field.
- `as/src/base/as.c` — call `as_defrag_autotune_start()` from `as_run()` after `as_nsup_start()`.
- `as/src/base/thr_info.c` — add six new fields to `info_get_namespace_info()`.
- `as/src/Makefile` — add `defrag_autotune.h` to `BASE_HEADERS`; add `defrag_autotune.c` to `BASE_SOURCES`.

---

## Task 0: Rebase onto Upstream Master

The current fork (`Alb0t/aerospike-server` on local `master`) carries unrelated historical commits and the discarded PR #1 work. Start fresh from `aerospike/aerospike-server` master.

**Files:** Git configuration and branching only. No code changes.

- [ ] **Step 1: Add upstream remote if not already present**

```bash
git remote -v
# If no 'upstream' remote, add it:
git remote add upstream https://github.com/aerospike/aerospike-server.git
git fetch upstream --tags
```

Expected: `upstream/master` shows up in `git branch -r`.

- [ ] **Step 2: Create the feature branch off upstream master**

```bash
git checkout -b ala-defrag-autotune upstream/master
```

Expected: `git log --oneline -1` shows the latest upstream master commit, not `a960304a`.

- [ ] **Step 3: Cherry-pick the design spec + this plan onto the new branch**

The spec commit `a960304a` was made on the fork's master and needs to come along:

```bash
git cherry-pick a960304a
```

Expected: clean cherry-pick, `docs/superpowers/specs/2026-04-20-defrag-autotune-design.md` present.

Then add the plan doc to the branch:

```bash
git add docs/superpowers/plans/2026-04-20-defrag-autotune.md
git commit -m "Add defrag-autotune implementation plan

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Sanity build on Linux**

```bash
make
```

Expected: clean build on Linux (no changes from upstream yet, so this just proves the build environment works). Skip on Mac; run on Linux before continuing to Task 1.

---

## Task 1: Define the Config Struct and Embed on `as_namespace`

Get the type visible across the codebase with a single commit that adds the header and embeds the struct. No behavior change.

**Files:**
- Create: `as/include/base/defrag_autotune.h`
- Modify: `as/include/base/datamodel.h` (add `#include` and struct member)
- Modify: `as/src/Makefile` (add header to `BASE_HEADERS`)

- [ ] **Step 1: Create `as/include/base/defrag_autotune.h`**

```c
/*
 * defrag_autotune.h
 *
 * Copyright (C) 2026 Aerospike, Inc.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_mutex.h"

// Forward decl - avoid pulling datamodel.h back into this header.
struct as_namespace_s;

//==========================================================
// Per-namespace autotune configuration + runtime state.
//
// Embedded on as_namespace. All user-configurable fields are
// also mutable at runtime via set-config.
//

typedef enum {
	AS_DEFRAG_AUTOTUNE_ACTION_NONE = 0,
	AS_DEFRAG_AUTOTUNE_ACTION_NOOP,
	AS_DEFRAG_AUTOTUNE_ACTION_LWM_UP,
	AS_DEFRAG_AUTOTUNE_ACTION_LWM_DOWN,
	AS_DEFRAG_AUTOTUNE_ACTION_SLEEP_UP,
	AS_DEFRAG_AUTOTUNE_ACTION_SLEEP_DOWN
} as_defrag_autotune_action;

typedef struct defrag_autotune_cfg_s {
	// User-configurable (cfg file + runtime set-config).
	bool     enabled;
	uint32_t tick_interval_sec;
	uint32_t target_avail_pct_min;
	uint32_t target_avail_pct_max;
	uint32_t defrag_lwm_pct_min;
	uint32_t defrag_lwm_pct_max;
	uint32_t defrag_lwm_step;
	uint32_t target_defrag_q;
	uint32_t defrag_q_io_threshold;
	uint32_t defrag_sleep_min_us;
	uint32_t defrag_sleep_max_us;

	// Runtime state - not configurable; written only by the tuner
	// thread or the lifecycle helpers below.
	cf_mutex lifecycle_lock;          // serializes spawn/exit transitions
	uint32_t thread_running;          // 0/1, set/cleared under lifecycle_lock
	uint32_t exit_flag;               // tuner thread observes under as_load_uint32

	uint64_t n_lwm_up;
	uint64_t n_lwm_down;
	uint64_t n_sleep_up;
	uint64_t n_sleep_down;
	uint64_t last_action_ms;
	uint32_t last_action;             // as_defrag_autotune_action enum value
} defrag_autotune_cfg;

//==========================================================
// Public API.
//

// Called once from as_run() after as_nsup_start(). Spawns a tuner
// thread for each device-backed namespace with enabled=true.
void as_defrag_autotune_start(void);

// Called from the set-config handler when defrag-autotune.enabled
// transitions. Handles thread spawn on false->true and exit on
// true->false. Rejects with a cf_warning and returns false if the
// namespace is not device-backed.
bool as_defrag_autotune_set_enabled(struct as_namespace_s* ns, bool enabled);

// Called from cfg.c in as_namespace_create() to populate defaults.
void as_defrag_autotune_cfg_init_defaults(defrag_autotune_cfg* cfg);

// Returns a stable string for the action enum (used by info stats).
const char* as_defrag_autotune_action_str(uint32_t action);
```

- [ ] **Step 2: Embed the cfg on `as_namespace` in `datamodel.h`**

Add the include near the other `base/*.h` includes at the top of `as/include/base/datamodel.h` (search for `#include "base/cfg.h"` and place it nearby):

```c
#include "base/defrag_autotune.h"
```

Then in the `as_namespace` struct, add a new field in the storage-related field block (search for `uint32_t storage_defrag_lwm_pct;` around line 868 and add the new member immediately after the storage block — a clean place is after `storage_defrag_startup_minimum`):

```c
	// Defrag autotune (opt-in; off by default).
	defrag_autotune_cfg autotune;
```

- [ ] **Step 3: Add the new header to the Makefile**

In `as/src/Makefile`, after `BASE_HEADERS += datamodel.h`, add:

```makefile
BASE_HEADERS += defrag_autotune.h
```

- [ ] **Step 4: Build on Linux**

```bash
make
```

Expected: clean build. This commit embeds a new struct member but nothing writes to or reads from it yet, so no behavior change.

- [ ] **Step 5: Commit**

```bash
git add as/include/base/defrag_autotune.h as/include/base/datamodel.h as/src/Makefile
git commit -m "defrag-autotune: add config struct and header

Preparation commit. Defines the per-namespace autotune config +
runtime-state struct and embeds it on as_namespace. No behavior
change - nothing reads or writes the struct yet.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Create `defrag_autotune.c` Skeleton

Add the implementation file with stubs. Wire it into the Makefile and call the start function from `as_run`. Still a no-op at runtime because the loop does nothing.

**Files:**
- Create: `as/src/base/defrag_autotune.c`
- Modify: `as/src/Makefile` (add to `BASE_SOURCES`)
- Modify: `as/src/base/as.c` (call `as_defrag_autotune_start()`)
- Modify: `as/src/base/namespace.c` (init cfg defaults in `as_namespace_create`)

- [ ] **Step 1: Create `as/src/base/defrag_autotune.c` with stubs**

```c
/*
 * defrag_autotune.c
 *
 * Copyright (C) 2026 Aerospike, Inc.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "base/defrag_autotune.h"

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_mutex.h"

#include "cf_thread.h"
#include "log.h"

#include "base/cfg.h"
#include "base/datamodel.h"

//==========================================================
// Forward declarations.
//

static void* run_autotuner(void* udata);

//==========================================================
// Public API.
//

void
as_defrag_autotune_cfg_init_defaults(defrag_autotune_cfg* cfg)
{
	cfg->enabled = false;
	cfg->tick_interval_sec = 60;
	cfg->target_avail_pct_min = 28;
	cfg->target_avail_pct_max = 31;
	cfg->defrag_lwm_pct_min = 2;
	cfg->defrag_lwm_pct_max = 55;
	cfg->defrag_lwm_step = 1;
	cfg->target_defrag_q = 1000;
	cfg->defrag_q_io_threshold = 1300;
	cfg->defrag_sleep_min_us = 2000;
	cfg->defrag_sleep_max_us = 30000;

	cf_mutex_init(&cfg->lifecycle_lock);
	cfg->thread_running = 0;
	cfg->exit_flag = 0;

	cfg->n_lwm_up = 0;
	cfg->n_lwm_down = 0;
	cfg->n_sleep_up = 0;
	cfg->n_sleep_down = 0;
	cfg->last_action_ms = 0;
	cfg->last_action = AS_DEFRAG_AUTOTUNE_ACTION_NONE;
}

void
as_defrag_autotune_start(void)
{
	for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
		as_namespace* ns = g_config.namespaces[i];

		if (!ns->autotune.enabled) {
			continue;
		}

		if (ns->storage_type != AS_STORAGE_ENGINE_SSD) {
			cf_warning(AS_INFO,
					"{%s} defrag-autotune enabled but storage-engine is not device; ignoring",
					ns->name);
			ns->autotune.enabled = false;
			continue;
		}

		cf_mutex_lock(&ns->autotune.lifecycle_lock);
		ns->autotune.exit_flag = 0;
		ns->autotune.thread_running = 1;
		cf_mutex_unlock(&ns->autotune.lifecycle_lock);

		cf_thread_create_detached(run_autotuner, ns);
		cf_info(AS_INFO, "{%s} defrag-autotune thread started", ns->name);
	}
}

bool
as_defrag_autotune_set_enabled(as_namespace* ns, bool enabled)
{
	if (ns->storage_type != AS_STORAGE_ENGINE_SSD) {
		cf_warning(AS_INFO,
				"{%s} defrag-autotune.enabled rejected: storage-engine is not device",
				ns->name);
		return false;
	}

	cf_mutex_lock(&ns->autotune.lifecycle_lock);

	if (enabled && !ns->autotune.thread_running) {
		ns->autotune.enabled = true;
		ns->autotune.exit_flag = 0;
		ns->autotune.thread_running = 1;
		cf_mutex_unlock(&ns->autotune.lifecycle_lock);
		cf_thread_create_detached(run_autotuner, ns);
		cf_info(AS_INFO, "{%s} defrag-autotune thread started", ns->name);
		return true;
	}

	if (!enabled && ns->autotune.thread_running) {
		ns->autotune.enabled = false;
		as_store_uint32(&ns->autotune.exit_flag, 1);
		cf_mutex_unlock(&ns->autotune.lifecycle_lock);
		cf_info(AS_INFO, "{%s} defrag-autotune thread exit requested", ns->name);
		return true;
	}

	// No transition (already in the requested state).
	ns->autotune.enabled = enabled;
	cf_mutex_unlock(&ns->autotune.lifecycle_lock);
	return true;
}

const char*
as_defrag_autotune_action_str(uint32_t action)
{
	switch (action) {
	case AS_DEFRAG_AUTOTUNE_ACTION_NONE:       return "none";
	case AS_DEFRAG_AUTOTUNE_ACTION_NOOP:       return "noop";
	case AS_DEFRAG_AUTOTUNE_ACTION_LWM_UP:     return "lwm_up";
	case AS_DEFRAG_AUTOTUNE_ACTION_LWM_DOWN:   return "lwm_down";
	case AS_DEFRAG_AUTOTUNE_ACTION_SLEEP_UP:   return "sleep_up";
	case AS_DEFRAG_AUTOTUNE_ACTION_SLEEP_DOWN: return "sleep_down";
	default:                                   return "unknown";
	}
}

//==========================================================
// Local helpers.
//

static void*
run_autotuner(void* udata)
{
	as_namespace* ns = (as_namespace*)udata;
	defrag_autotune_cfg* c = &ns->autotune;

	while (as_load_uint32(&c->exit_flag) == 0) {
		uint32_t tick = c->tick_interval_sec;

		if (tick < 5) {
			tick = 5;  // defense-in-depth; cfg parser already rejects < 5.
		}

		sleep(tick);

		if (as_load_uint32(&c->exit_flag) != 0) {
			break;
		}
		if (!c->enabled) {
			continue;
		}

		// Algorithm fills in during Task 5.
	}

	cf_mutex_lock(&c->lifecycle_lock);
	c->thread_running = 0;
	cf_mutex_unlock(&c->lifecycle_lock);

	cf_info(AS_INFO, "{%s} defrag-autotune thread exited", ns->name);
	return NULL;
}
```

Note on headers: the exact include paths for `cf_thread.h`, `log.h`, `citrusleaf/cf_*.h` should match how `nsup.c` includes them — check that file if any of the above don't resolve.

- [ ] **Step 2: Add to `BASE_SOURCES` in `as/src/Makefile`**

After `BASE_SOURCES += cfg_info.c` (or any sensible alphabetical spot), add:

```makefile
BASE_SOURCES += defrag_autotune.c
```

- [ ] **Step 3: Call `as_defrag_autotune_start()` from `as_run` in `as/src/base/as.c`**

Find the line `as_nsup_start();` in `as_run()` (around line 416). Add, immediately before `as_service_start()`:

```c
	as_defrag_autotune_start();  // per-namespace opt-in defrag tuner
```

Add the include near the other `base/*.h` includes at the top:

```c
#include "base/defrag_autotune.h"
```

- [ ] **Step 4: Init defaults in `as_namespace_create` (`as/src/base/namespace.c`)**

Find `as_namespace_create()` near line 120. After existing `ns->storage_defrag_*` initializations, add:

```c
	as_defrag_autotune_cfg_init_defaults(&ns->autotune);
```

Add the include at the top if not already pulled transitively:

```c
#include "base/defrag_autotune.h"
```

- [ ] **Step 5: Build on Linux**

```bash
make
```

Expected: clean build.

- [ ] **Step 6: Smoke-test**

Start `asd` on a Linux host with an existing config file (no `defrag-autotune` stanza). Expected in logs:

- No `defrag-autotune thread started` lines (because `enabled=false` everywhere).
- Server starts and serves traffic normally.

Stop `asd` cleanly.

- [ ] **Step 7: Commit**

```bash
git add as/src/base/defrag_autotune.c as/src/Makefile as/src/base/as.c as/src/base/namespace.c
git commit -m "defrag-autotune: add skeleton module and wire into startup

Adds the implementation module with stubs for the tuner loop and
lifecycle helpers. Also initializes the per-namespace defaults and
calls as_defrag_autotune_start() from as_run(). Still a no-op
because the algorithm hasn't been implemented yet and no namespace
can have enabled=true (config parser is also not wired up yet).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Parse the `defrag-autotune` Sub-Stanza

Let operators put the stanza in `aerospike.conf` and have it actually set fields on `ns->autotune`. After this task, `enabled=true` via config will spawn the (still-stub) thread.

**Files:**
- Modify: `as/src/base/cfg.c` (tokens, context, case handlers, cross-field validation)

- [ ] **Step 1: Add case tokens in `cfg.c`**

Find the big `enum` around line 250-700 that lists `CASE_NAMESPACE_*` values. Add a new block for the autotune stanza. A safe location is right after `CASE_NAMESPACE_STORAGE_ENGINE_BEGIN` (line 507) — or wherever makes sense alphabetically in the namespace block. Example:

```c
	// defrag-autotune sub-stanza begin
	CASE_NAMESPACE_DEFRAG_AUTOTUNE_BEGIN,

	// defrag-autotune sub-stanza fields
	CASE_DEFRAG_AUTOTUNE_ENABLED,
	CASE_DEFRAG_AUTOTUNE_TICK_INTERVAL,
	CASE_DEFRAG_AUTOTUNE_TARGET_AVAIL_PCT_MIN,
	CASE_DEFRAG_AUTOTUNE_TARGET_AVAIL_PCT_MAX,
	CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_PCT_MIN,
	CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_PCT_MAX,
	CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_STEP,
	CASE_DEFRAG_AUTOTUNE_TARGET_DEFRAG_Q,
	CASE_DEFRAG_AUTOTUNE_DEFRAG_Q_IO_THRESHOLD,
	CASE_DEFRAG_AUTOTUNE_DEFRAG_SLEEP_MIN,
	CASE_DEFRAG_AUTOTUNE_DEFRAG_SLEEP_MAX,
```

- [ ] **Step 2: Register the sub-stanza opener in the namespace-level options table**

Find the `cfg_opt NAMESPACE_OPTS[]` array (search for `static const cfg_opt NAMESPACE_OPTS`). Add:

```c
		{ "defrag-autotune",		CASE_NAMESPACE_DEFRAG_AUTOTUNE_BEGIN },
```

- [ ] **Step 3: Define the new sub-stanza's options table**

At the same level where `NAMESPACE_STORAGE_DEVICE_OPTS` is defined, add a new one:

```c
static const cfg_opt NAMESPACE_DEFRAG_AUTOTUNE_OPTS[] = {
		{ "enabled",					CASE_DEFRAG_AUTOTUNE_ENABLED },
		{ "tick-interval",				CASE_DEFRAG_AUTOTUNE_TICK_INTERVAL },
		{ "target-avail-pct-min",		CASE_DEFRAG_AUTOTUNE_TARGET_AVAIL_PCT_MIN },
		{ "target-avail-pct-max",		CASE_DEFRAG_AUTOTUNE_TARGET_AVAIL_PCT_MAX },
		{ "defrag-lwm-pct-min",			CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_PCT_MIN },
		{ "defrag-lwm-pct-max",			CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_PCT_MAX },
		{ "defrag-lwm-step",			CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_STEP },
		{ "target-defrag-q",			CASE_DEFRAG_AUTOTUNE_TARGET_DEFRAG_Q },
		{ "defrag-q-io-threshold",		CASE_DEFRAG_AUTOTUNE_DEFRAG_Q_IO_THRESHOLD },
		{ "defrag-sleep-min",			CASE_DEFRAG_AUTOTUNE_DEFRAG_SLEEP_MIN },
		{ "defrag-sleep-max",			CASE_DEFRAG_AUTOTUNE_DEFRAG_SLEEP_MAX }
};

static const int NUM_NAMESPACE_DEFRAG_AUTOTUNE_OPTS =
		sizeof(NAMESPACE_DEFRAG_AUTOTUNE_OPTS) / sizeof(cfg_opt);
```

- [ ] **Step 4: Enter the sub-stanza context when the opener is parsed**

In the namespace-level case handler (around line 2183 for `CASE_NAMESPACE_BEGIN`, where `CASE_NAMESPACE_STORAGE_ENGINE_BEGIN` is also handled), add:

```c
			case CASE_NAMESPACE_DEFRAG_AUTOTUNE_BEGIN:
				cfg_begin_context(&state, NAMESPACE_DEFRAG_AUTOTUNE);
				break;
```

Also add a corresponding context enum value — search for `NAMESPACE_STORAGE_DEVICE` in the `cfg_context` enum and add `NAMESPACE_DEFRAG_AUTOTUNE` nearby. Then wire the new context into the context-dispatch table (search how `NAMESPACE_STORAGE_DEVICE` is wired; copy the pattern).

- [ ] **Step 5: Add the case handlers for the per-field tokens**

In the big switch inside the context-dispatch for `NAMESPACE_DEFRAG_AUTOTUNE`, add handlers for each token. Use `cfg_u32(&line, min, max)` for bounded integer fields:

```c
			case CASE_DEFRAG_AUTOTUNE_ENABLED:
				ns->autotune.enabled = cfg_bool(&line);
				break;
			case CASE_DEFRAG_AUTOTUNE_TICK_INTERVAL:
				ns->autotune.tick_interval_sec = cfg_u32(&line, 5, 3600);
				break;
			case CASE_DEFRAG_AUTOTUNE_TARGET_AVAIL_PCT_MIN:
				ns->autotune.target_avail_pct_min = cfg_u32(&line, 0, 100);
				break;
			case CASE_DEFRAG_AUTOTUNE_TARGET_AVAIL_PCT_MAX:
				ns->autotune.target_avail_pct_max = cfg_u32(&line, 0, 100);
				break;
			case CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_PCT_MIN:
				ns->autotune.defrag_lwm_pct_min = cfg_u32(&line, 1, 99);
				break;
			case CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_PCT_MAX:
				ns->autotune.defrag_lwm_pct_max = cfg_u32(&line, 1, 99);
				break;
			case CASE_DEFRAG_AUTOTUNE_DEFRAG_LWM_STEP:
				ns->autotune.defrag_lwm_step = cfg_u32(&line, 1, 50);
				break;
			case CASE_DEFRAG_AUTOTUNE_TARGET_DEFRAG_Q:
				ns->autotune.target_defrag_q = cfg_u32_no_checks(&line);
				break;
			case CASE_DEFRAG_AUTOTUNE_DEFRAG_Q_IO_THRESHOLD:
				ns->autotune.defrag_q_io_threshold = cfg_u32_no_checks(&line);
				break;
			case CASE_DEFRAG_AUTOTUNE_DEFRAG_SLEEP_MIN:
				ns->autotune.defrag_sleep_min_us = cfg_u32_no_checks(&line);
				break;
			case CASE_DEFRAG_AUTOTUNE_DEFRAG_SLEEP_MAX:
				ns->autotune.defrag_sleep_max_us = cfg_u32_no_checks(&line);
				break;
```

- [ ] **Step 6: Add cross-field validation at end-of-stanza**

Post-parse namespace-level validation already exists in cfg.c (search for `cf_crash_nostack` within a per-namespace post-parse validator). Add a block there:

```c
	// defrag-autotune cross-field validation.
	{
		defrag_autotune_cfg* a = &ns->autotune;

		if (a->target_avail_pct_min >= a->target_avail_pct_max) {
			cf_crash_nostack(AS_CFG,
					"{%s} defrag-autotune: target-avail-pct-min (%u) must be < target-avail-pct-max (%u)",
					ns->name, a->target_avail_pct_min, a->target_avail_pct_max);
		}
		if (a->defrag_lwm_pct_min >= a->defrag_lwm_pct_max) {
			cf_crash_nostack(AS_CFG,
					"{%s} defrag-autotune: defrag-lwm-pct-min (%u) must be < defrag-lwm-pct-max (%u)",
					ns->name, a->defrag_lwm_pct_min, a->defrag_lwm_pct_max);
		}
		if (a->defrag_sleep_min_us >= a->defrag_sleep_max_us) {
			cf_crash_nostack(AS_CFG,
					"{%s} defrag-autotune: defrag-sleep-min (%u) must be < defrag-sleep-max (%u)",
					ns->name, a->defrag_sleep_min_us, a->defrag_sleep_max_us);
		}
		if (a->defrag_q_io_threshold < (uint32_t)(a->target_defrag_q * 12 / 10)) {
			cf_crash_nostack(AS_CFG,
					"{%s} defrag-autotune: defrag-q-io-threshold (%u) must be >= 1.2 * target-defrag-q (%u)",
					ns->name, a->defrag_q_io_threshold, a->target_defrag_q);
		}
	}
```

- [ ] **Step 7: Build on Linux**

```bash
make
```

Expected: clean build.

- [ ] **Step 8: Verify config parsing manually**

On Linux, add to a test namespace block in `aerospike.conf`:

```
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
```

Start `asd`. Expected: startup succeeds, log shows `{<ns>} defrag-autotune thread started`.

Verify each validation error by triggering it once (e.g., set `target-avail-pct-min 40` with `max 30` → expect `cf_crash_nostack` on startup with a clear message). Revert the invalid config before committing.

- [ ] **Step 9: Commit**

```bash
git add as/src/base/cfg.c
git commit -m "defrag-autotune: parse per-namespace config sub-stanza

Adds the 'defrag-autotune { ... }' sub-stanza under the namespace
block, with per-field tokens and cross-field validation. Still no
effect at runtime because the tuner loop body is empty.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Shared Setter Helpers

Introduce the two helpers that clamp-and-assign `defrag-lwm-pct` / `defrag-sleep`. These are called from the tuner in Task 5, and later from the runtime set-config handler in Task 6.

**Files:**
- Modify: `as/src/base/cfg_info.c` (add helpers)
- Modify: `as/include/base/cfg_info.h` (declare helpers)

- [ ] **Step 1: Add helper declarations to `as/include/base/cfg_info.h`**

Near the other public declarations in this header, add:

```c
struct as_namespace_s;

// Validates that val is in [min, max] then assigns to ns->storage_defrag_lwm_pct.
// On reject, logs cf_warning and returns false. On accept, returns true.
bool as_ns_set_defrag_lwm_pct_bounded(struct as_namespace_s* ns, uint32_t val,
		uint32_t min, uint32_t max);

// Same for ns->storage_defrag_sleep (microseconds).
bool as_ns_set_defrag_sleep_us_bounded(struct as_namespace_s* ns, uint32_t val,
		uint32_t min, uint32_t max);
```

- [ ] **Step 2: Implement helpers in `as/src/base/cfg_info.c`**

Add at an appropriate spot (near other helpers; end of file if unsure):

```c
bool
as_ns_set_defrag_lwm_pct_bounded(as_namespace* ns, uint32_t val,
		uint32_t min, uint32_t max)
{
	if (val < min || val > max) {
		cf_warning(AS_INFO,
				"{%s} defrag-lwm-pct=%u rejected; must be in [%u, %u]",
				ns->name, val, min, max);
		return false;
	}

	ns->storage_defrag_lwm_pct = val;
	return true;
}

bool
as_ns_set_defrag_sleep_us_bounded(as_namespace* ns, uint32_t val,
		uint32_t min, uint32_t max)
{
	if (val < min || val > max) {
		cf_warning(AS_INFO,
				"{%s} defrag-sleep=%u rejected; must be in [%u, %u]",
				ns->name, val, min, max);
		return false;
	}

	ns->storage_defrag_sleep = val;
	return true;
}
```

Verify the necessary includes are already present (`base/datamodel.h`, `log.h`).

- [ ] **Step 3: Build on Linux**

```bash
make
```

Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add as/include/base/cfg_info.h as/src/base/cfg_info.c
git commit -m "defrag-autotune: add shared defrag-lwm-pct/defrag-sleep setters

Single place that validates-and-assigns these fields. Called in a
follow-up commit from both the new defrag-autotune thread and the
existing set-config info path, so the clamp logic has exactly one
home.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Implement the Control Loop

Fill in the algorithm from the spec. After this, a running tuner actually changes `defrag-lwm-pct` and `defrag-sleep` each tick.

**Files:**
- Modify: `as/src/base/defrag_autotune.c`

- [ ] **Step 1: Replace the empty `// Algorithm fills in during Task 5.` block in `run_autotuner` with the full algorithm**

Add these local helpers above `run_autotuner`:

```c
static uint64_t
now_monotonic_ms(void)
{
	return cf_getms();  // monotonic ms - same as other periodic subsystems use
}

static uint32_t
max_defrag_q_over_devices(as_namespace* ns)
{
	uint32_t max_q = 0;
	uint32_t n_devs = ns->n_storage_files != 0 ? ns->n_storage_files : ns->n_storage_devices;

	for (uint32_t i = 0; i < n_devs; i++) {
		storage_device_stats s;
		as_storage_device_stats(ns, i, &s);
		if (s.defrag_q_sz > max_q) {
			max_q = s.defrag_q_sz;
		}
	}
	return max_q;
}

static void
adjust_defrag_lwm(as_namespace* ns, uint32_t avail, uint32_t defrag_q_max)
{
	defrag_autotune_cfg* c = &ns->autotune;
	uint32_t current_lwm = ns->storage_defrag_lwm_pct;

	bool can_reduce = current_lwm > c->defrag_lwm_pct_min
			&& avail > c->target_avail_pct_max;
	bool should_increase = current_lwm < c->defrag_lwm_pct_max
			&& avail < c->target_avail_pct_min
			&& defrag_q_max < c->defrag_q_io_threshold;

	if (can_reduce) {
		uint32_t new_val = current_lwm - c->defrag_lwm_step;
		if (as_ns_set_defrag_lwm_pct_bounded(ns, new_val,
				c->defrag_lwm_pct_min, c->defrag_lwm_pct_max)) {
			c->n_lwm_down++;
			c->last_action = AS_DEFRAG_AUTOTUNE_ACTION_LWM_DOWN;
			c->last_action_ms = now_monotonic_ms();
			cf_info(AS_INFO,
					"{%s} defrag-autotune: lwm %u -> %u (avail=%u > max=%u)",
					ns->name, current_lwm, new_val, avail, c->target_avail_pct_max);
		}
	}
	else if (should_increase) {
		uint32_t new_val = current_lwm + c->defrag_lwm_step;
		if (as_ns_set_defrag_lwm_pct_bounded(ns, new_val,
				c->defrag_lwm_pct_min, c->defrag_lwm_pct_max)) {
			c->n_lwm_up++;
			c->last_action = AS_DEFRAG_AUTOTUNE_ACTION_LWM_UP;
			c->last_action_ms = now_monotonic_ms();
			cf_info(AS_INFO,
					"{%s} defrag-autotune: lwm %u -> %u (avail=%u < min=%u, defrag_q=%u)",
					ns->name, current_lwm, new_val, avail, c->target_avail_pct_min, defrag_q_max);
		}
	}
	else {
		cf_detail(AS_INFO,
				"{%s} defrag-autotune: lwm unchanged (avail=%u, defrag_q=%u, lwm=%u)",
				ns->name, avail, defrag_q_max, current_lwm);
	}
}

static void
adjust_defrag_sleep(as_namespace* ns, uint32_t defrag_q_max)
{
	defrag_autotune_cfg* c = &ns->autotune;
	uint32_t current_sleep = ns->storage_defrag_sleep;

	uint32_t q_too_low_thresh  = (uint32_t)(c->target_defrag_q * 8 / 10);
	uint32_t q_too_high_thresh = (uint32_t)(c->target_defrag_q * 12 / 10);

	if (defrag_q_max > q_too_high_thresh) {
		uint32_t new_val = current_sleep * 7 / 10;
		if (new_val < c->defrag_sleep_min_us) {
			new_val = c->defrag_sleep_min_us;
		}
		if (new_val != current_sleep
				&& as_ns_set_defrag_sleep_us_bounded(ns, new_val,
						c->defrag_sleep_min_us, c->defrag_sleep_max_us)) {
			c->n_sleep_down++;
			c->last_action = AS_DEFRAG_AUTOTUNE_ACTION_SLEEP_DOWN;
			c->last_action_ms = now_monotonic_ms();
			cf_info(AS_INFO,
					"{%s} defrag-autotune: defrag-sleep %u -> %u (defrag_q=%u > %u)",
					ns->name, current_sleep, new_val, defrag_q_max, q_too_high_thresh);
		}
	}
	else if (defrag_q_max < q_too_low_thresh) {
		uint32_t new_val = current_sleep * 11 / 10;
		if (new_val > c->defrag_sleep_max_us) {
			new_val = c->defrag_sleep_max_us;
		}
		if (new_val != current_sleep
				&& as_ns_set_defrag_sleep_us_bounded(ns, new_val,
						c->defrag_sleep_min_us, c->defrag_sleep_max_us)) {
			c->n_sleep_up++;
			c->last_action = AS_DEFRAG_AUTOTUNE_ACTION_SLEEP_UP;
			c->last_action_ms = now_monotonic_ms();
			cf_info(AS_INFO,
					"{%s} defrag-autotune: defrag-sleep %u -> %u (defrag_q=%u < %u)",
					ns->name, current_sleep, new_val, defrag_q_max, q_too_low_thresh);
		}
	}
	else {
		cf_detail(AS_INFO,
				"{%s} defrag-autotune: sleep unchanged (defrag_q=%u, sleep=%u)",
				ns->name, defrag_q_max, current_sleep);
	}
}
```

Then in `run_autotuner`'s loop body (replacing the `// Algorithm fills in` comment):

```c
		uint32_t avail = 100;
		as_storage_stats(ns, &avail, NULL);
		uint32_t defrag_q_max = max_defrag_q_over_devices(ns);

		adjust_defrag_lwm(ns, avail, defrag_q_max);
		adjust_defrag_sleep(ns, defrag_q_max);
```

Verify includes — add at the top of `defrag_autotune.c`:

```c
#include "base/cfg_info.h"
#include "storage/storage.h"
```

Also add `#include "clock.h"` or whatever header exposes `cf_getms()` (check `ticker.c` for the right include path).

- [ ] **Step 2: Check `n_storage_files` vs `n_storage_devices`**

Search `datamodel.h` / `storage.c` for the exact field on `as_namespace` that counts devices. The helper above assumes one of `n_storage_files` or `n_storage_devices`; use whichever exists (typically `n_storage_files` for file-backed, `n_storage_devices` for raw devices — there's usually a single unified accessor or they're mutually exclusive). Replace the `n_devs` initializer appropriately.

- [ ] **Step 3: Build on Linux**

```bash
make
```

Expected: clean build.

- [ ] **Step 4: Verify — steady-state, LWM-up, LWM-down, sleep paths**

On Linux, run the spec's manual checklist items 3-7 (steady-state no-op, LWM raise path, LWM lower path, defrag-sleep adjust, IO gate). Document actual behavior in the PR body.

- [ ] **Step 5: Commit**

```bash
git add as/src/base/defrag_autotune.c
git commit -m "defrag-autotune: implement per-namespace control loop

Faithful C port of the Ruby script's adjust_defrag_lwm and
adjust_defrag_sleep, using the shared setter helpers. Reads
live storage stats each tick; on applied changes, logs INFO and
increments per-ns counters.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Runtime `set-config` for Autotune Fields

Let operators toggle `enabled` and edit autotune parameters at runtime via `asinfo set-config`.

**Files:**
- Modify: `as/src/base/cfg_info.c` (add namespace-context `defrag-autotune.<field>` handlers)

- [ ] **Step 1: Locate the namespace-context set-config handler**

Search `cfg_info.c` for where `defrag-lwm-pct` is handled for runtime set-config (grep `defrag-lwm-pct`). The existing pattern will be a cascade of `if (strcmp(name, "...") == 0)` or a tokenized switch. Match that pattern.

- [ ] **Step 2: Add handlers for each autotune field**

Within the namespace-context set-config handler, add:

```c
	if (strcmp(name, "defrag-autotune.enabled") == 0) {
		bool enabled;
		if (!cfg_str_to_bool(value, &enabled)) {
			cf_warning(AS_INFO, "invalid bool for defrag-autotune.enabled: %s", value);
			return false;
		}
		return as_defrag_autotune_set_enabled(ns, enabled);
	}
	if (strcmp(name, "defrag-autotune.tick-interval") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32_in_range(value, 5, 3600, &v)) {
			cf_warning(AS_INFO, "invalid tick-interval: %s (must be 5..3600)", value);
			return false;
		}
		ns->autotune.tick_interval_sec = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.target-avail-pct-min") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32_in_range(value, 0, 100, &v)) return false;
		if (v >= ns->autotune.target_avail_pct_max) {
			cf_warning(AS_INFO,
					"{%s} target-avail-pct-min (%u) must be < target-avail-pct-max (%u)",
					ns->name, v, ns->autotune.target_avail_pct_max);
			return false;
		}
		ns->autotune.target_avail_pct_min = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.target-avail-pct-max") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32_in_range(value, 0, 100, &v)) return false;
		if (v <= ns->autotune.target_avail_pct_min) {
			cf_warning(AS_INFO,
					"{%s} target-avail-pct-max (%u) must be > target-avail-pct-min (%u)",
					ns->name, v, ns->autotune.target_avail_pct_min);
			return false;
		}
		ns->autotune.target_avail_pct_max = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.defrag-lwm-pct-min") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32_in_range(value, 1, 99, &v)) return false;
		if (v >= ns->autotune.defrag_lwm_pct_max) return false;
		ns->autotune.defrag_lwm_pct_min = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.defrag-lwm-pct-max") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32_in_range(value, 1, 99, &v)) return false;
		if (v <= ns->autotune.defrag_lwm_pct_min) return false;
		ns->autotune.defrag_lwm_pct_max = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.defrag-lwm-step") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32_in_range(value, 1, 50, &v)) return false;
		ns->autotune.defrag_lwm_step = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.target-defrag-q") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32(value, &v)) return false;
		if (ns->autotune.defrag_q_io_threshold < (uint32_t)(v * 12 / 10)) {
			cf_warning(AS_INFO,
					"{%s} would make defrag-q-io-threshold (%u) < 1.2*target (%u); reject",
					ns->name, ns->autotune.defrag_q_io_threshold, v);
			return false;
		}
		ns->autotune.target_defrag_q = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.defrag-q-io-threshold") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32(value, &v)) return false;
		if (v < (uint32_t)(ns->autotune.target_defrag_q * 12 / 10)) return false;
		ns->autotune.defrag_q_io_threshold = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.defrag-sleep-min") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32(value, &v)) return false;
		if (v >= ns->autotune.defrag_sleep_max_us) return false;
		ns->autotune.defrag_sleep_min_us = v;
		return true;
	}
	if (strcmp(name, "defrag-autotune.defrag-sleep-max") == 0) {
		uint32_t v;
		if (!cfg_str_to_u32(value, &v)) return false;
		if (v <= ns->autotune.defrag_sleep_min_us) return false;
		ns->autotune.defrag_sleep_max_us = v;
		return true;
	}
```

If the helpers `cfg_str_to_bool` / `cfg_str_to_u32` / `cfg_str_to_u32_in_range` don't exist by those names, use the file's existing parse helpers (grep for `strtoul` in `cfg_info.c` to see what's available). The shape is the same; only the function names change.

Add include at top of `cfg_info.c`:

```c
#include "base/defrag_autotune.h"
```

- [ ] **Step 3: Build on Linux**

```bash
make
```

Expected: clean build.

- [ ] **Step 4: Verify runtime toggle (spec checklist item 8)**

On Linux, with a running `asd`:

```bash
asinfo -v 'set-config:context=namespace;id=<ns>;defrag-autotune.enabled=false'
asinfo -v 'set-config:context=namespace;id=<ns>;defrag-autotune.enabled=true'
asinfo -v 'set-config:context=namespace;id=<ns>;defrag-autotune.tick-interval=30'
asinfo -v 'set-config:context=namespace;id=<ns>;defrag-autotune.target-avail-pct-max=45'
```

Expected in logs: `thread exit requested` / `thread started` on the enabled toggles; new `tick-interval` observed on the next cycle.

- [ ] **Step 5: Commit**

```bash
git add as/src/base/cfg_info.c
git commit -m "defrag-autotune: add runtime set-config handlers

All defrag-autotune.<field> knobs are now editable at runtime via
asinfo set-config. The 'enabled' setter spawns/exits the per-ns
tuner thread. Cross-field constraints are re-checked on every edit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Info Stats on `namespace/<ns>`

Surface the six counters + last-action + last-action-ms in the `namespace/X` info dump so operators and dashboards can see tuner activity.

**Files:**
- Modify: `as/src/base/thr_info.c` (extend `info_get_namespace_info`)

- [ ] **Step 1: Add the stat appends**

Find `info_get_namespace_info(as_namespace* ns, cf_dyn_buf* db)` in `thr_info.c` (around line 275 declaration; the body is further down — search for `info_append_uint64(db, "objects"` to find the body). At an appropriate spot (e.g., after the `nsup_*` stats), add:

```c
	info_append_uint64(db, "defrag_autotune_n_lwm_up",     ns->autotune.n_lwm_up);
	info_append_uint64(db, "defrag_autotune_n_lwm_down",   ns->autotune.n_lwm_down);
	info_append_uint64(db, "defrag_autotune_n_sleep_up",   ns->autotune.n_sleep_up);
	info_append_uint64(db, "defrag_autotune_n_sleep_down", ns->autotune.n_sleep_down);
	info_append_uint64(db, "defrag_autotune_last_action_ms", ns->autotune.last_action_ms);
	info_append_string(db, "defrag_autotune_last_action",
			as_defrag_autotune_action_str(ns->autotune.last_action));
```

Add include at the top if not already present:

```c
#include "base/defrag_autotune.h"
```

- [ ] **Step 2: Build on Linux**

```bash
make
```

Expected: clean build.

- [ ] **Step 3: Verify (spec checklist item 10)**

On Linux with a running `asd`:

```bash
asinfo -v 'namespace/<ns>' | tr ';' '\n' | grep defrag_autotune
```

Expected: six lines, initially `defrag_autotune_last_action=none` and counters at 0. After forcing an LWM raise (checklist item 4), `defrag_autotune_n_lwm_up` > 0 and `defrag_autotune_last_action=lwm_up`.

- [ ] **Step 4: Commit**

```bash
git add as/src/base/thr_info.c
git commit -m "defrag-autotune: expose per-namespace tuner stats

Six new stats on namespace/<ns>: four counters (lwm up/down,
sleep up/down), last action timestamp, last action kind.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: PR Preparation

Assemble the PR against `aerospike/aerospike-server`.

- [ ] **Step 1: Rebase + squash if needed**

Review the history:

```bash
git log --oneline upstream/master..HEAD
```

Expected: a clean linear sequence of ~8 commits (spec, plan, Tasks 1-7). Squash or reword if any turned out noisy. Keep the spec + plan commits; upstream reviewers may want to see them (or, if upstream prefers code-only PRs, omit those docs from the PR branch but keep them in TTD's fork).

- [ ] **Step 2: Run the full manual checklist from the spec**

Walk through items 1-10 of the spec's "Manual integration checklist" on a Linux dev host. Capture command invocations + log output in a scratchpad.

- [ ] **Step 3: Push to the TTD fork and open a draft PR**

```bash
git push -u origin ala-defrag-autotune
# Then open a draft PR on GitHub against aerospike/aerospike-server:master.
```

The PR body should include:

- Motivation (summary of the spec's Motivation section).
- A link to / inlined copy of the manual checklist with actual observed outputs.
- A note that autotune is off by default and the patch is a no-op for existing deployments.

- [ ] **Step 4: Update TTD Chef cookbook (follow-up, not part of this PR)**

Out of scope for this PR but tracked for later:

- Remove `recipes/tuning.rb`'s `auto_adjust_lwm` block + systemd timer.
- Template the `defrag-autotune { ... }` stanza into the `aerospike.conf` for each enabled namespace.
- Port `vaf` DC overrides.

---

## Self-Review Notes

Run a final spec-coverage check before executing:

- **Off by default** → Task 1 defaults + Task 3 parser. ✓
- **New config stanza with all 11 fields** → Task 3. ✓
- **Parse-time validation** → Task 3 Step 6. ✓
- **Runtime set-config with re-validation** → Task 6. ✓
- **Per-ns thread, storage_type == SSD only** → Task 2 + Task 6. ✓
- **Faithful Ruby algorithm (LWM ±step, sleep ×0.7/×1.1)** → Task 5. ✓
- **IO gate (defrag-q-io-threshold)** → Task 5 (`should_increase`). ✓
- **Shared setter helpers** → Task 4, used in Task 5 and indirectly in Task 6. ✓
- **Six new info stats** → Task 7. ✓
- **INFO on apply, DEBUG on no-op** → Task 5. ✓
- **Thread lifecycle w/ runtime toggle** → Task 2 + Task 6. ✓
- **No touching of `drv_ssd.c` defrag sweep, `namespace.c` defaults, or other unrelated areas** → verified by the files-modified list. ✓

No placeholders remain. No missing spec requirements.
