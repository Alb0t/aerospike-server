/*
 * sindex.h
 *
 * Copyright (C) 2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

#pragma once

//==========================================================
// Includes.
//

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_hash_math.h"

#include "arenax.h"
#include "dynbuf.h"
#include "shash.h"

#include "base/datamodel.h"
#include "sindex/sindex_arena.h"


//==========================================================
// Forward declarations.
//

struct as_index_ref_s;
struct as_namespace_s;
struct as_storage_rd_s;
struct si_btree_s;


//==========================================================
// Typedefs & constants.
//

#define INAME_MAX_SZ 64

// Sanity check limits.
#define MAX_STRING_KSIZE 2048 // TODO - increase?
#define MAX_GEOJSON_KSIZE (1024 * 1024)

// Info command parsing buffer sizes.
#define INDEXTYPE_MAX_SZ 10 // (default/list/mapkeys/mapvalues)
#define INDEXDATA_MAX_SZ (AS_BIN_NAME_MAX_SZ + 11 + 1) // bin-name,key-type (string/numeric/geo2dsphere)
#define CTX_B64_MAX_SZ 2048
#define SINDEX_SMD_KEY_MAX_SZ (AS_ID_NAMESPACE_SZ + AS_SET_NAME_MAX_SIZE + AS_BIN_NAME_MAX_SZ + 2 + 2 + CTX_B64_MAX_SZ)

typedef enum {
	AS_SINDEX_OP_DELETE = 0,
	AS_SINDEX_OP_INSERT = 1
} as_sindex_op;

typedef enum {
	AS_SINDEX_ITYPE_DEFAULT   = 0,
	AS_SINDEX_ITYPE_LIST      = 1,
	AS_SINDEX_ITYPE_MAPKEYS   = 2,
	AS_SINDEX_ITYPE_MAPVALUES = 3,

	AS_SINDEX_N_ITYPES        = 4
} as_sindex_type;

typedef struct as_sindex_s {
	struct as_namespace_s* ns;
	char iname[INAME_MAX_SZ];

	char set_name[AS_SET_NAME_MAX_SIZE];
	uint16_t set_id;

	char bin_name[AS_BIN_NAME_MAX_SZ];
	uint16_t bin_id;

	as_particle_type ktype;
	as_sindex_type itype;

	char* ctx_b64;
	uint8_t* ctx_buf;
	uint32_t ctx_buf_sz;

	uint32_t id;

	bool readable; // false while building sindex
	bool dropped;

	uint64_t keys_per_bval;
	uint64_t keys_per_rec;
	uint64_t load_time;
	uint32_t populate_pct;
	uint64_t n_gc_cleaned;

	uint32_t n_btrees;
	struct si_btree_s** btrees;
} as_sindex;

typedef struct as_sindex_bin_s {
	as_sindex* si;
	as_sindex_op op;

	uint32_t n_values;
	int64_t val; // optimize for non-CDT use case which needs only one value
	int64_t* values;
	uint32_t capacity;
} as_sindex_bin;


//==========================================================
// Public API.
//

// Startup.
void as_sindex_init(void);
void as_sindex_resume(void);
void as_sindex_load(void);
void as_sindex_start(void);
void as_sindex_shutdown(struct as_namespace_s* ns);

// Populate sindexes.
void as_sindex_put_all_rd(struct as_namespace_s* ns, struct as_storage_rd_s* rd, struct as_index_ref_s* r_ref);
void as_sindex_put_rd(as_sindex* si, struct as_storage_rd_s* rd, struct as_index_ref_s* r_ref);

// Modify sindexes from writes/deletes.
uint32_t as_sindex_arr_lookup_by_set_and_bin_lockfree(const struct as_namespace_s* ns, uint16_t set_id, uint16_t bin_id, as_sindex** si_arr);
uint32_t as_sindex_sbins_from_bin(struct as_namespace_s* ns, uint16_t set_id, const as_bin* b, as_sindex_bin* start_sbin, as_sindex_op op);
void as_sindex_update_by_sbin(as_sindex_bin* start_sbin, uint32_t n_sbins, cf_arenax_handle r_h);
void as_sindex_sbin_free_all(as_sindex_bin* sbin, uint32_t n_sbins);

// Query.
as_sindex* as_sindex_lookup_by_defn(const struct as_namespace_s* ns, uint16_t set_id, uint16_t bin_id, as_particle_type ktype, as_sindex_type itype, const uint8_t* ctx_buf, uint32_t ctx_buf_sz);

// GC.
as_sindex* as_sindex_lookup_by_iname_lockfree(const struct as_namespace_s* ns, const char* iname);

// Info & stats.
as_particle_type as_sindex_ktype_from_string(const char* ktype_str);
as_sindex_type as_sindex_itype_from_string(const char* itype_str);
bool as_sindex_exists(const struct as_namespace_s* ns, const char* iname);
bool as_sindex_stats_str(struct as_namespace_s* ns, char* iname, cf_dyn_buf* db);
void as_sindex_list_str(const struct as_namespace_s* ns, bool b64, cf_dyn_buf* db);
void as_sindex_build_smd_key(const char* ns_name, const char* set_name, const char* bin_name, const char* cdt_ctx, as_sindex_type itype, as_particle_type ktype, char* smd_key);
int32_t as_sindex_cdt_ctx_b64_decode(const char* ctx_b64, uint32_t ctx_b64_len, uint8_t** buf_r);

static inline uint32_t
as_sindex_n_sindexes(const as_namespace* ns)
{
	return cf_shash_get_size(ns->sindex_iname_hash);
}

static inline int64_t
as_sindex_string_to_bval(const char* s, size_t len)
{
	return (int64_t)cf_wyhash64((const void*)s, len);
}

static inline uint64_t
as_sindex_used_bytes(const as_namespace* ns)
{
	return ns->si_arena->n_used_eles * ns->si_arena->ele_sz;
}

static inline void
as_sindex_reserve(as_sindex* si)
{
	cf_rc_reserve(si);
}

static inline void
as_sindex_release(as_sindex* si)
{
	cf_rc_release(si);
}

static inline void
as_sindex_release_arr(as_sindex* si_arr[], uint32_t si_arr_sz)
{
	for (uint32_t i = 0; i < si_arr_sz; i++) {
		as_sindex_release(si_arr[i]);
	}
}

// Lifecycle lock.
extern pthread_rwlock_t g_sindex_rwlock;

#define SINDEX_GRLOCK() pthread_rwlock_rdlock(&g_sindex_rwlock)
#define SINDEX_GWLOCK() pthread_rwlock_wrlock(&g_sindex_rwlock)
#define SINDEX_GRUNLOCK() pthread_rwlock_unlock(&g_sindex_rwlock)
#define SINDEX_GWUNLOCK() pthread_rwlock_unlock(&g_sindex_rwlock)


//==========================================================
// Private API - for enterprise separation only.
//

void add_to_sindexes(as_sindex* si);
void drop_from_sindexes(struct as_sindex_s* si);
void as_sindex_resume_check(void);
