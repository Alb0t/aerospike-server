/*
 * shash.c
 *
 * Copyright (C) 2017-2020 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include "shash.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_hash_math.h"

#include "cf_mutex.h"
#include "log.h"


//==========================================================
// Typedefs & constants.
//

// TODO - in_use is wasteful, especially when not first in bucket.
typedef struct cf_shash_ele_s {
	struct cf_shash_ele_s* next;
	bool in_use;
	uint8_t data[];
} cf_shash_ele;


//==========================================================
// Forward declarations.
//

static inline void cf_shash_clear_table(cf_shash* h);
static inline void cf_shash_destroy_elements(cf_shash* h);
static inline uint32_t cf_shash_calculate_hash(cf_shash* h, const void* key);
static inline cf_mutex* cf_shash_lock(cf_shash* h, uint32_t i);
static inline void cf_shash_unlock(cf_mutex* l);
static inline cf_shash_ele* cf_shash_get_bucket(cf_shash* h, uint32_t i);
static inline void cf_shash_fill_element(cf_shash_ele* e, cf_shash* h, const void* key, const void* value);
static inline void cf_shash_size_incr(cf_shash* h);
static inline void cf_shash_size_decr(cf_shash* h);
static int cf_shash_delete_or_pop(cf_shash* h, const void* key, void* value);


//==========================================================
// Inlines & macros.
//

#define ELE_KEY(_h, _e) ((void*)_e->data)
#define ELE_VALUE(_h, _e) ((void*)(_e->data + _h->key_size))


//==========================================================
// Public API - useful hash functions.
//

// Interpret first 4 bytes of key as (host-ordered) uint32_t. (Note - caller
// is responsible for ensuring key size is at least 4 bytes.)
uint32_t
cf_shash_fn_u32(const void* key)
{
	return *(const uint32_t*)key;
}

// Useful if key is a pointer.
uint32_t
cf_shash_fn_ptr(const void* key)
{
	return cf_hash_ptr32(key);
}

// Useful if key is a null-terminated string. (Note - using fixed-size keys, so
// key must still be padded to correctly compare keys in a bucket.)
uint32_t
cf_shash_fn_zstr(const void* key)
{
	return cf_wyhash32((const uint8_t*)key, strlen(key));
}


//==========================================================
// Public API.
//

cf_shash*
cf_shash_create(cf_shash_hash_fn h_fn, uint32_t key_size, uint32_t value_size,
		uint32_t n_buckets, bool thread_safe)
{
	cf_assert(h_fn != NULL && key_size != 0 && n_buckets != 0, CF_MISC,
			"bad param");
	// Note - value_size 0 works, and is used.

	cf_shash* h = cf_malloc(sizeof(cf_shash));

	h->h_fn = h_fn;
	h->key_size = key_size;
	h->value_size = value_size;
	h->ele_size = sizeof(cf_shash_ele) + key_size + value_size;
	h->n_buckets = n_buckets;
	h->thread_safe = thread_safe;
	h->n_elements = 0;
	h->table = (cf_shash_ele*)cf_malloc(n_buckets * h->ele_size);

	cf_shash_clear_table(h);

	if (thread_safe) {
		h->bucket_locks = cf_malloc(sizeof(cf_mutex) * n_buckets);

		for (uint32_t i = 0; i < n_buckets; i++) {
			cf_mutex_init(&h->bucket_locks[i]);
		}
	}

	return h;
}

void
cf_shash_destroy(cf_shash* h)
{
	cf_assert(h != NULL, CF_MISC, "bad param");

	cf_shash_destroy_elements(h);

	if (h->thread_safe) {
		for (uint32_t i = 0; i < h->n_buckets; i++) {
			cf_mutex_destroy(&h->bucket_locks[i]);
		}

		cf_free(h->bucket_locks);
	}

	cf_free(h->table);
	cf_free(h);
}

uint32_t
cf_shash_get_size(const cf_shash* h)
{
	cf_assert(h != NULL, CF_MISC, "bad param");

	return h->n_elements;
}

void
cf_shash_put(cf_shash* h, const void* key, const void* value)
{
	cf_assert(h != NULL && key != NULL && value != NULL, CF_MISC, "bad param");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	cf_mutex* l = cf_shash_lock(h, hash);

	// Most common case should be insert into empty bucket.
	if (! e->in_use) {
		cf_shash_fill_element(e, h, key, value);
		cf_shash_unlock(l);
		return;
	}

	cf_shash_ele* e_head = e;

	while (e != NULL) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) == 0) {
			// Replace the previous value with the new value.
			memcpy(ELE_VALUE(h, e), value, h->value_size);
			cf_shash_unlock(l);
			return;
		}

		e = e->next;
	}

	e = (cf_shash_ele*)cf_malloc(h->ele_size);

	cf_shash_fill_element(e, h, key, value);

	// Insert just after head.
	e->next = e_head->next;
	e_head->next = e;

	cf_shash_unlock(l);
}

int
cf_shash_put_unique(cf_shash* h, const void* key, const void* value)
{
	cf_assert(h != NULL && key != NULL && value != NULL, CF_MISC, "bad param");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	cf_mutex* l = cf_shash_lock(h, hash);

	// Most common case should be insert into empty bucket.
	if (! e->in_use) {
		cf_shash_fill_element(e, h, key, value);
		cf_shash_unlock(l);
		return CF_SHASH_OK;
	}

	cf_shash_ele* e_head = e;

	while (e != NULL) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) == 0) {
			cf_shash_unlock(l);
			return CF_SHASH_ERR_FOUND;
		}

		e = e->next;
	}

	e = (cf_shash_ele*)cf_malloc(h->ele_size);

	cf_shash_fill_element(e, h, key, value);

	// Insert just after head.
	e->next = e_head->next;
	e_head->next = e;

	cf_shash_unlock(l);

	return CF_SHASH_OK;
}

int
cf_shash_get(cf_shash* h, const void* key, void* value)
{
	cf_assert(h != NULL && key != NULL, CF_MISC, "bad param");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	if (! e->in_use) {
		return CF_SHASH_ERR_NOT_FOUND;
	}

	cf_mutex* l = cf_shash_lock(h, hash);

	while (e != NULL && e->in_use) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) == 0) {
			if (value != NULL) {
				memcpy(value, ELE_VALUE(h, e), h->value_size);
			}

			cf_shash_unlock(l);
			return CF_SHASH_OK;
		}

		e = e->next;
	}

	cf_shash_unlock(l);

	return CF_SHASH_ERR_NOT_FOUND;
}

int
cf_shash_get_vlock(cf_shash* h, const void* key, void** value_r,
		cf_mutex** vlock_r)
{
	cf_assert(h != NULL && key != NULL && value_r != NULL && vlock_r != NULL,
			CF_MISC, "bad param");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	if (! e->in_use) {
		return CF_SHASH_ERR_NOT_FOUND;
	}

	cf_mutex* l = cf_shash_lock(h, hash);

	while (e != NULL && e->in_use) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) == 0) {
			*value_r = ELE_VALUE(h, e);
			*vlock_r = l;
			return CF_SHASH_OK;
		}

		e = e->next;
	}

	cf_shash_unlock(l);

	return CF_SHASH_ERR_NOT_FOUND;
}

// Also returns value pointer instead of copy, but without lock.
int
cf_shash_get_p(cf_shash* h, const void* key, void** value_r)
{
	cf_assert(h != NULL && key != NULL && value_r != NULL, CF_MISC,
			"bad param");

	cf_assert(! h->thread_safe, CF_MISC,
			"called cf_shash_get_p() for thread-safe hash");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	if (! e->in_use) {
		return CF_SHASH_ERR_NOT_FOUND;
	}

	while (e != NULL && e->in_use) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) == 0) {
			*value_r = ELE_VALUE(h, e);
			return CF_SHASH_OK;
		}

		e = e->next;
	}

	return CF_SHASH_ERR_NOT_FOUND;
}

int
cf_shash_pop(cf_shash* h, const void* key, void* value)
{
	cf_assert(value != NULL, CF_MISC, "bad param");

	return cf_shash_delete_or_pop(h, key, value);
}

int
cf_shash_delete(cf_shash* h, const void* key)
{
	return cf_shash_delete_or_pop(h, key, NULL);
}

int
cf_shash_delete_lockfree(cf_shash* h, const void* key)
{
	cf_assert(h != NULL && key != NULL, CF_MISC, "bad param");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	cf_shash_ele* e_prev = NULL;

	// Look for the element, remove and release if found.
	while (e != NULL && e->in_use) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) != 0) {
			e_prev = e;
			e = e->next;
			continue;
		}
		// else - found it, remove from hash, free (if needed).

		// If not at head, patch pointers and free element.
		if (e_prev != NULL) {
			e_prev->next = e->next;
			cf_free(e);
		}
		// If at head with no next, empty head.
		else if (e->next == NULL) {
			e->in_use = false;
		}
		// If at head with a next, copy next into head and free next.
		else {
			cf_shash_ele* free_e = e->next;

			memcpy(e, e->next, h->ele_size);
			cf_free(free_e);
		}

		cf_shash_size_decr(h);

		return CF_SHASH_OK;
	}

	return CF_SHASH_ERR_NOT_FOUND;
}

void
cf_shash_delete_all(cf_shash* h)
{
	cf_assert(h != NULL, CF_MISC, "bad param");

	uint8_t* bucket = (uint8_t*)h->table;

	for (uint32_t i = 0; i < h->n_buckets; i++) {
		// Don't bother optimizing for already empty bucket.
		cf_mutex* l = cf_shash_lock(h, i);

		cf_shash_ele* e = ((cf_shash_ele*)bucket)->next;

		while (e != NULL) {
			cf_shash_ele* temp = e->next;

			cf_free(e);
			e = temp;

			cf_shash_size_decr(h);
		}

		if (((cf_shash_ele*)bucket)->in_use) {
			((cf_shash_ele*)bucket)->in_use = false;
			((cf_shash_ele*)bucket)->next = NULL;

			cf_shash_size_decr(h);
		}

		cf_shash_unlock(l);

		bucket += h->ele_size;
	}
}

int
cf_shash_reduce(cf_shash* h, cf_shash_reduce_fn reduce_fn, void* udata)
{
	cf_assert(h != NULL && reduce_fn != NULL, CF_MISC, "bad param");

	if (h->n_elements == 0) {
		return CF_SHASH_OK;
	}

	uint8_t* bucket = (uint8_t*)h->table;

	for (uint32_t i = 0; i < h->n_buckets; i++) {
		cf_shash_ele* e = (cf_shash_ele*)bucket;

		if (! e->in_use) {
			bucket += h->ele_size;
			continue;
		}

		cf_mutex* l = cf_shash_lock(h, i);

		cf_shash_ele* e_prev = NULL;

		while (e != NULL && e->in_use) {
			int rv = reduce_fn(ELE_KEY(h, e), ELE_VALUE(h, e), udata);

			if (rv == CF_SHASH_OK) {
				// Caller says keep going - most common case.

				e_prev = e;
				e = e->next;
			}
			else if (rv == CF_SHASH_REDUCE_DELETE) {
				// Caller says delete this element and keep going.

				// If not at head, patch pointers and free element.
				if (e_prev != NULL) {
					e_prev->next = e->next;
					cf_free(e);
					e = e_prev->next;
				}
				// If at head with no next, empty head.
				else if (e->next == NULL) {
					e->in_use = false;
				}
				// If at head with a next, copy next into head and free next.
				else {
					cf_shash_ele* free_e = e->next;

					memcpy(e, e->next, h->ele_size);
					cf_free(free_e);
				}

				cf_shash_size_decr(h);
			}
			else {
				// Caller says stop iterating.
				cf_shash_unlock(l);
				return rv;
			}
		}

		cf_shash_unlock(l);

		bucket += h->ele_size;
	}

	return CF_SHASH_OK;
}


//==========================================================
// Local helpers.
//

static inline void
cf_shash_clear_table(cf_shash* h)
{
	uint8_t* bucket = (uint8_t*)h->table;
	uint8_t* end = bucket + (h->n_buckets * h->ele_size);

	while (bucket < end) {
		((cf_shash_ele*)bucket)->next = NULL;
		((cf_shash_ele*)bucket)->in_use = false;
		bucket += h->ele_size;
	}
}

static inline void
cf_shash_destroy_elements(cf_shash* h)
{
	uint8_t* bucket = (uint8_t*)h->table;
	uint8_t* end = bucket + (h->n_buckets * h->ele_size);

	while (bucket < end) {
		cf_shash_ele* e = ((cf_shash_ele*)bucket)->next;

		while (e != NULL) {
			cf_shash_ele* temp = e->next;

			cf_free(e);
			e = temp;
		}

		bucket += h->ele_size;
	}
}

static inline uint32_t
cf_shash_calculate_hash(cf_shash* h, const void* key)
{
	return h->h_fn(key) % h->n_buckets;
}

static inline cf_mutex*
cf_shash_lock(cf_shash* h, uint32_t i)
{
	cf_mutex* l = NULL;

	if (h->thread_safe) {
		l = &h->bucket_locks[i];
		cf_mutex_lock(l);
	}

	return l;
}

static inline void
cf_shash_unlock(cf_mutex* l)
{
	if (l != NULL) {
		cf_mutex_unlock(l);
	}
}

static inline cf_shash_ele*
cf_shash_get_bucket(cf_shash* h, uint32_t i)
{
	return (cf_shash_ele*)((uint8_t*)h->table + (h->ele_size * i));
}

static inline void
cf_shash_fill_element(cf_shash_ele* e, cf_shash* h, const void* key,
		const void* value)
{
	memcpy(ELE_KEY(h, e), key, h->key_size);
	memcpy(ELE_VALUE(h, e), value, h->value_size);
	e->in_use = true;
	cf_shash_size_incr(h);
}

static inline void
cf_shash_size_incr(cf_shash* h)
{
	as_incr_uint32(&h->n_elements);
}

static inline void
cf_shash_size_decr(cf_shash* h)
{
	as_decr_uint32(&h->n_elements);
}

static int
cf_shash_delete_or_pop(cf_shash* h, const void* key, void* value)
{
	cf_assert(h != NULL && key != NULL, CF_MISC, "bad param");

	uint32_t hash = cf_shash_calculate_hash(h, key);
	cf_shash_ele* e = cf_shash_get_bucket(h, hash);

	if (! e->in_use) {
		return CF_SHASH_ERR_NOT_FOUND;
	}

	cf_mutex* l = cf_shash_lock(h, hash);

	cf_shash_ele* e_prev = NULL;

	// Look for the element, remove and release if found.
	while (e != NULL && e->in_use) {
		if (memcmp(ELE_KEY(h, e), key, h->key_size) != 0) {
			e_prev = e;
			e = e->next;
			continue;
		}
		// else - found it, remove from hash, free (if needed) outside lock.

		// Return value.
		if (value != NULL) {
			memcpy(value, ELE_VALUE(h, e), h->value_size);
		}

		// Save pointer to free.
		cf_shash_ele* free_e = NULL;

		// If not at head, patch pointers and free element.
		if (e_prev != NULL) {
			e_prev->next = e->next;
			free_e = e;
		}
		// If at head with no next, empty head.
		else if (e->next == NULL) {
			e->in_use = false;
		}
		// If at head with a next, copy next into head and free next.
		else {
			free_e = e->next;
			memcpy(e, e->next, h->ele_size);
		}

		cf_shash_size_decr(h);
		cf_shash_unlock(l);

		if (free_e != NULL) {
			cf_free(free_e);
		}

		return CF_SHASH_OK;
	}

	cf_shash_unlock(l);

	return CF_SHASH_ERR_NOT_FOUND;
}
