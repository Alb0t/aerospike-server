/*
 * query_manager.c
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

//==========================================================
// Includes.
//

#include "query/query_manager.h"

#include <stdbool.h>
#include <stdint.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "dynbuf.h"
#include "log.h"

#include "base/cfg.h"
#include "base/proto.h"
#include "base/thr_info.h"
#include "fabric/partition.h"
#include "query/query_job.h"

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

typedef struct find_item_s {
	uint64_t trid;
	as_query_job* _job;
	bool remove_job;
} find_item;

typedef struct info_item_s {
	as_query_job** p_job;
} info_item;


//==========================================================
// Globals.
//

uint32_t g_n_query_threads = 0;

static as_query_manager g_mgr;


//==========================================================
// Forward declarations.
//

static void add_query_job_thread(as_query_job* _job);
static void evict_finished_jobs(void);
static int abort_cb(void* buf, void* udata);
static int info_cb(void* buf, void* udata);
static as_query_job* find_any(uint64_t trid);
static as_query_job* find_active(uint64_t trid);
static as_query_job* remove_active(uint64_t trid);
static as_query_job* find_job(cf_queue* jobs, uint64_t trid, bool remove_job);
static int find_cb(void* buf, void* udata);


//==========================================================
// Public API.
//

void
as_query_manager_init(void)
{
	cf_mutex_init(&g_mgr.lock);

	g_mgr.active_jobs = cf_queue_create(sizeof(as_query_job*), false);
	g_mgr.finished_jobs = cf_queue_create(sizeof(as_query_job*), false);
}

int
as_query_manager_start_job(as_query_job* _job)
{
	if (_job->si != NULL) {
		_job->start_ms_clepoch = cf_clepoch_milliseconds();
	}

	if (_job->do_inline) {
		as_query_job_run((void*)_job);
		return 0;
	}

	cf_mutex_lock(&g_mgr.lock);

	if (g_n_query_threads >= g_config.n_query_threads_limit) {
		cf_warning(AS_QUERY, "at query threads limit - can't start new query");
		cf_mutex_unlock(&g_mgr.lock);
		return AS_ERR_FORBIDDEN;
	}

	if (! _job->is_short) {
		_job->base_us = _job->start_ns / 1000; // for throttling

		// Make sure trid is unique.
		if (find_any(_job->trid)) {
			cf_warning(AS_QUERY, "job with trid %lu already active",
					_job->trid);
			cf_mutex_unlock(&g_mgr.lock);
			return AS_ERR_PARAMETER;
		}

		cf_queue_push(g_mgr.active_jobs, &_job);
	}

	add_query_job_thread(_job);

	cf_mutex_unlock(&g_mgr.lock);

	return 0;
}

void
as_query_manager_add_job_thread(as_query_job* _job)
{
	if ((_job->n_pids_requested != 0 &&
			_job->n_threads >= (uint32_t)_job->n_pids_requested) ||
			_job->n_threads >= _job->ns->n_single_query_threads) {
		return;
	}

	cf_mutex_lock(&g_mgr.lock);

	if (g_n_query_threads < g_config.n_query_threads_limit) {
		add_query_job_thread(_job);
	}

	cf_mutex_unlock(&g_mgr.lock);
}

void
as_query_manager_add_max_job_threads(as_query_job* _job)
{
	uint32_t n_pids = _job->n_pids_requested == 0 ?
			AS_PARTITIONS : (uint32_t)_job->n_pids_requested;

	if (_job->n_threads >= n_pids) {
		return;
	}

	uint32_t single_max = as_load_uint32(&_job->ns->n_single_query_threads);

	if (_job->n_threads >= single_max) {
		return;
	}

	// Don't need more threads than there are partitions to query.
	uint32_t n_extra = n_pids - _job->n_threads;

	uint32_t single_extra = single_max - _job->n_threads;

	if (single_extra < n_extra) {
		n_extra = single_extra;
	}

	uint32_t all_max = as_load_uint32(&g_config.n_query_threads_limit);

	cf_mutex_lock(&g_mgr.lock);

	if (g_n_query_threads >= all_max) {
		cf_mutex_unlock(&g_mgr.lock);
		return;
	}

	uint32_t all_extra = all_max - g_n_query_threads;

	if (all_extra < n_extra) {
		n_extra = all_extra;
	}

	for (uint32_t n = 0; n < n_extra; n++) {
		add_query_job_thread(_job);
	}

	cf_mutex_unlock(&g_mgr.lock);
}

void
as_query_manager_finish_job(as_query_job* _job)
{
	cf_mutex_lock(&g_mgr.lock);

	remove_active(_job->trid);

	_job->finish_ns = cf_getns();
	cf_queue_push(g_mgr.finished_jobs, &_job);
	evict_finished_jobs();

	cf_mutex_unlock(&g_mgr.lock);
}

void
as_query_manager_abandon_job(as_query_job* _job, int reason)
{
	_job->abandoned = reason;
}

bool
as_query_manager_abort_job(uint64_t trid)
{
	cf_mutex_lock(&g_mgr.lock);

	as_query_job* _job = find_active(trid);

	cf_mutex_unlock(&g_mgr.lock);

	if (_job == NULL) {
		return false;
	}

	_job->abandoned = AS_ERR_QUERY_ABORT;

	return true;
}

uint32_t
as_query_manager_abort_all_jobs(void)
{
	cf_mutex_lock(&g_mgr.lock);

	uint32_t n_jobs = cf_queue_sz(g_mgr.active_jobs);

	if (n_jobs != 0) {
		cf_queue_reduce(g_mgr.active_jobs, abort_cb, NULL);
	}

	cf_mutex_unlock(&g_mgr.lock);

	return n_jobs;
}

void
as_query_manager_limit_finished_jobs(void)
{
	cf_mutex_lock(&g_mgr.lock);

	evict_finished_jobs();

	cf_mutex_unlock(&g_mgr.lock);
}

void
as_query_manager_get_job_info(uint64_t trid, cf_dyn_buf* db)
{
	cf_mutex_lock(&g_mgr.lock);

	as_query_job* _job = find_any(trid);

	if (_job == NULL) {
		cf_mutex_unlock(&g_mgr.lock);

		as_info_respond_error(db, AS_ERR_NOT_FOUND, "job not found");

		return;
	}

	as_query_job_info(_job, db);

	cf_mutex_unlock(&g_mgr.lock);
}

void
as_query_manager_get_all_jobs_info(cf_dyn_buf* db)
{
	cf_mutex_lock(&g_mgr.lock);

	uint32_t n_jobs = cf_queue_sz(g_mgr.active_jobs) +
			cf_queue_sz(g_mgr.finished_jobs);

	if (n_jobs == 0) {
		cf_mutex_unlock(&g_mgr.lock);
		return;
	}

	as_query_job* _jobs[n_jobs];
	info_item item = { _jobs };

	cf_queue_reduce_reverse(g_mgr.active_jobs, info_cb, &item);
	cf_queue_reduce_reverse(g_mgr.finished_jobs, info_cb, &item);

	for (uint32_t i = 0; i < n_jobs; i++) {
		as_query_job* _job = _jobs[i];

		as_query_job_info(_job, db);

		cf_dyn_buf_append_char(db, ';');
	}

	cf_dyn_buf_chomp(db);

	cf_mutex_unlock(&g_mgr.lock);
}

uint32_t
as_query_manager_get_active_job_count(void)
{
	return cf_queue_sz(g_mgr.active_jobs);
}


//==========================================================
// Local helpers.
//

static void
add_query_job_thread(as_query_job* _job)
{
	as_incr_uint32(&g_n_query_threads);
	as_incr_uint32(&_job->n_threads);

	cf_thread_create_transient(as_query_job_run, _job);
}

static void
evict_finished_jobs(void)
{
	uint32_t max_allowed = as_load_uint32(&g_config.query_max_done);

	while (cf_queue_sz(g_mgr.finished_jobs) > max_allowed) {
		as_query_job* _job;

		cf_queue_pop(g_mgr.finished_jobs, &_job, 0);
		as_query_job_destroy(_job);
	}
}

static int
abort_cb(void* buf, void* udata)
{
	(void)udata;

	as_query_job* _job = *(as_query_job**)buf;

	_job->abandoned = AS_ERR_QUERY_ABORT;

	return 0;
}

static int
info_cb(void* buf, void* udata)
{
	as_query_job* _job = *(as_query_job**)buf;
	info_item* item = (info_item*)udata;

	*item->p_job++ = _job;

	return 0;
}

static as_query_job*
find_any(uint64_t trid)
{
	as_query_job* _job = find_job(g_mgr.active_jobs, trid, false);

	if (_job == NULL) {
		_job = find_job(g_mgr.finished_jobs, trid, false);
	}

	return _job;
}

static as_query_job*
find_active(uint64_t trid)
{
	return find_job(g_mgr.active_jobs, trid, false);
}

static as_query_job*
remove_active(uint64_t trid)
{
	return find_job(g_mgr.active_jobs, trid, true);
}

static as_query_job*
find_job(cf_queue* jobs, uint64_t trid, bool remove_job)
{
	find_item item = { trid, NULL, remove_job };

	cf_queue_reduce(jobs, find_cb, &item);

	return item._job;
}

static int
find_cb(void* buf, void* udata)
{
	as_query_job* _job = *(as_query_job**)buf;
	find_item* match = (find_item*)udata;

	if (match->trid == _job->trid) {
		match->_job = _job;
		return match->remove_job ? -2 : -1;
	}

	return 0;
}
