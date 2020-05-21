/*
 * rw_utils_ce.c
 *
 * Copyright (C) 2016-2020 Aerospike, Inc.
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

#include "transaction/rw_utils.h"

#include <stdbool.h>
#include <stdint.h>

#include "log.h"
#include "msg.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/transaction.h"
#include "base/udf_record.h"
#include "storage/storage.h"
#include "transaction/rw_request.h"
#include "transaction/udf.h"


//==========================================================
// Public API.
//

int
validate_delete_durability(as_transaction* tr)
{
	if (as_transaction_is_durable_delete(tr)) {
		cf_warning(AS_RW, "durable delete is an enterprise feature");
		return AS_ERR_ENTERPRISE_ONLY;
	}

	return AS_OK;
}


int
repl_state_check(as_record* r, as_transaction* tr)
{
	return 0;
}


void
will_replicate(as_record* r, as_namespace* ns)
{
}


bool
write_is_full_drop(const as_transaction* tr)
{
	return IS_DROP(tr);
}


bool
set_replica_destinations(as_transaction* tr, rw_request* rw)
{
	rw->n_dest_nodes = as_partition_get_other_replicas(tr->rsv.p,
			rw->dest_nodes);

	return true;
}


void
finished_replicated(as_transaction* tr)
{
}


void
finished_not_replicated(rw_request* rw)
{
}


bool
generation_check(const as_record* r, const as_msg* m, const as_namespace* ns)
{
	if ((m->info2 & AS_MSG_INFO2_GENERATION) != 0) {
		return m->generation == r->generation;
	}

	if ((m->info2 & AS_MSG_INFO2_GENERATION_GT) != 0) {
		return m->generation > r->generation;
	}

	return true; // no generation requirement
}


void
stash_index_metadata(const as_record* r, index_metadata* old)
{
	old->void_time = r->void_time;
	old->last_update_time = r->last_update_time;
	old->generation = r->generation;
}


void
unwind_index_metadata(const index_metadata* old, as_record* r)
{
	r->void_time = old->void_time;
	r->last_update_time = old->last_update_time;
	r->generation = old->generation;
}


void
set_xdr_write(const as_transaction* tr, as_record* r)
{
}


void
transition_delete_metadata(as_transaction* tr, as_record* r, bool is_delete)
{
}


//==========================================================
// Private API - for enterprise separation only.
//

bool
create_only_check(const as_record* r, const as_msg* m)
{
	// Ok (return true) if no requirement.
	return (m->info2 & AS_MSG_INFO2_CREATE_ONLY) == 0;
}


void
write_delete_record(as_record* r, as_index_tree* tree)
{
	as_index_delete(tree, &r->keyd);
}


udf_optype
udf_finish_delete(udf_record* urecord)
{
	return (urecord->flag & UDF_RECORD_FLAG_PREEXISTS) != 0 ?
			UDF_OPTYPE_DELETE : UDF_OPTYPE_NONE;
}


uint32_t
dup_res_pack_repl_state_info(const as_record* r, const as_namespace* ns)
{
	return 0;
}


bool
dup_res_should_retry_transaction(rw_request* rw, uint32_t result_code)
{
	return false;
}


void
dup_res_handle_tie(rw_request* rw, const msg* m, uint32_t result_code)
{
}


void
apply_if_tie(rw_request* rw)
{
}


void
dup_res_translate_result_code(rw_request* rw)
{
	rw->result_code = AS_OK;
}


void
dup_res_init_repl_state(as_remote_record* rr, uint32_t info)
{
}


void
repl_write_init_repl_state(as_remote_record* rr, bool from_replica)
{
}


conflict_resolution_pol
repl_write_conflict_resolution_policy(const as_namespace* ns)
{
	return AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_LAST_UPDATE_TIME;
}


bool
repl_write_should_retransmit_replicas(rw_request* rw, uint32_t result_code)
{
	switch (result_code) {
	case AS_ERR_CLUSTER_KEY_MISMATCH:
		rw->xmit_ms = 0; // force retransmit on next cycle
		return true;
	default:
		return false;
	}
}


void
repl_write_send_confirmation(rw_request* rw)
{
}


void
repl_write_handle_confirmation(msg* m)
{
}


int
record_replace_check(as_record* r, as_namespace* ns)
{
	return 0;
}


void
record_replaced(as_record* r, as_remote_record* rr)
{
}
