/*
 * cfg_info.h
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

#include "dynbuf.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;


//==========================================================
// Public API.
//

void as_cfg_info_cmd_config_get_with_params(const char* name, const char* params, cf_dyn_buf* db);
void as_cfg_info_cmd_config_get(const char* name, const char* params, cf_dyn_buf* db);
void as_cfg_info_namespace_config_get(const struct as_namespace_s* ns, cf_dyn_buf* db);
void as_cfg_info_cmd_config_set(const char* name, const char* params, cf_dyn_buf* db);
