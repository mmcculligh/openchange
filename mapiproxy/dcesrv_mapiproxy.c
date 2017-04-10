/*
   MAPI Proxy

   This proxy is based on dcesrv_remote.c code from Stefan Metzemacher

   OpenChange Project

   Copyright (C) Julien Kerihuel 2008-2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/dcesrv_mapiproxy_proto.h"
#include "utils/dlinklist.h"
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"

/* Default interfaces to use if no others were specified in smb.conf. */
#define DEFAULT_INTERFACES "exchange_emsmdb, exchange_nsp, exchange_ds_rfr"

static int dispatch_nbr = 0;

/**
   \file dcesrv_mapiproxy.c

   \brief mapiproxy main file
 */


static NTSTATUS mapiproxy_op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	OC_DEBUG(5, "mapiproxy::mapiproxy_op_reply");
	return NT_STATUS_OK;
}

static NTSTATUS mapiproxy_op_connect(struct dcesrv_call_state *dce_call, 
				     const struct ndr_interface_table *table,
				     const char *binding)
{
	NTSTATUS				status;
	struct dcesrv_mapiproxy_private		*private;
	const char				*user;
	const char				*pass;
	const char				*domain;
	char					*self_service;
	char					*target_service;
	struct cli_credentials			*credentials;
	bool					acquired_creds = false;
	bool					machine_account;
	bool					delegated;

	OC_DEBUG(5, "mapiproxy::mapiproxy_op_connect");

	/* Retrieve the binding string from parametric options if undefined */
	if (!binding) {
		binding = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "binding");
		if (!binding) {
			OC_DEBUG(0, "You must specify a DCE/RPC binding string");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	/* Retrieve parametric options */
	machine_account = lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "use_machine_account", false);
	delegated = lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "delegated_auth", false);
	user = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "username");
	pass = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "password");
	domain = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "domain");

	/* Retrieve private mapiproxy data */
	private = dce_call->context->private_data;

	if (private->oa_mode) {
		OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: Using anonymous credentials");
		credentials = cli_credentials_init(private);
		if (!credentials) {
			return NT_STATUS_NO_MEMORY;
		}

		cli_credentials_set_anonymous(credentials);
	} else if (user && pass) {
		OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: Using specified account: %s", user);
		credentials = cli_credentials_init(private);
		if (!credentials) {
			return NT_STATUS_NO_MEMORY;
		}

		cli_credentials_set_conf(credentials, dce_call->conn->dce_ctx->lp_ctx);
		cli_credentials_set_username(credentials, user, CRED_SPECIFIED);
		if (domain) {
			cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
		}
		cli_credentials_set_password(credentials, pass, CRED_SPECIFIED);
	} else if (machine_account) {
		OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: Using machine account");
		credentials = cli_credentials_init(private);
		if (!credentials) {
			return NT_STATUS_NO_MEMORY;
		}
		cli_credentials_set_conf(credentials, dce_call->conn->dce_ctx->lp_ctx);
		if (domain) {
			cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
		}
		status = cli_credentials_set_machine_account(credentials, dce_call->conn->dce_ctx->lp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else if (delegated) {
		/* Constrained delegation requires the S4U2Self and S4U2Proxy extensions in Kerberos */
		OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: Using machine account with constrained delegation");
		credentials = cli_credentials_init(private);
		if (!credentials) {
			return NT_STATUS_NO_MEMORY;
		}
		cli_credentials_set_conf(credentials, dce_call->conn->dce_ctx->lp_ctx);
		status = cli_credentials_set_machine_account(credentials, dce_call->conn->dce_ctx->lp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		OC_DEBUG(5, "Impersonating %s", dce_call->conn->auth_state.session_info->info->account_name);

		/* Determine what interface this is, the service principal names are different for each service */
		if (table->name && !strcmp(table->name, NDR_EXCHANGE_DS_RFR_NAME)) {
			struct dcerpc_binding		*b;

			/* Set the desired principal (authenticated client) and our own service principal name (SPN) for S4U2Self stage */
			self_service = talloc_asprintf(dce_call,"exchangeRFR/%s.%s", lpcfg_netbios_name(dce_call->conn->dce_ctx->lp_ctx), lpcfg_realm(dce_call->conn->dce_ctx->lp_ctx));
			cli_credentials_set_impersonate_principal(credentials, dce_call->conn->auth_state.session_info->info->account_name, self_service);
			talloc_free(self_service);

			/* Parse binding string to determine the hostname of the target */
			status = dcerpc_parse_binding(dce_call->context, binding, &b);
			if (!NT_STATUS_IS_OK(status)) {
				OC_DEBUG(0, "Failed to parse dcerpc binding '%s'", binding);
				return status;
			}

			/* Set the target service princial name (SPN) for the S4U2Proxy stage */
			char* properHostname = strupper_talloc(dce_call,b->host);
			target_service = talloc_asprintf(dce_call,"exchangeRFR/%s", properHostname);
			cli_credentials_set_target_service(credentials, target_service);
			talloc_free(target_service);
			talloc_free(properHostname);
		}
		else if (table->name && !strcmp(table->name, NDR_EXCHANGE_NSP_NAME)) {
			struct dcerpc_binding		*b;

			/* Set the desired principal (authenticated client) and our own service principal name (SPN) for S4U2Self stage */
			self_service = talloc_asprintf(dce_call,"exchangeAB/%s.%s", lpcfg_netbios_name(dce_call->conn->dce_ctx->lp_ctx), lpcfg_realm(dce_call->conn->dce_ctx->lp_ctx));
			cli_credentials_set_impersonate_principal(credentials, dce_call->conn->auth_state.session_info->info->account_name, self_service);
			talloc_free(self_service);

			/* The NSP interface isn't likely found on the main target, it could be on a different server like the domain controller */
			binding = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "nsp_binding");
			if (!binding) {
				OC_DEBUG(0, "You must specify a DCE/RPC binding string for the exchange_nsp interface using nsp_binding");
				return NT_STATUS_INVALID_PARAMETER;
			}

			/* Parse binding string to determine the hostname of the target */
			status = dcerpc_parse_binding(dce_call->context, binding, &b);
			if (!NT_STATUS_IS_OK(status)) {
				OC_DEBUG(0, "Failed to parse dcerpc binding '%s'", binding);
				return status;
			}

			/* Set the target service princial name (SPN) for the S4U2Proxy stage */
			char* properHostname = strupper_talloc(dce_call,b->host);
			target_service = talloc_asprintf(dce_call,"exchangeAB/%s",properHostname);
			cli_credentials_set_target_service(credentials, target_service);
			talloc_free(target_service);
			talloc_free(properHostname);
		}
		else if (table->name && !strcmp(table->name, NDR_EXCHANGE_EMSMDB_NAME))	{
			struct dcerpc_binding		*b;

			/* Set the desired principal (authenticated client) and our own service principal name (SPN) for S4U2Self stage */
			self_service = talloc_asprintf(dce_call,"exchangeMDB/%s.%s", lpcfg_netbios_name(dce_call->conn->dce_ctx->lp_ctx), lpcfg_realm(dce_call->conn->dce_ctx->lp_ctx));
			cli_credentials_set_impersonate_principal(credentials, dce_call->conn->auth_state.session_info->info->account_name, self_service);
			talloc_free(self_service);

			/* Parse binding string to determine the hostname of the target */
			status = dcerpc_parse_binding(dce_call->context, binding, &b);
			if (!NT_STATUS_IS_OK(status)) {
				OC_DEBUG(0, "Failed to parse dcerpc binding '%s'", binding);
				return status;
			}

			/* Set the target service princial name (SPN) for the S4U2Proxy stage */
			char* properHostname = strupper_talloc(dce_call,b->host);
			target_service = talloc_asprintf(dce_call,"exchangeMDB/%s", properHostname);
			cli_credentials_set_target_service(credentials, target_service);
			talloc_free(target_service);
			talloc_free(properHostname);
		}
		else {
			OC_DEBUG(0, "Unknown interface not supported for constrained delegation.");
			return NT_STATUS_INVALID_PARAMETER;
		}
	} else if (dcesrv_call_credentials(dce_call)) {
		OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: Using delegated credentials");
		credentials = dcesrv_call_credentials(dce_call);
		acquired_creds = true;
	} else if (private->credentials) {
		OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: Using acquired deletegated credentials");
		credentials = private->credentials;
		acquired_creds = true;
	} else {
		oc_log(OC_LOG_ERROR, "dcerpc_mapiproxy: RPC proxy: You must supply binding, user and password or have delegated credentials");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Always use the local binding parsing code path since we need to control the flags and assoc_group_id */
	if (true) {
		struct dcerpc_binding		*b;
		struct composite_context	*pipe_conn_req;

		/* parse binding string to the structure */
		status = dcerpc_parse_binding(dce_call->context, binding, &b);
		if (!NT_STATUS_IS_OK(status)) {
			oc_log(OC_LOG_ERROR, "dcerpc_mapiproxy: Failed to parse dcerpc binding '%s'", binding);
			return status;
		}

		/* Enable multiplex on the RPC pipe */
		b->flags|= DCERPC_CONCURRENT_MULTIPLEX;

		OC_DEBUG(3, "Using binding %s", dcerpc_binding_string(dce_call->context, b));

		switch (dce_call->pkt.ptype) {
		case DCERPC_PKT_BIND:
			b->assoc_group_id = dce_call->context->assoc_group->proxied_id;
			break;
		case DCERPC_PKT_ALTER:
			b->assoc_group_id = dce_call->context->assoc_group->proxied_id;
			break;
		default:
			break;
		}
		
		pipe_conn_req = dcerpc_pipe_connect_b_send(dce_call->context, b, table,
							   credentials, dce_call->event_ctx, dce_call->conn->dce_ctx->lp_ctx);
		status = dcerpc_pipe_connect_b_recv(pipe_conn_req, dce_call->context, &(private->c_pipe));

		if (acquired_creds == false) {
			talloc_unlink(private,credentials);
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		dce_call->context->assoc_group->proxied_id = private->c_pipe->assoc_group_id;
	} else {
		status = dcerpc_pipe_connect(dce_call->context,
					     &(private->c_pipe), binding, table,
					     credentials, dce_call->event_ctx,
					     dce_call->conn->dce_ctx->lp_ctx);
		
		if (acquired_creds == false) {
			talloc_free(credentials);
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		dce_call->context->assoc_group->proxied_id = private->c_pipe->assoc_group_id;
	}

	private->connected = true;

	OC_DEBUG(5, "dcerpc_mapiproxy: RPC proxy: CONNECTED");

	return NT_STATUS_OK;
}

static NTSTATUS mapiproxy_op_bind_proxy(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
	NTSTATUS				status = NT_STATUS_OK;
	const struct ndr_interface_table	*table;
	struct dcesrv_mapiproxy_private		*private;
	bool					delegated;

	/* Retrieve private mapiproxy data */
	private = dce_call->context->private_data;

	table = ndr_table_by_uuid(&iface->syntax_id.uuid);
	if (!table) {
		dce_call->fault_code = DCERPC_FAULT_UNK_IF;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	if (dcesrv_call_credentials(dce_call)) {
		private->credentials = dcesrv_call_credentials(dce_call);
		if (cli_credentials_is_anonymous(private->credentials))	{
			OC_DEBUG(5, "dcerpc_mapiproxy: Anonymous credentials being used by client");
		}
		else {
			OC_DEBUG(5, "dcerpc_mapiproxy: Delegated credentials acquired from client for user %s\%s", private->credentials->domain, private->credentials->username);
		}
	}

	delegated = lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "delegated_auth", false);
	if (delegated == false) {
		status = mapiproxy_op_connect(dce_call, table, NULL);
	}

	return status;
}


/**
   \details This function is called when the client binds to one of
   the interfaces mapiproxy handles.

   \param dce_call pointer to the session context
   \param iface pointer to the dcesrv interface structure with
   function hooks
   \param if_version the version of the pipe

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
static NTSTATUS mapiproxy_op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
	struct dcesrv_mapiproxy_private		*private;
	bool					server_mode;
	bool					oa_mode;
	bool					ndrdump;
	char					*server_id_printable = NULL;
	
	server_id_printable = server_id_str(NULL, &(dce_call->conn->server_id));
	OC_DEBUG(5, "mapiproxy::mapiproxy_op_bind: [session = 0x%x] [session server id = %s] [interface = %s]",
		  dce_call->context->context_id, server_id_printable, iface->name);
	talloc_free(server_id_printable);

	OC_DEBUG(5, "mapiproxy::mapiproxy_op_bind: [session = 0x%x] [session server id = 0x%"PRIx64" 0x%x 0x%x]", dce_call->context->context_id,
		  dce_call->conn->server_id.pid, dce_call->conn->server_id.task_id, dce_call->conn->server_id.vnn);

	/* Retrieve server mode parametric option */
	server_mode = lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "server", true);

	/* Retrieve OA mode parametric option */
	oa_mode = lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "oa_mode", false);

	/* Retrieve ndrdump parametric option */
	ndrdump = lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "ndrdump", false);

	/* Initialize private structure to all zeros */
	private = talloc_zero(dce_call->context, struct dcesrv_mapiproxy_private);
	if (!private) {
		return NT_STATUS_NO_MEMORY;
	}
	
	private->server_mode = server_mode;
	private->oa_mode = oa_mode;
	private->connected = false;
	private->ndrdump = ndrdump;

	dce_call->context->private_data = private;
	dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_MULTIPLEXED;

	if (server_mode == false) {
		if (dce_call->pkt.ptype == DCERPC_PKT_BIND)
		{
			OC_DEBUG(5, "mapiproxy::mapiproxy_op_bind: Bind with initial assoc_group_id 0x%x, resulting assoc_group_id 0x%x",dce_call->pkt.u.bind.assoc_group_id, dce_call->context->assoc_group->id);
		}
		else if (dce_call->pkt.ptype == DCERPC_PKT_ALTER)
		{
			OC_DEBUG(5, "mapiproxy::mapiproxy_op_bind: Alter context with assoc_group_id 0x%x",dce_call->pkt.u.alter.assoc_group_id);
		}

		if (dce_call->pkt.ptype == DCERPC_PKT_ALTER) {
			// Find the existing context with the server (pipe connection to the server)
			struct dcesrv_connection_context *pContext = dce_call->conn->contexts;
			while (pContext) {
				// Disable the check for matching assoc_group_id, Outlook 2013 doesn't send it?
				// TODO: Revisit this later
				//if (pContext->assoc_group->id == dce_call->pkt.u.alter.assoc_group_id)
				{
					struct dcesrv_mapiproxy_private *context_private = (struct dcesrv_mapiproxy_private *)pContext->private_data;
					if (context_private != NULL) {
						if (context_private->c_pipe != NULL) {
							// Found it, create secondary context for this interface
							NTSTATUS status = dcerpc_secondary_context(context_private->c_pipe,&private->c_pipe,dce_call->context->iface->private_data);
							if (NT_STATUS_IS_OK(status)) {
								private->connected = true;
							}

							return status;
						}
					}
				}

				pContext = pContext->next;
			}

			return NT_STATUS_INVALID_PARAMETER;
		}
		else {
			return mapiproxy_op_bind_proxy(dce_call, iface, if_version);
		}
	}

	return NT_STATUS_OK;
}


/**
   \details Called when the client disconnects from one of the
   endpoints managed by mapiproxy.

   \param context pointer to the connection context
   \param iface pointer to the dcesrv interface structure with
   function hooks
 */
static void mapiproxy_op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
	struct dcesrv_mapiproxy_private	*private = (struct dcesrv_mapiproxy_private *) context->private_data;

	OC_DEBUG(5, "mapiproxy::mapiproxy_op_unbind\n");

	mapiproxy_module_unbind(context->conn->server_id, context->context_id);
	mapiproxy_server_unbind(context->conn->server_id, context->context_id);

	if (private) {
		talloc_free(private->c_pipe);
		talloc_free(private);
	}

	return;
}


/**
   \details This is the function called when mapiproxy receives a
   request. The request has already been extracted and its information
   filled into structures

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param pull pointer on pointer to the ndr_pull structure
   \param r generic pointer on pointer to the pulled ndr content

   \return NT_STATUS_OK on success, other NTSTATUS error
 */
static NTSTATUS mapiproxy_op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	NTSTATUS				status;
	enum ndr_err_code			ndr_err;
	const struct ndr_interface_table	*table;
	uint16_t				opnum;
	struct dcesrv_mapiproxy_private		*private;

	OC_DEBUG(5, "mapiproxy::mapiproxy_op_ndr_pull");

	private = dce_call->context->private_data;
	table = (const struct ndr_interface_table *)dce_call->context->iface->private_data;
	opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (private->credentials) {
		if (cli_credentials_is_anonymous(private->credentials) == false){
			if (!dcesrv_call_authenticated(dce_call)) {
				OC_DEBUG(0, "User is not authenticated, cannot process");
				dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
				return NT_STATUS_NET_WRITE_FAULT;
			}
		}
	}

	/* If remote connection bind/auth has been delayed */
	if (private->connected == false && private->server_mode == false) {
		status = mapiproxy_op_connect(dce_call, table, NULL);

		if (!NT_STATUS_IS_OK(status)) {
			dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
			return NT_STATUS_NET_WRITE_FAULT;
		}
	}

	if (opnum >= table->num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_size(mem_ctx, table->calls[opnum].struct_size);
	if (!*r) {
		return NT_STATUS_NO_MEMORY;
	}

	/* directly alter the pull struct before it got pulled from ndr */
	mapiproxy_module_ndr_pull(dce_call, mem_ctx, pull);

	ndr_err = table->calls[opnum].ndr_pull(pull, NDR_IN, *r);

	mapiproxy_module_pull(dce_call, mem_ctx, *r);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		OC_DEBUG(0, "mapiproxy: mapiproxy_ndr_pull: ERROR");
		dcerpc_log_packet(dce_call->conn->packet_log_dir, table, opnum, NDR_IN, 
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}


/**
   \details This is the function called when mapiproxy receive a
   response. The response has already been extracted and its
   information filled into structures

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param push pointer to the ndr_push structure
   \param r generic pointer to the data pushed

   \return NT_STATUS_OK on success, otherwise a NTSTATUS error
 */
static NTSTATUS mapiproxy_op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	struct dcesrv_mapiproxy_private		*private;
	enum ndr_err_code			ndr_err;
	const struct ndr_interface_table	*table;
	/* const struct ndr_interface_call		*call; */
	uint16_t				opnum;
	/* const char				*name; */

	OC_DEBUG(5, "mapiproxy::mapiproxy_op_ndr_push");

	private = dce_call->context->private_data;
	table = (const struct ndr_interface_table *)dce_call->context->iface->private_data;
	opnum = dce_call->pkt.u.request.opnum;

	/* name = table->calls[opnum].name; */
	/* call = &table->calls[opnum]; */

	dce_call->fault_code = 0;

	if (private->server_mode == false) {
		/* NspiGetProps binding strings replacement */
		if ((mapiproxy_server_loaded(NDR_EXCHANGE_NSP_NAME) == false) &&
		    table->name && !strcmp(table->name, NDR_EXCHANGE_NSP_NAME)) {
			switch (opnum) {
			case NDR_NSPIGETPROPS:
				mapiproxy_NspiGetProps(dce_call, (struct NspiGetProps *)r);
				break;
			case NDR_NSPIQUERYROWS:
				mapiproxy_NspiQueryRows(dce_call, (struct NspiQueryRows *)r);
				break;
			default:
				break;
			}
		}

		/* RfrGetNewDSA FQDN replacement */
		if ((mapiproxy_server_loaded(NDR_EXCHANGE_DS_RFR_NAME) == false) &&
		    table->name && !strcmp(table->name, NDR_EXCHANGE_DS_RFR_NAME)) {
			switch (opnum) {
			case NDR_RFRGETNEWDSA:
				mapiproxy_RfrGetNewDSA(dce_call, (struct RfrGetNewDSA *)r);
				break;
			default:
				OC_DEBUG(0, "exchange_ds_rfr: OTHER DS-RFR CALL DETECTED!");
				break;
			}
		}
	}

	mapiproxy_module_push(dce_call, mem_ctx, (void *)r);

	ndr_err = table->calls[opnum].ndr_push(push, NDR_OUT, r);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		OC_DEBUG(0, "mapiproxy: mapiproxy_ndr_push: ERROR");
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

struct dcerpc_binding_handle_async_call_state {
	struct dcesrv_call_state *dce_call;
};

static void dcerpc_binding_handle_async_call_done(struct tevent_req *subreq)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
	struct dcerpc_binding_handle_async_call_state *state = tevent_req_data(req, struct dcerpc_binding_handle_async_call_state);

	status = dcesrv_reply(state->dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		OC_DEBUG(0, "dcerpc_binding_handle_async_call_done: dcesrv_reply() failed - %s", nt_errstr(status));
	}
}

struct dcerpc_binding_handle {
	void *private_data;
	const struct dcerpc_binding_handle_ops *ops;
	const char *location;
	const struct GUID *object;
	const struct ndr_interface_table *table;
	struct tevent_context *sync_ev;
};

NTSTATUS dcerpc_binding_handle_async_call(struct dcesrv_call_state *dce_call,
										  struct dcerpc_binding_handle *h,
				    				      const struct GUID *object,
										  const struct ndr_interface_table *table,
										  uint32_t opnum,
										  TALLOC_CTX *r_mem,
										  void *r_ptr)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	struct tevent_context *ev;
	struct tevent_req *req;
	struct tevent_req *subreq;
	struct dcerpc_binding_handle_async_call_state *state;

	if (h->sync_ev) {
		ev = h->sync_ev;
	} else {
		ev = samba_tevent_context_init(r_mem);
	}
	if (ev == NULL) {
		goto fail;
	}

	req = tevent_req_create(r_mem, &state, struct dcerpc_binding_handle_async_call_state);
	if (req == NULL) {
		goto fail;
	}

	state->dce_call = dce_call;

	// Async calls can take up to 5 minutes, give 10 for a timeout - 600 seconds
	dcerpc_binding_handle_set_timeout(h, 600);
	subreq = dcerpc_binding_handle_call_send(r_mem, ev, h, object, table, opnum, r_mem, r_ptr);
	if (subreq == NULL) {
		goto fail;
	}

	tevent_req_set_callback(subreq, dcerpc_binding_handle_async_call_done, req);

	/* Signal that the async response will come later */
	dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	status = NT_STATUS_OK;

fail:
	return status;
}

/**
   \details This function is called after the pull but before the
   push. Moreover it is called before the request is forward to the
   remote endpoint.

   \param dce_call pointer to the session context
   \param mem_ctx pointer to the memory context
   \param r generic pointer to the call mapped data

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
static NTSTATUS mapiproxy_op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	struct dcesrv_mapiproxy_private		*private;
	struct ndr_push				*push;
	enum ndr_err_code			ndr_err;
	struct mapiproxy			mapiproxy;
	const struct ndr_interface_table	*table;
	const struct ndr_interface_call		*call;
	uint16_t				opnum;
	const char				*name;
	NTSTATUS				status;
	int					this_dispatch;
	struct timeval				tv;

	this_dispatch = dispatch_nbr;
	dispatch_nbr++;

	gettimeofday(&tv, NULL);
	OC_DEBUG(5, "mapiproxy::mapiproxy_op_dispatch: [tv=%lu.%.6lu] [#%d start]", tv.tv_sec, tv.tv_usec, this_dispatch);

	private = dce_call->context->private_data;
	table = dce_call->context->iface->private_data;
	opnum = dce_call->pkt.u.request.opnum;

	name = table->calls[opnum].name;
	call = &table->calls[opnum];

	mapiproxy.norelay = false;
	mapiproxy.ahead = false;

	if (!private) {
		dce_call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	OC_DEBUG(5, "mapiproxy::mapiproxy_op_dispatch: %s(0x%x): %zd bytes",
		  table->calls[opnum].name, opnum, table->calls[opnum].struct_size);

	if (private->server_mode == false) {
		if ((private->ndrdump == true) && (private->c_pipe->conn->flags & DCERPC_DEBUG_PRINT_IN)) {
			ndr_print_function_debug(call->ndr_print, name, NDR_IN | NDR_SET_VALUES, r);
		}

		private->c_pipe->conn->flags |= DCERPC_NDR_REF_ALLOC;
	}

	if ((private->server_mode == true) || (mapiproxy_server_loaded(NDR_EXCHANGE_NSP_NAME) == true)) {
		if (private->ndrdump == true) {
			ndr_print_function_debug(call->ndr_print, name, NDR_IN | NDR_SET_VALUES, r);
		}
		status = mapiproxy_server_dispatch(dce_call, mem_ctx, r, &mapiproxy);
		if (private->ndrdump == true) {
			ndr_print_function_debug(call->ndr_print, name, NDR_OUT | NDR_SET_VALUES, r);
		}
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_NET_WRITE_FAULT;
		}
	} else {
		if (table->name && !strcmp(table->name, NDR_EXCHANGE_NSP_NAME)) {
			if (opnum == NDR_NSPIDNTOMID) {
				mapiproxy_NspiDNToMId(dce_call, (struct NspiDNToMId *)r);
			}
		}
	}

	if (private->server_mode == false) {
	ahead:
		if (mapiproxy.ahead == true) {
			push = ndr_push_init_ctx(dce_call);
			NT_STATUS_HAVE_NO_MEMORY(push);
			ndr_err = call->ndr_push(push, NDR_OUT, r);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				OC_DEBUG(0, "mapiproxy: mapiproxy_op_dispatch:push: ERROR");
				dce_call->fault_code = DCERPC_FAULT_NDR;
				return NT_STATUS_NET_WRITE_FAULT;
			}
		}
		
		status = mapiproxy_module_dispatch(dce_call, mem_ctx, r, &mapiproxy);
		if (!NT_STATUS_IS_OK(status)) {
			private->c_pipe->last_fault_code = dce_call->fault_code;
			return NT_STATUS_NET_WRITE_FAULT;
		}
		
		private->c_pipe->last_fault_code = 0;
		if (mapiproxy.norelay == false) {
			
			if (table->name && !strcmp(table->name, NDR_EXCHANGE_ASYNCEMSMDB_NAME)) {
				/* Proxy to the server in an async fashion */
				status = dcerpc_binding_handle_async_call(dce_call, private->c_pipe->binding_handle, NULL, table, opnum, mem_ctx, r);
			}
			else {
				status = dcerpc_binding_handle_call(private->c_pipe->binding_handle, NULL, table, opnum, mem_ctx, r);
			}
		}
		
		dce_call->fault_code = private->c_pipe->last_fault_code;
		if (dce_call->fault_code != 0 || !NT_STATUS_IS_OK(status)) {
			OC_DEBUG(0, "mapiproxy: call[%s] failed with %s! (status = %s)", name, 
				  dcerpc_errstr(mem_ctx, dce_call->fault_code), nt_errstr(status));
			return NT_STATUS_NET_WRITE_FAULT;
		}
		
		if ((dce_call->fault_code == 0) && 
		    (private->c_pipe->conn->flags & DCERPC_DEBUG_PRINT_OUT) && mapiproxy.norelay == false) {
			if (private->ndrdump == true) {
				ndr_print_function_debug(call->ndr_print, name, NDR_OUT | NDR_SET_VALUES, r);
			}
		}
		
		if (mapiproxy.ahead == true) goto ahead;
	}

	gettimeofday(&tv, NULL);
	OC_DEBUG(5, "mapiproxy::mapiproxy_op_dispatch: [tv=%lu.%.6lu] [#%d end]",
			 tv.tv_sec, tv.tv_usec, this_dispatch);
	
	return NT_STATUS_OK;
}


/**
   \details Register an endpoint

   \param dce_ctx pointer to the dcerpc context
   \param iface pointer to the dcesrv interface with function hooks

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
static NTSTATUS mapiproxy_register_one_iface(struct dcesrv_context *dce_ctx, const struct dcesrv_interface *iface)
{
	const struct ndr_interface_table	*table = iface->private_data;
	int					i;

	for (i = 0; i < table->endpoints->count; i++) {
		NTSTATUS	ret;
		const char	*name = table->endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, iface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			OC_DEBUG(1, "mapiproxy_op_init_server: failed to register endpoint '%s'", name);
			return ret;
		}
	}

	return NT_STATUS_OK;
}


/**
   \details Initializes the server and register emsmdb,nspi and rfr
   interfaces

   \param dce_ctx pointer to the dcesrv context
   \param ep_server pointer to the endpoint server list

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
static NTSTATUS mapiproxy_op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	NTSTATUS		ret;
	struct dcesrv_interface	iface;
	const char     		**ifaces;
	uint32_t		i;
	static bool		initialized = false;

	if (initialized == true) return NT_STATUS_OK;

	/* Register mapiproxy modules */
	ret = mapiproxy_module_init(dce_ctx);
	NT_STATUS_NOT_OK_RETURN(ret);

	/* Register mapiproxy servers */
	ret = mapiproxy_server_init(dce_ctx);
	NT_STATUS_NOT_OK_RETURN(ret);

	ifaces = lpcfg_parm_string_list(dce_ctx, dce_ctx->lp_ctx, NULL, "dcerpc_mapiproxy", "interfaces", NULL);

	if (ifaces == NULL) {
		ifaces = discard_const_p(const char *, str_list_make(dce_ctx, DEFAULT_INTERFACES, NULL));
	}

	for (i = 0; ifaces[i]; i++) {
		/* Register the interface */
		if (!ep_server->interface_by_name(&iface, ifaces[i])) {
			OC_DEBUG(0, "mapiproxy_op_init_server: failed to find interface '%s'", ifaces[i]);
			return NT_STATUS_UNSUCCESSFUL;
		}

		ret = mapiproxy_register_one_iface(dce_ctx, &iface);
		if (!NT_STATUS_IS_OK(ret)) {
			OC_DEBUG(0, "mapiproxy_op_init_server: failed to register interface '%s'", ifaces[i]);
			return ret;
		}
	}

	initialized = true;
	return NT_STATUS_OK;
}


static bool mapiproxy_fill_interface(struct dcesrv_interface *iface, const struct ndr_interface_table *tbl)
{
	iface->name = tbl->name;
	iface->syntax_id = tbl->syntax_id;
	
	iface->bind = mapiproxy_op_bind;
	iface->unbind = mapiproxy_op_unbind;
	
	iface->ndr_pull = mapiproxy_op_ndr_pull;
	iface->dispatch = mapiproxy_op_dispatch;
	iface->reply = mapiproxy_op_reply;
	iface->ndr_push = mapiproxy_op_ndr_push;

	iface->private_data = tbl;

	return true;
}


static bool mapiproxy_op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	const struct ndr_interface_list	*l;

	for (l = ndr_table_list(); l; l = l->next) {
		if (l->table->syntax_id.if_version == if_version &&
		    GUID_equal(&l->table->syntax_id.uuid, uuid) == 0) {
			return mapiproxy_fill_interface(iface, l->table);
		}
	}

	return false;
}


static bool mapiproxy_op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	const struct ndr_interface_table	*tbl;

	tbl = ndr_table_by_name(name);

	if (tbl) {
		return mapiproxy_fill_interface(iface, tbl);
	}

	return false;
}


/**
   \details register the mapiproxy endpoint server.

   \return NT_STATUS_OK on success, otherwise NTSTATUS error
 */
NTSTATUS dcerpc_server_mapiproxy_init(void)
{
	NTSTATUS			ret;
	struct dcesrv_endpoint_server	ep_server;

	ZERO_STRUCT(ep_server);

	/* Fill in our name */
	ep_server.name = "mapiproxy";

	/* Fill in all the operations */
	ep_server.init_server = mapiproxy_op_init_server;

	ep_server.interface_by_uuid = mapiproxy_op_interface_by_uuid;
	ep_server.interface_by_name = mapiproxy_op_interface_by_name;

	/* Register ourselves with the DCE/RPC subsystem */
	ret = dcerpc_register_ep_server(&ep_server);
	if (!NT_STATUS_IS_OK(ret)) {
		OC_DEBUG(0, "Failed to register 'mapiproxy' endpoint server!");
		return ret;
	}

	/* Full DCE/RPC interface table needed */
	ndr_table_init();
	
	return ret;
}

/**
   \details override defaults in loadparm to enable mapiproxy by default.

   \return true on success, otherwise false
  */
static bool dcesrv_mapiproxy_lp_defaults(struct loadparm_context *lp_ctx)
{
	lpcfg_do_global_parameter(lp_ctx, "dcerpc endpoint servers",  "+mapiproxy");

	return true;
}

/**
   \details Register mapiproxy dynamic shared object modules

   This function registers mapiproxy modules located
 */

/**
   \details Entry point of mapiproxy dynamic shared object.

   This function first registers exchange endpoints and ndr tables,
   then attempts to register the mapiproxy interface.

   \return NT_STATUS_OK on success, otherwise NT_STATUS_UNSUCCESSFUL;
 */
NTSTATUS samba_init_module(void)
{
	NTSTATUS status;

	/* Step1. Register Exchange endpoints */
	status = dcerpc_server_exchange_emsmdb_init();
	NT_STATUS_NOT_OK_RETURN(status);

	status = dcerpc_server_exchange_nsp_init();
	NT_STATUS_NOT_OK_RETURN(status);

	status = dcerpc_server_exchange_ds_rfr_init();
	NT_STATUS_NOT_OK_RETURN(status);
	
	status = dcerpc_server_exchange_asyncemsmdb_init();
	NT_STATUS_NOT_OK_RETURN(status);

	/* Step2. Register Exchange ndr tables */
	status = ndr_table_register(&ndr_table_exchange_emsmdb);
	NT_STATUS_NOT_OK_RETURN(status);

	status = ndr_table_register(&ndr_table_exchange_nsp);
	NT_STATUS_NOT_OK_RETURN(status);

	status = ndr_table_register(&ndr_table_exchange_ds_rfr);
	NT_STATUS_NOT_OK_RETURN(status);

	status = ndr_table_register(&ndr_table_exchange_asyncemsmdb);
	NT_STATUS_NOT_OK_RETURN(status);
	
	/* Step3. Finally register mapiproxy endpoint */
	status = dcerpc_server_mapiproxy_init();
	NT_STATUS_NOT_OK_RETURN(status);

	/* Configuration hooks are only supported in Samba >= 4.3 */
#if SAMBA_VERSION_MAJOR >= 4 && SAMBA_VERSION_MINOR >= 3
	/* Step4. Register configuration default hook */
	if (!lpcfg_register_defaults_hook("dcesrv_mapiproxy", dcesrv_mapiproxy_lp_defaults)) {
		return NT_STATUS_UNSUCCESSFUL;
	}
#endif

	OC_DEBUG(0, "MAPIProxy Server initialized with aysnc support");

	return NT_STATUS_OK;
}

/* include server boiler template */
#include "gen_ndr/ndr_exchange_s.c"
