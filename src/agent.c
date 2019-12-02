/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <ell/ell.h>
#include "src/dbus.h"
#include "src/agent.h"
#include "src/iwd.h"
#include "src/module.h"

static unsigned int next_request_id = 0;

enum agent_request_type {
	AGENT_REQUEST_TYPE_PASSPHRASE,
	AGENT_REQUEST_TYPE_USER_NAME_PASSWD,
};

/* Agent dbus request is done from iwd towards the agent */
struct agent_request {
	enum agent_request_type type;
	struct l_dbus_message *message;
	unsigned int id;
	void *user_data;
	void *user_callback;
	struct l_dbus_message *trigger;
	agent_request_destroy_func_t destroy;
};

struct agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
	uint32_t pending_id;
	struct l_timeout *timeout;
	int timeout_secs;
	struct l_queue *requests;
};

static struct l_queue *agents;

/*
 * How long we wait for user to input things.
 * Return value is in seconds.
 *
 * This should probably be configurable by user via
 * config file/command line option/env variable.
 */
static unsigned int agent_timeout_input_request(void)
{
	return 120;
}

static void send_request(struct agent *agent, const char *request)
{
	l_debug("send %s request to %s %s", request, agent->owner,
							agent->path);
}

static void send_cancel_request(void *user_data, int reason)
{
	struct agent *agent = user_data;
	const char *reasonstr;

	switch (reason) {
	case -ECANCELED:
		reasonstr = "user-canceled";
		break;
	case -ETIMEDOUT:
		reasonstr = "timed-out";
		break;
	case -ERANGE:
		reasonstr = "out-of-range";
		break;
	case -ESHUTDOWN:
		reasonstr = "shutdown";
		break;
	default:
		reasonstr = "unknown";
	}

	l_debug("send a Cancel(%s) to %s %s", reasonstr,
			agent->owner, agent->path);
}

static void agent_request_free(void *user_data)
{
	struct agent_request *request = user_data;

	if (request->destroy)
		request->destroy(request->user_data);

	l_free(request);
}

static void agent_finalize_pending(struct agent *agent,
						struct l_dbus_message *reply)
{
	struct agent_request *pending;

	if (agent->timeout) {
		l_timeout_remove(agent->timeout);
		agent->timeout = NULL;
	}

	pending = l_queue_pop_head(agent->requests);

	switch (pending->type) {
	case AGENT_REQUEST_TYPE_PASSPHRASE:
		break;
	case AGENT_REQUEST_TYPE_USER_NAME_PASSWD:
		break;
	}

	if (pending->trigger) {
		pending->trigger = NULL;
	}

	agent_request_free(pending);
}

static void agent_free(void *data)
{
	struct agent *agent = data;

	l_debug("agent free %p", agent);

	if (agent->timeout)
		l_timeout_remove(agent->timeout);

	l_queue_destroy(agent->requests, agent_request_free);

	l_free(agent->owner);
	l_free(agent->path);
	l_free(agent);
}

static void agent_send_next_request(struct agent *agent);

static void request_timeout(struct l_timeout *timeout, void *user_data)
{
	struct agent *agent = user_data;

	send_cancel_request(agent, -ETIMEDOUT);

	agent_finalize_pending(agent, NULL);

	agent_send_next_request(agent);
}

static void agent_receive_reply(struct l_dbus_message *message,
							void *user_data)
{
	struct agent *agent = user_data;

	l_debug("agent %p request id %u", agent, agent->pending_id);

	agent->pending_id = 0;

	agent_finalize_pending(agent, NULL);

	if (!agent->pending_id)
		agent_send_next_request(agent);
}

static void agent_send_next_request(struct agent *agent)
{
	struct agent_request *pending;

	pending = l_queue_peek_head(agent->requests);
	if (!pending)
		return;

	agent->timeout = l_timeout_create(agent->timeout_secs,
						request_timeout,
						agent, NULL);

	l_debug("send request to %s %s", agent->owner, agent->path);

	agent->pending_id = l_dbus_send_with_reply(dbus_get_bus(),
							pending->message,
							agent_receive_reply,
							agent, NULL);

	pending->message = NULL;

	return;
}

static struct agent *agent_lookup(const char *owner)
{
	const struct l_queue_entry *entry;

	if (!owner)
		return NULL;

	for (entry = l_queue_get_entries(agents); entry; entry = entry->next) {
		struct agent *agent = entry->data;

		if (strcmp(agent->owner, owner))
			continue;

		return agent;
	}

	return NULL;
}

static struct agent *get_agent(const char *owner)
{
	struct agent *agent = agent_lookup(owner);

	if (agent)
		return agent;

	return l_queue_peek_head(agents);
}

static bool find_request(const void *a, const void *b)
{
	const struct agent_request *request = a;
	unsigned int id = L_PTR_TO_UINT(b);

	return request->id == id;
}

bool agent_request_cancel(unsigned int req_id, int reason)
{
	struct agent_request *request = NULL;
	struct agent *agent;
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(agents); entry; entry = entry->next) {
		agent = entry->data;

		request = l_queue_remove_if(agent->requests, find_request,
							L_UINT_TO_PTR(req_id));
		if (request)
			break;
	}

	if (!request)
		return false;

	if (!request->message) {
		send_cancel_request(agent, reason);

		agent->pending_id = 0;

		if (agent->timeout) {
			l_timeout_remove(agent->timeout);
			agent->timeout = NULL;
		}

		agent_send_next_request(agent);
	}

	agent_request_free(request);

	return true;
}

static bool release_agent(void *data, void *user_data)
{
	struct agent *agent = data;

	send_request(agent, "Release");

	agent_free(agent);

	return true;
}

static int agent_init(void)
{
	agents = l_queue_new();

	return 0;
}

static void agent_exit(void)
{
	l_queue_destroy(agents, agent_free);
	agents = NULL;
}

void agent_shutdown(void)
{
	l_queue_foreach_remove(agents, release_agent, NULL);
}

IWD_MODULE(agent, agent_init, agent_exit);
