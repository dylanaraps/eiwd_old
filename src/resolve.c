/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/module.h"
#include "src/resolve.h"

struct resolve_method_ops {
	void *(*init)(void);
	void (*exit)(void *data);
	void (*add_dns)(uint32_t ifindex, uint8_t type, char **dns_list,
								void *data);
	void (*remove)(uint32_t ifindex, void *data);
};

struct resolve_method {
	void *data;
	const struct resolve_method_ops *ops;
};

static struct resolve_method method;
static char *resolvconf_path;

static void resolve_resolvconf_add_dns(uint32_t ifindex, uint8_t type,
						char **dns_list, void *data)
{
	bool *ready = data;
	FILE *resolvconf;
	struct l_string *content;
	int error;
	L_AUTO_FREE_VAR(char *, cmd) = NULL;
	L_AUTO_FREE_VAR(char *, str) = NULL;

	if (!*ready)
		return;

	cmd = l_strdup_printf("%s -a %u", resolvconf_path, ifindex);

	if (!(resolvconf = popen(cmd, "w"))) {
		l_error("resolve: Failed to start %s (%s).", resolvconf_path,
							strerror(errno));
		return;
	}

	content = l_string_new(0);

	for (; *dns_list; dns_list++)
		l_string_append_printf(content, "nameserver %s\n", *dns_list);

	str = l_string_unwrap(content);

	if (fprintf(resolvconf, "%s", str) < 0)
		l_error("resolve: Failed to print into %s stdin.",
							resolvconf_path);

	error = pclose(resolvconf);
	if (error < 0)
		l_error("resolve: Failed to close pipe to %s (%s).",
					resolvconf_path, strerror(errno));
	else if (error > 0)
		l_info("resolve: %s exited with status (%d).", resolvconf_path,
									error);
}

static void resolve_resolvconf_remove(uint32_t ifindex, void *data)
{
	bool *ready = data;
	FILE *resolvconf;
	int error;
	L_AUTO_FREE_VAR(char *, cmd) = NULL;

	if (!*ready)
		return;

	cmd = l_strdup_printf("%s -d %u", resolvconf_path, ifindex);

	if (!(resolvconf = popen(cmd, "r"))) {
		l_error("resolve: Failed to start %s (%s).", resolvconf_path,
							strerror(errno));
		return;
	}

	error = pclose(resolvconf);
	if (error < 0)
		l_error("resolve: Failed to close pipe to %s (%s).",
					resolvconf_path, strerror(errno));
	else if (error > 0)
		l_info("resolve: %s exited with status (%d).", resolvconf_path,
									error);
}

static void *resolve_resolvconf_init(void)
{
	static const char *default_path = "/sbin:/usr/sbin";
	bool *ready;
	const char *path;

	ready = l_new(bool, 1);
	*ready = false;

	l_debug("Trying to find resolvconf in $PATH");
	path = getenv("PATH");
	if (path)
		resolvconf_path = l_path_find("resolvconf", path, X_OK);

	if (!resolvconf_path) {
		l_debug("Trying to find resolvconf in default paths");
		resolvconf_path = l_path_find("resolvconf", default_path, X_OK);
	}

	if (!resolvconf_path) {
		l_error("No usable resolvconf found on system");
		return ready;
	}

	l_debug("resolvconf found as: %s", resolvconf_path);
	*ready = true;
	return ready;
}

static void resolve_resolvconf_exit(void *data)
{
	bool *ready = data;

	l_free(resolvconf_path);
	resolvconf_path = NULL;
	l_free(ready);
}

static const struct resolve_method_ops resolve_method_resolvconf = {
	.init = resolve_resolvconf_init,
	.exit = resolve_resolvconf_exit,
	.add_dns = resolve_resolvconf_add_dns,
	.remove = resolve_resolvconf_remove,
};

void resolve_add_dns(uint32_t ifindex, uint8_t type, char **dns_list)
{
	if (!dns_list || !*dns_list)
		return;

	if (!method.ops || !method.ops->add_domain_name)
		return;

	method.ops->add_dns(ifindex, type, dns_list, method.data);
}

void resolve_remove(uint32_t ifindex)
{
	if (!method.ops || !method.ops->remove)
		return;

	method.ops->remove(ifindex, method.data);
}

static const struct {
	const char *name;
	const struct resolve_method_ops *method_ops;
} resolve_method_ops_list[] = {
	{ "resolvconf", &resolve_method_resolvconf },
	{ }
};

static int resolve_init(void)
{
	const char *method_name;
	bool enabled;
	uint8_t i;

	if (!l_settings_get_bool(iwd_get_config(), "General",
					"EnableNetworkConfiguration",
					&enabled)) {
		if (!l_settings_get_bool(iwd_get_config(), "General",
					"enable_network_config", &enabled))
			enabled = false;
	}

	if (!enabled)
		return 0;

	method_name = l_settings_get_value(iwd_get_config(), "Network",
						"NameResolvingService");
	if (!method_name) {
		method_name = l_settings_get_value(iwd_get_config(), "General",
							"dns_resolve_method");
		if (method_name)
			l_warn("[General].dns_resolve_method is deprecated, "
				"use [Network].NameResolvingService");
		else /* Default to resolvconf. */
			method_name = "resolvconf";
	}

	for (i = 0; resolve_method_ops_list[i].name; i++) {
		if (strcmp(resolve_method_ops_list[i].name, method_name))
			continue;

		method.ops = resolve_method_ops_list[i].method_ops;

		break;
	}

	if (!method.ops) {
		l_error("Unknown resolution method: %s", method_name);
		return -EINVAL;
	}

	if (method.ops->init)
		method.data = method.ops->init();

	return 0;
}

static void resolve_exit(void)
{
	if (!method.ops || !method.ops->exit)
		return;

	method.ops->exit(method.data);
}

IWD_MODULE(resolve, resolve_init, resolve_exit)
