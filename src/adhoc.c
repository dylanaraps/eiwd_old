/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/nl80211util.h"

struct adhoc_state {
	struct netdev *netdev;
	struct l_genl_family *nl80211;
	char *ssid;
	uint8_t pmk[32];
	struct l_queue *sta_states;
	uint32_t sta_watch_id;
	uint32_t netdev_watch_id;
	uint32_t ciphers;
	uint32_t group_cipher;
	uint8_t gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t gtk_index;
	bool started : 1;
	bool open : 1;
	bool gtk_set : 1;
};

struct sta_state {
	uint8_t addr[6];
	struct adhoc_state *adhoc;
	struct eapol_sm *sm;
	struct handshake_state *hs_sta;
	struct eapol_sm *sm_a;
	struct handshake_state *hs_auth;
	uint32_t gtk_query_cmd_id;
	bool hs_sta_done : 1;
	bool hs_auth_done : 1;
	bool authenticated : 1;
};

static uint32_t netdev_watch;

static void adhoc_sta_free(void *data)
{
	struct sta_state *sta = data;

	if (sta->adhoc->open)
		goto end;

	if (sta->gtk_query_cmd_id)
		l_genl_family_cancel(sta->adhoc->nl80211,
						sta->gtk_query_cmd_id);

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs_sta)
		handshake_state_free(sta->hs_sta);

	if (sta->sm_a)
		eapol_sm_free(sta->sm_a);

	if (sta->hs_auth)
		handshake_state_free(sta->hs_auth);

end:
	l_free(sta);
}

static void adhoc_add_interface(struct netdev *netdev)
{
	struct adhoc_state *adhoc;

	/* just allocate/set device, Start method will complete setup */
	adhoc = l_new(struct adhoc_state, 1);
	adhoc->netdev = netdev;
	adhoc->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
}

static void adhoc_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_ADHOC &&
				netdev_get_is_up(netdev))
			adhoc_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		break;
	default:
		break;
	}
}

static int adhoc_init(void)
{
	netdev_watch = netdev_watch_add(adhoc_netdev_watch, NULL, NULL);

	return 0;
}

static void adhoc_exit(void)
{
	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(adhoc, adhoc_init, adhoc_exit)
