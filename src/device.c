/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/module.h"
#include "src/util.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/station.h"

struct device {
	uint32_t index;

	struct wiphy *wiphy;
	struct netdev *netdev;

	bool powered : 1;		/* Current IFUP state */

	uint32_t ap_roam_watch;
	uint32_t wiphy_rfkill_watch;
};

static uint32_t netdev_watch;

static void device_ap_roam_frame_event(struct netdev *netdev,
		const struct mmpdu_header *hdr,
		const void *body, size_t body_len,
		void *user_data)
{
	struct device *device = user_data;
	struct station *station = station_find(device->index);

	if (!station)
		return;

	station_ap_directed_roam(station, hdr, body, body_len);
}

static void device_wiphy_state_changed_event(struct wiphy *wiphy,
					enum wiphy_state_watch_event event,
					void *user_data)
{
	switch (event) {
	case WIPHY_STATE_WATCH_EVENT_RFKILLED:
		break;
	case WIPHY_STATE_WATCH_EVENT_POWERED:
		break;
	}
}

static struct device *device_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct device *device;
	uint32_t ifindex = netdev_get_ifindex(netdev);
	const uint8_t action_ap_roam_prefix[2] = { 0x0a, 0x07 };

	device = l_new(struct device, 1);
	device->index = ifindex;
	device->wiphy = wiphy;
	device->netdev = netdev;

	scan_wdev_add(netdev_get_wdev_id(device->netdev));

	/*
	 * register for AP roam transition watch
	 */
	device->ap_roam_watch = netdev_frame_watch_add(netdev, 0x00d0,
			action_ap_roam_prefix, sizeof(action_ap_roam_prefix),
			device_ap_roam_frame_event, device);

	device->powered = netdev_get_is_up(netdev);

	device->wiphy_rfkill_watch =
		wiphy_state_watch_add(wiphy, device_wiphy_state_changed_event,
					device, NULL);

	return device;
}

static void device_free(struct device *device)
{
	l_debug("");

	scan_wdev_remove(netdev_get_wdev_id(device->netdev));

	netdev_frame_watch_remove(device->netdev, device->ap_roam_watch);
	wiphy_state_watch_remove(device->wiphy, device->wiphy_rfkill_watch);

	l_free(device);
}

static void device_netdev_notify(struct netdev *netdev,
					enum netdev_watch_event event,
					void *user_data)
{
	struct device *device;

    /* TODO: FIX */
    device = NULL;

	if (!device && event != NETDEV_WATCH_EVENT_NEW)
		return;

	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
		if (L_WARN_ON(device))
			break;

		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_P2P_CLIENT ||
				netdev_get_iftype(netdev) ==
				NETDEV_IFTYPE_P2P_GO)
			return;

		device_create(netdev_get_wiphy(netdev), netdev);
		break;
	case NETDEV_WATCH_EVENT_DEL:
		break;
	case NETDEV_WATCH_EVENT_UP:
		device->powered = true;

		break;
	case NETDEV_WATCH_EVENT_DOWN:
		device->powered = false;

		break;
	case NETDEV_WATCH_EVENT_NAME_CHANGE:
		break;
	case NETDEV_WATCH_EVENT_ADDRESS_CHANGE:
		break;
	default:
		break;
	}
}

static int device_init(void)
{
	netdev_watch = netdev_watch_add(device_netdev_notify, NULL, NULL);

	return 0;
}

static void device_exit(void)
{
	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(device, device_init, device_exit)
