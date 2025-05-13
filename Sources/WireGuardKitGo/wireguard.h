/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

// __BEGIN_CYLONIX_MOD__
typedef void(*adapter_fn_t)(void *context, const char *method, const char *args, char *resp_buf, int resp_buf_len);
extern void wgSetAdapter(const char *group_dir, void *context, adapter_fn_t adapter_fn);
extern char *wgSendCommand(const char *cmd, const char *args);
// __END_CYLONIX_MOD__
#endif
