#ifndef _DOLPHIN_OSRESETSW_H_
#define _DOLPHIN_OSRESETSW_H_

#ifdef __REVOLUTION_SDK__
#include <revolution/os/OSResetSW.h>
#else
#include <dolphin/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*OSResetCallback)(void);

BOOL OSGetResetButtonState(void);

#ifdef __cplusplus
}
#endif

#endif
#endif
