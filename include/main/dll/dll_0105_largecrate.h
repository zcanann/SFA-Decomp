#ifndef MAIN_DLL_DLL_0105_LARGECRATE_H_
#define MAIN_DLL_DLL_0105_LARGECRATE_H_

#include "ghidra_import.h"

/* largecrate (DLL 0x105) tuning constants and entry points. */

#define LARGECRATE_TIMER_SCALE_FRAMES 0x3C
#define LARGECRATE_TIMER_SENTINEL_DISABLED 0
#define LARGECRATE_TIMER_SENTINEL_FOREVER 0xFF
#define LARGECRATE_RESOURCE_ID 0x5B
#define LARGECRATE_RESOURCE_MODE 1
#define LARGECRATE_RANDOM_DELAY_MIN 0
#define LARGECRATE_RANDOM_DELAY_MAX 100
#define LARGECRATE_RANDOM_DELAY_BASE 300
#define LARGECRATE_DEFAULT_COUNTDOWN 0x190
#define LARGECRATE_OBJECT_FLAGS 0x2000
#define LARGECRATE_RANDOM_BOB_MAX 200

#define LARGECRATE_VARIANT_A 0x3DE
#define LARGECRATE_VARIANT_B 0x49F
#define LARGECRATE_VARIANT_C 0x7BE
#define LARGECRATE_VARIANT_A_SFX_A 0x5F
#define LARGECRATE_VARIANT_A_SFX_B 0x60
#define LARGECRATE_VARIANT_B_SFX_A 0x48
#define LARGECRATE_VARIANT_B_SFX_B 0x4A

int largecrate_spawnDropContents(int obj, int player, int state);
int LargeCrate_SeqFn(int *obj);
int largecrate_getExtraSize(void);
int largecrate_getObjectTypeId(void);
void largecrate_render(int obj, int p2, int p3, int p4, int p5, s8 renderState);
void largecrate_hitDetect(int obj);
void largecrate_init(int obj, u8 *initData);
void largecrate_release(void);
void largecrate_initialise(void);

#endif /* MAIN_DLL_DLL_0105_LARGECRATE_H_ */
