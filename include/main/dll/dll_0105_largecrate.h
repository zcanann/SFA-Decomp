#ifndef MAIN_DLL_DLL_0105_LARGECRATE_H_
#define MAIN_DLL_DLL_0105_LARGECRATE_H_

#include "main/game_object.h"
#include "ghidra_import.h"

/* largecrate (DLL 0x105) tuning constants and entry points. */

#define LARGECRATE_TIMER_SCALE_FRAMES      0x3C
#define LARGECRATE_TIMER_SENTINEL_DISABLED 0
#define LARGECRATE_TIMER_SENTINEL_FOREVER  0xFF
#define LARGECRATE_RESOURCE_ID             0x5B
#define LARGECRATE_RESOURCE_MODE           1
#define LARGECRATE_RANDOM_DELAY_MIN        0
#define LARGECRATE_RANDOM_DELAY_MAX        100
#define LARGECRATE_RANDOM_DELAY_BASE       300
#define LARGECRATE_DEFAULT_COUNTDOWN       0x190
#define LARGECRATE_OBJECT_FLAGS            0x2000
#define LARGECRATE_RANDOM_BOB_MAX          200

/* Object ids spawned as drop contents, dispatched on LargeCrateState.dropType. */
#define LARGECRATE_DROP_FRUIT_A 0x3D3 /* dropType 1 */
#define LARGECRATE_DROP_FRUIT_B 0x3D4 /* dropType 2 */
#define LARGECRATE_DROP_FRUIT_C 0x3D5 /* dropType 3 */
#define LARGECRATE_DROP_GAS     0xB   /* dropType 5 (collectible, DLL 0x00ED) */
#define LARGECRATE_DROP_GAS_ALT 0x3CD /* dropType 6 */
#define LARGECRATE_DROP_PICKUP  0x259 /* dropType 9 */

#define LARGECRATE_VARIANT_A       0x3DE
#define LARGECRATE_VARIANT_B       0x49F
#define LARGECRATE_VARIANT_C       0x7BE
#define LARGECRATE_VARIANT_A_SFX_A 0x5F
#define LARGECRATE_VARIANT_A_SFX_B 0x60
#define LARGECRATE_VARIANT_B_SFX_A 0x48
#define LARGECRATE_VARIANT_B_SFX_B 0x4A

int largecrate_spawnDropContents(GameObject* obj, int player, int state);
int LargeCrate_SeqFn(int* obj);
int largecrate_getExtraSize(void);
int largecrate_getObjectTypeId(void);
void largecrate_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderState);
void largecrate_hitDetect(int obj);
void largecrate_init(GameObject* obj, u8* initData);
void largecrate_release(void);
void largecrate_initialise(void);

/* extern-cleanup: defining-file public prototypes */
f32 largecrate_getReticleDistance(GameObject* obj);

#endif /* MAIN_DLL_DLL_0105_LARGECRATE_H_ */
