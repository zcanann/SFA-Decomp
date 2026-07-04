#ifndef MAIN_DLL_BACKPACK_H_
#define MAIN_DLL_BACKPACK_H_

#include "ghidra_import.h"

#define TUMBLEWEED_TYPE_1 0x39d
#define TUMBLEWEED_TYPE_3 0x4ba
#define TUMBLEWEED_TYPE_4 0x4c1

#define TUMBLEWEED_EFFECT_BURST_SPECIAL 0x34d
#define TUMBLEWEED_EFFECT_BURST_DEFAULT 0x32e
#define TUMBLEWEED_EFFECT_PUFF_SPECIAL 0x34c
#define TUMBLEWEED_EFFECT_PUFF_DEFAULT 0x32d
#define TUMBLEWEED_EFFECT_SPAWN_COUNT 0x14
#define TUMBLEWEED_PARTFX_MODE_ACTIVE 2
#define TUMBLEWEED_SFX_BURST 0x27d
#define TUMBLEWEED_SFX_HIT_LOOP 0x451
#define TUMBLEWEED_HIT_PULSE_VOLUME_SLOT 0x1f
#define TUMBLEWEED_HIT_PULSE_PERIOD 6
#define TUMBLEWEED_HIT_PULSE_ALT_STYLE 3

#define TUMBLEWEED_EFFECT_FLAG_BURST 0x01
#define TUMBLEWEED_EFFECT_FLAG_PUFF 0x02
#define TUMBLEWEED_EFFECT_FLAG_DESPAWN 0x04
#define TUMBLEWEED_EFFECT_FLAG_HIT_PULSE 0x10

/* phase/mode state machine (BackpackState.phase == TumbleweedState.mode, off 0x278).
 * States 3, 4 and 7 remain numeric: their meaning is not self-evident. */
#define TUMBLEWEED_PHASE_GROWING    0 /* scale ramps up to targetScale */
#define TUMBLEWEED_PHASE_ARMED      1 /* waiting to activate (hit / player in range) */
#define TUMBLEWEED_PHASE_ROLLING    2 /* active rolling motion */
#define TUMBLEWEED_PHASE_DESPAWNING 5 /* fading out and freeing */
#define TUMBLEWEED_PHASE_HOMING     6 /* steering toward targetPos */

typedef struct TumbleweedState {
    u8 pad000[0x270];
    f32 despawnTimer;
    u8 pad274[0x278 - 0x274];
    u8 mode;
    u8 variant;
    u8 effectFlags;
    u8 hitPulseCounter;
} TumbleweedState;

void tumbleweed_updateStateMachine(int obj);
void tumbleweed_updateTargetedStateMachine(int obj);
void tumbleweed_updateEffects(int obj);
void tumbleweed_update(int obj);
int LandedArwing_ReturnZero(void);
void tumbleweed_init(int obj, int defData);
int LandedArwing_TriggerLaunchTarget(int obj, int target);
int LandedArwing_UpdateBounceFade(int obj, u32 *stateWord);
int LandedArwing_UpdateRetreatChase(int obj, int stateWord);

#endif /* MAIN_DLL_BACKPACK_H_ */
