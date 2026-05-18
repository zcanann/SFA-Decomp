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
#define TUMBLEWEED_EXPGFX_MODE_ACTIVE 2

#define TUMBLEWEED_EFFECT_FLAG_BURST 0x01
#define TUMBLEWEED_EFFECT_FLAG_PUFF 0x02
#define TUMBLEWEED_EFFECT_FLAG_DESPAWN 0x04
#define TUMBLEWEED_EFFECT_FLAG_HIT_PULSE 0x10

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
int fn_801650D0(void);
void tumbleweed_init(int obj, int defData);
int fn_801650D8(int obj, int target);
int fn_80165188(int obj, u32 *stateWord);
int fn_801653D8(int obj, int stateWord);

#endif /* MAIN_DLL_BACKPACK_H_ */
