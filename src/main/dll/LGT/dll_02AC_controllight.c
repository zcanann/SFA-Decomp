#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct ControlLightSetup {
    ObjPlacement base;
    u8 pad18;
    s8 invertMode;
    s16 radius;
    u8 pad1C[0x1E - 0x1C];
    s16 gameBit;
} ControlLightSetup;

typedef struct ControlLightState {
    s16 gameBit;
    u8 pad02[2];
    f32 radius;
    u8 invertMode;
    u8 lastBit;
    u8 pad0A[2];
} ControlLightState;

STATIC_ASSERT(sizeof(ControlLightState) == 0x0C);
STATIC_ASSERT(offsetof(ControlLightState, gameBit) == 0x00);
STATIC_ASSERT(offsetof(ControlLightState, radius) == 0x04);
STATIC_ASSERT(offsetof(ControlLightState, invertMode) == 0x08);
STATIC_ASSERT(offsetof(ControlLightState, lastBit) == 0x09);
STATIC_ASSERT(offsetof(ControlLightSetup, invertMode) == 0x19);
STATIC_ASSERT(offsetof(ControlLightSetup, radius) == 0x1A);
STATIC_ASSERT(offsetof(ControlLightSetup, gameBit) == 0x1E);
STATIC_ASSERT(sizeof(ControlLightSetup) == 0x20);

int controllight_getExtraSize(void) { return 0xc; }

int controllight_getObjectTypeId(void) { return 0; }

void controllight_free(void) {}

void controllight_hitDetect(void) {}

void controllight_render(void) {}

#pragma peephole off
#pragma scheduling off
void controllight_init(int obj, int setup)
{
    ControlLightSetup *setupData = (ControlLightSetup *)setup;
    ControlLightState *state = ((GameObject *)obj)->extra;

    state->gameBit = setupData->gameBit;
    state->radius = (f32)setupData->radius;
    state->invertMode = setupData->invertMode % 2;
    state->lastBit = 0xff;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void controllight_update(int obj)
{
    ControlLightState *state = ((GameObject *)obj)->extra;
    u8 bit = (u8)GameBit_Get(state->gameBit);

    if (bit != state->lastBit) {
        switch (state->invertMode) {
        case 0: {
            f32 radius = state->radius;
            int count;
            int *objs = ObjGroup_GetObjects(0x35, &count);
            int *p = objs;
            int i;
            for (i = 0; i < count; i++) {
                int o = *p;
                if (Vec_distance(obj + 0x18, o + 0x18) < radius) {
                    pointlight_setEffectState(o, bit);
                }
                p++;
            }
            break;
        }
        case 1: {
            f32 radius = state->radius;
            int count;
            int *objs = ObjGroup_GetObjects(0x35, &count);
            int *p = objs;
            int i;
            for (i = 0; i < count; i++) {
                int o = *p;
                if (Vec_distance(obj + 0x18, o + 0x18) < radius) {
                    pointlight_setEffectState(o, !bit);
                }
                p++;
            }
            break;
        }
        }
    }

    state->lastBit = bit;
}
#pragma scheduling reset
#pragma peephole reset

void controllight_release(void) {}

void controllight_initialise(void) {}
