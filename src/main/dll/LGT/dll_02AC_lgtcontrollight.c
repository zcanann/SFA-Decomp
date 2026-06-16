#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct ControlLightSetup
{
    ObjPlacement base;
    u8 pad18;
    s8 invertMode;
    s16 radius;
    u8 pad1C[0x1E - 0x1C];
    s16 gameBit;
} ControlLightSetup;

typedef struct ControlLightState
{
    s16 gameBit;
    u8 pad02[2];
    f32 radius;
    u8 invertMode;
    u8 lastBit;
    u8 pad0A[2];
} ControlLightState;

#define CONTROLLIGHT_MODE_DIRECT 0
#define CONTROLLIGHT_MODE_INVERTED 1
#define CONTROLLIGHT_LAST_BIT_INVALID 0xff

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

void controllight_free(void)
{
}

void controllight_hitDetect(void)
{
}

void controllight_render(void)
{
}

void controllight_init(int obj, int setup)
{
    ControlLightSetup* setupData = (ControlLightSetup*)setup;
    ControlLightState* state = ((GameObject*)obj)->extra;

    state->gameBit = setupData->gameBit;
    state->radius = (f32)setupData->radius;
    state->invertMode = setupData->invertMode % 2;
    state->lastBit = CONTROLLIGHT_LAST_BIT_INVALID;
}

#pragma opt_loop_invariants off
#pragma optimization_level 1
void controllight_update(int obj)
{
    extern void pointlight_setEffectState(int obj, u8 enabled);
    ControlLightState* state = ((GameObject*)obj)->extra;
    u8 bit = (u8)GameBit_Get(state->gameBit);

    if (bit != state->lastBit)
    {
        switch (state->invertMode)
        {
        case CONTROLLIGHT_MODE_DIRECT:
            {
                f32 radius = state->radius;
                int count;
                int i;
                GameObject** objs = (GameObject**)ObjGroup_GetObjects(LGT_POINTLIGHT_GROUP, &count);
                GameObject** p;
                for (i = 0, p = objs; i < count; i++)
                {
                    GameObject* lightObj = *p;
                    if (Vec_distance((int)&((GameObject*)obj)->anim.worldPosX,
                                     (int)&lightObj->anim.worldPosX) < radius)
                    {
                        pointlight_setEffectState((int)lightObj, bit);
                    }
                    p++;
                }
                break;
            }
        case CONTROLLIGHT_MODE_INVERTED:
            {
                f32 radius = state->radius;
                int count;
                int i;
                int invBit;
                GameObject** objs = (GameObject**)ObjGroup_GetObjects(LGT_POINTLIGHT_GROUP, &count);
                GameObject** p;
                invBit = !bit;
                for (i = 0, p = objs; i < count; i++)
                {
                    GameObject* lightObj = *p;
                    if (Vec_distance((int)&((GameObject*)obj)->anim.worldPosX,
                                     (int)&lightObj->anim.worldPosX) < radius)
                    {
                        pointlight_setEffectState((int)lightObj, invBit);
                    }
                    p++;
                }
                break;
            }
        }
    }

    state->lastBit = bit;
}
#pragma optimization_level reset
#pragma opt_loop_invariants reset

void controllight_release(void)
{
}

void controllight_initialise(void)
{
}
