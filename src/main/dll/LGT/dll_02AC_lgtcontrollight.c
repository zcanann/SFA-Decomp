/*
 * lgtcontrollight (DLL 0x2AC) - a switch object that drives nearby point
 * lights from a game bit.
 *
 * It owns no light of its own. Each frame update reads its gameBit; when the
 * bit's value changes it walks LGT_POINTLIGHT_GROUP and, for every point light
 * within `radius`, calls pointlight_setEffectState with the new bit value
 * (CONTROLLIGHT_MODE_DIRECT) or its inverse (CONTROLLIGHT_MODE_INVERTED). The
 * last-seen bit is cached so the sweep only runs on a transition; lastBit
 * starts at CONTROLLIGHT_LAST_BIT_INVALID to force the first update.
 */
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/vecmath.h"
#include "main/dll/LGT/dll_02AC_lgtcontrollight.h"
#include "main/dll/LGT/dll_02A9_lgtpointlight.h"

#define CONTROLLIGHT_MODE_DIRECT      0
#define CONTROLLIGHT_MODE_INVERTED    1
#define CONTROLLIGHT_LAST_BIT_INVALID 0xff

int ControlLight_getExtraSize(void)
{
    return sizeof(ControlLightState);
}

int ControlLight_getObjectTypeId(void)
{
    return 0;
}

void ControlLight_free(void)
{
}

void ControlLight_hitDetect(void)
{
}

void ControlLight_render(void)
{
}

void ControlLight_init(GameObject* obj, int setup)
{
    ControlLightSetup* setupData = (ControlLightSetup*)setup;
    ControlLightState* state = obj->extra;

    state->gameBit = setupData->gameBit;
    state->radius = setupData->radius;
    state->invertMode = setupData->invertMode % 2;
    state->lastBit = CONTROLLIGHT_LAST_BIT_INVALID;
}

#pragma opt_loop_invariants off
#pragma optimization_level 1
void ControlLight_update(GameObject* obj)
{
    u8 newBit;
    u32 bit;
    ControlLightState* state;
    GameObject* self = obj;
    state = self->extra;
    newBit = mainGetBit(state->gameBit);
    bit = newBit;

    if (bit != state->lastBit)
    {
        switch (state->invertMode)
        {
        case CONTROLLIGHT_MODE_DIRECT:
        {
            f32 radius = state->radius;
            int count;
            int i;
            GameObject* lightObj;
            GameObject** objs = (GameObject**)ObjGroup_GetObjects(LGT_POINTLIGHT_GROUP, &count);
            GameObject** lightIter;
            for (i = 0, lightIter = objs; i < count; i++)
            {
                lightObj = *lightIter;
            if (Vec_distance(&self->anim.worldPosX, &lightObj->anim.worldPosX) < radius)
                {
                    pointlight_setEffectState((GameObject*)lightObj, newBit);
                }
                lightIter++;
            }
            break;
        }
        case CONTROLLIGHT_MODE_INVERTED:
        {
            f32 radius = state->radius;
            int count;
            GameObject* lightObj;
            int i;
            int invBit;
            GameObject** objs = (GameObject**)ObjGroup_GetObjects(LGT_POINTLIGHT_GROUP, &count);
            GameObject** lightIter;
            i = 0, lightIter = objs;
            invBit = bit == 0;
            for (; i < count; i++)
            {
                lightObj = *lightIter;
                if (Vec_distance(&self->anim.worldPosX, &lightObj->anim.worldPosX) < radius)
                {
                    pointlight_setEffectState((GameObject*)lightObj, (u8)invBit);
                }
                lightIter++;
            }
            break;
        }
        }
    }

    state->lastBit = newBit;
}
#pragma optimization_level reset
#pragma opt_loop_invariants reset

void ControlLight_release(void)
{
}

void ControlLight_initialise(void)
{
}
