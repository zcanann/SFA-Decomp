/*
 * explodeanimator (DLL 0x13D) - one-shot particle burst animator.
 * When the trigger game bit (placement->triggerGameBit) becomes set, it fires
 * a configurable number of particles with randomised positions and velocities
 * drawn from per-axis min/max ranges in the placement data, then sets a result
 * game bit (placement->resultGameBit) and marks itself done (state->flags |= 1)
 * so it never fires again.
 *
 * Lives in OBJ_GROUP 0x1A alongside the sister xyzanimator (0x51) that drives
 * continuous map-geometry deformation.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/dll_013D_explodeanimator.h"

#define EXPLODEANIMATOR_OBJGROUP 0x1a

extern void ObjGroup_RemoveObject(u32 obj, int group);
extern u32 ObjGroup_AddObject();

int ExplodeAnimator_getExtraSize(void)
{
    return 0x4;
}
int ExplodeAnimator_getObjectTypeId(void)
{
    return 0x0;
}

void ExplodeAnimator_free(int obj)
{
    ObjGroup_RemoveObject(obj, EXPLODEANIMATOR_OBJGROUP);
}

void ExplodeAnimator_render(void)
{
}

void ExplodeAnimator_hitDetect(void)
{
}

void ExplodeAnimator_update(int* obj)
{
    int i;
    u8* sub;
    u8* def;
    f32 buf[6];
    f32 vel[2];

    sub = ((GameObject*)obj)->extra;
    if ((sub[2] & 1) != 0)
        return;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (mainGetBit(((ExplodeanimatorPlacement*)def)->triggerGameBit) == 0)
        return;
    mainSetBits(((ExplodeanimatorPlacement*)def)->resultGameBit, 1);
    sub[2] = (u8)(sub[2] | 1);
    {
        for (i = 0; i < def[0x2c]; i++)
        {
            vel[0] = 0.01f * (f32)(s32)randomGetRange(((ExplodeanimatorPlacement*)def)->velXMin,
                                                      ((ExplodeanimatorPlacement*)def)->velXMax);
            vel[1] = 0.01f * (f32)(s32)randomGetRange(((ExplodeanimatorPlacement*)def)->velYMin,
                                                      ((ExplodeanimatorPlacement*)def)->velYMax);
            buf[3] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement*)def)->posXMin,
                                              ((ExplodeanimatorPlacement*)def)->posXMax);
            buf[4] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement*)def)->posYMin,
                                              ((ExplodeanimatorPlacement*)def)->posYMax);
            buf[5] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement*)def)->posZMin,
                                              ((ExplodeanimatorPlacement*)def)->posZMax);
            (*gPartfxInterface)->spawnObject(obj, ((ExplodeanimatorPlacement*)def)->effectId, buf, 2, -1, vel);
        }
    }
}

void ExplodeAnimator_init(int* obj, int* def)
{
    int* state = ((GameObject*)obj)->extra;
    int flag;
    if ((u32)mainGetBit(((ExplodeanimatorPlacement*)def)->resultGameBit) != 0u)
    {
        flag = 1;
    }
    else
    {
        flag = 0;
    }
    ((ExplodeanimatorState*)state)->flags = flag;
    ObjGroup_AddObject(obj, EXPLODEANIMATOR_OBJGROUP);
}

void ExplodeAnimator_release(void)
{
}

void ExplodeAnimator_initialise(void)
{
}
