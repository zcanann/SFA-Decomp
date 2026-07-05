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

#define EXPLODEANIMATOR_OBJGROUP 0x1a
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern u32 ObjGroup_AddObject();

typedef struct ExplodeanimatorState
{
    u8 pad0[0x2 - 0x0];
    u8 flags;   /* 0x02: bit 0 = already fired; skip further updates */
    u8 pad3[0x4 - 0x3];
} ExplodeanimatorState;

typedef struct ExplodeanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 posXMin;    /* 0x18 */
    s16 posYMin;    /* 0x1A */
    s16 posZMin;    /* 0x1C */
    s16 posXMax;    /* 0x1E */
    s16 posYMax;    /* 0x20 */
    s16 posZMax;    /* 0x22 */
    s16 effectId;   /* 0x24: particle effect id passed to spawnObject */
    u8 pad26[0x28 - 0x26];
    s16 velXMax;    /* 0x28 */
    s16 velYMax;    /* 0x2A */
    u8 pad2C[0x2E - 0x2C];
    s16 velXMin;    /* 0x2E */
    s16 velYMin;    /* 0x30 */
    s16 resultGameBit;  /* 0x32: set to 1 when triggered */
    s16 triggerGameBit; /* 0x34: gate bit; burst fires once this is set */
    u8 pad36[0x38 - 0x36];
} ExplodeanimatorPlacement;

int explodeanimator_getExtraSize(void) { return 0x4; }
int explodeanimator_getObjectTypeId(void) { return 0x0; }

void explodeanimator_free(int x) { ObjGroup_RemoveObject(x, EXPLODEANIMATOR_OBJGROUP); }

void explodeanimator_render(void)
{
}

void explodeanimator_hitDetect(void)
{
}

void explodeanimator_update(int* obj)
{
    int i;
    u8* sub;
    u8* def;
    f32 buf[6];
    f32 vel[2];

    sub = ((GameObject*)obj)->extra;
    if ((sub[2] & 1) != 0) return;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((ExplodeanimatorPlacement*)def)->triggerGameBit) == 0) return;
    GameBit_Set(((ExplodeanimatorPlacement*)def)->resultGameBit, 1);
    sub[2] = (u8)(sub[2] | 1);
    {
    for (i = 0; i < def[0x2c]; i++)
    {
        vel[0] = 0.01f * (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->velXMin, ((ExplodeanimatorPlacement*)def)->velXMax);
        vel[1] = 0.01f * (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->velYMin, ((ExplodeanimatorPlacement*)def)->velYMax);
        buf[3] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->posXMin, ((ExplodeanimatorPlacement*)def)->posXMax);
        buf[4] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->posYMin, ((ExplodeanimatorPlacement*)def)->posYMax);
        buf[5] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->posZMin, ((ExplodeanimatorPlacement*)def)->posZMax);
        (*gPartfxInterface)->spawnObject(obj, ((ExplodeanimatorPlacement*)def)->effectId, buf, 2, -1, vel);
    }
    }
}

void explodeanimator_init(int* obj, int* def)
{
    int* state = ((GameObject*)obj)->extra;
    int v;
    if ((u32)GameBit_Get(((ExplodeanimatorPlacement*)def)->resultGameBit) != 0u)
    {
        v = 1;
    }
    else
    {
        v = 0;
    }
    ((ExplodeanimatorState*)state)->flags = v;
    ObjGroup_AddObject(obj, EXPLODEANIMATOR_OBJGROUP);
}

void explodeanimator_release(void)
{
}

void explodeanimator_initialise(void)
{
}
