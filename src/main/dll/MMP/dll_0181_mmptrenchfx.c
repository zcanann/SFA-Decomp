/*
 * mmptrenchfx (DLL 0x181) - Moon Mountain Pass trench particle emitter.
 *
 * A placed effect source that periodically spawns particles within a
 * box-shaped volume. The placement supplies a gamebit gate (-1 = always
 * on), per-axis half-extents, and orientation. Each tick the emit
 * cooldown counts down; when it lapses a fresh random offset inside the
 * extents is rotated by the emit angles, added to the object position,
 * and the cooldown/timer are re-rolled. Effect 0x71F fires while the emit
 * timer is positive; effect 0x720 fires every tick from a second random
 * position.
 */

#include "main/dll/mmptrenchfxstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

STATIC_ASSERT(sizeof(MmpTrenchfxState) == 0x30);


extern char lbl_803AC930[];
extern f32 lbl_803E45C0;
extern f32 lbl_803E45B0;
extern f32 lbl_803E45B4;

void mmp_trenchfx_hitDetect(void)
{
}

void mmp_trenchfx_release(void)
{
}

void mmp_trenchfx_initialise(void)
{
}

int mmp_trenchfx_getExtraSize(void) { return 0x30; }
int mmp_trenchfx_getObjectTypeId(void) { return 0x0; }

void mmp_trenchfx_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

#pragma peephole off
void mmp_trenchfx_init(int obj, int data)
{
    MmpTrenchfxState* state = ((GameObject*)obj)->extra;
    MmpTrenchfxPlacement* place = (MmpTrenchfxPlacement*)data;
    s16 angle;
    state->enableBit = place->enableBit;
    state->extentX = (u16)(place->extentX << 2);
    state->extentZ = (u16)(place->extentZ << 2);
    state->extentY = (u16)(place->extentY << 2);
    angle = (s16)(((s32)place->emitAngleZ) << 8);
    state->emitAngles[2] = angle;
    ((GameObject*)obj)->anim.rotZ = angle;
    angle = (s16)(((s32)place->emitAngleY) << 8);
    state->emitAngles[1] = angle;
    ((GameObject*)obj)->anim.rotY = angle;
    angle = (s16)(((s32)place->emitAngleX) << 8);
    state->emitAngles[0] = angle;
    ((GameObject*)obj)->anim.rotX = angle;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E45C0;
}

void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

#pragma scheduling off
void mmp_trenchfx_update(int obj)
{
    MmpTrenchfxState* state = ((GameObject*)obj)->extra;
    if (state->enableBit == -1 || GameBit_Get(state->enableBit) != 0)
    {
        state->emitCooldown -= timeDelta;
        if (state->emitCooldown < lbl_803E45B0)
        {
            state->fxScale = lbl_803E45B4;
            state->fxX = (f32)(int)
            randomGetRange(-state->extentX, state->extentX);
            state->fxY = (f32)(int)
            randomGetRange(-state->extentY, state->extentY);
            state->fxZ = (f32)(int)
            randomGetRange(-state->extentZ, state->extentZ);
            vecRotateZXY((void*)state->emitAngles, &state->fxX);
            state->fxX += ((GameObject*)obj)->anim.localPosX;
            state->fxY += ((GameObject*)obj)->anim.localPosY;
            state->fxZ += ((GameObject*)obj)->anim.localPosZ;
            state->emitCooldown = (f32)(int)
            randomGetRange(0x64, 0xC8);
            state->emitTimer = (f32)(int)
            randomGetRange(0x32, 0x64);
        }
        state->emitTimer -= timeDelta;
        if (state->emitTimer > lbl_803E45B0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71F, &state->fxUnk10, 0x200001,
                                             -1, NULL);
        }
        *(f32*)(lbl_803AC930 + 8) = lbl_803E45B4;
        *(f32*)(lbl_803AC930 + 0xC) = (f32)(int)
        randomGetRange(-state->extentX, state->extentX);
        *(f32*)(lbl_803AC930 + 0x10) = (f32)(int)
        randomGetRange(-state->extentY, state->extentY);
        *(f32*)(lbl_803AC930 + 0x14) = (f32)(int)
        randomGetRange(-state->extentZ, state->extentZ);
        vecRotateZXY((void*)state->emitAngles, (void*)(lbl_803AC930 + 0xC));
        *(f32*)(lbl_803AC930 + 0xC) += ((GameObject*)obj)->anim.localPosX;
        *(f32*)(lbl_803AC930 + 0x10) += ((GameObject*)obj)->anim.localPosY;
        *(f32*)(lbl_803AC930 + 0x14) += ((GameObject*)obj)->anim.localPosZ;
        (*gPartfxInterface)->spawnObject((void*)obj, 0x720, lbl_803AC930, 0x200001, -1,
                                         NULL);
    }
}
