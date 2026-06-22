/*
 * wmworm (DLL 0x0207) - 'WM_Worm', a worm enemy for Krazoa Palace
 * (map 'warlock', Dinosaur Planet's Warlock Mountain - hence the WM
 * dll prefix). TU: 0x801F3C2C-0x801F3F18.
 *
 * CUT CONTENT: the object def shipped (OBJECTS.bin def 954, romlist
 * type 0x179) and this handler is fully implemented, but no map
 * romlist places type 0x179 and nothing spawns it dynamically - the
 * worm is unreachable in retail (same status as WM_WallCraw).
 *
 * While the player is within WMWORM_CHASE_RANGE (in the XZ plane of the
 * placement) the worm drifts toward the player at 1% of the offset per
 * time unit and spins; once per approach it emits a burst of
 * state->burstCount particle effects, then cools down for that many
 * frames in obj->unkF4 before it may fire again. Out of range it snaps
 * back to its recorded home position.
 */
#include "main/dll_000A_expgfx.h"
#include "main/dll/WM/dll_0207_wmworm.h"
#include "main/gameplay_runtime.h"
extern f32 Vec_xzDistance(f32* a, f32* b);
extern u8 framesThisStep;
extern f32 lbl_803E5E58; /* 440.0: chase range */
extern f32 lbl_803E5E5C; /* 0.0 */
extern f32 lbl_803E5E60; /* 0.01: chase speed factor */
extern f32 timeDelta;

int wmworm_getExtraSize(void) { return sizeof(WmWormState); }
int wmworm_getObjectTypeId(void) { return 0x0; }

void wmworm_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void wmworm_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void wmworm_hitDetect(void)
{
}

#pragma opt_common_subs off
void wmworm_update(GameObject* obj)
{
    float dx;
    float dy;
    float dz;
    GameObject* player;
    WmWormState* state;
    int burstCount;
    int i;
    f32 dist;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        dist = Vec_xzDistance(&player->anim.worldPosX, &((ObjPlacement*)obj->anim.placementData)->posX);
        if (dist > lbl_803E5E58)
        {
            obj->anim.localPosX = state->homeX;
            obj->anim.localPosY = state->homeY;
            obj->anim.localPosZ = state->homeZ;
        }
        else
        {
            dx = player->anim.worldPosX - obj->anim.localPosX;
            dy = player->anim.worldPosY - obj->anim.localPosY;
            dz = player->anim.worldPosZ - obj->anim.localPosZ;
            /* "axis offset != 0" spelled as two strict compares; the
               self-reassign split keeps the scale product in the dN
               register (recipe #85). */
            if ((dx > lbl_803E5E5C) || (dx < lbl_803E5E5C))
            {
                dx = lbl_803E5E60 * dx;
                obj->anim.localPosX = dx * timeDelta + obj->anim.localPosX;
            }
            if ((dy > lbl_803E5E5C) || (dy < lbl_803E5E5C))
            {
                dy = lbl_803E5E60 * dy;
                obj->anim.localPosY = dy * timeDelta + obj->anim.localPosY;
            }
            if ((dz > lbl_803E5E5C) || (dz < lbl_803E5E5C))
            {
                dz = lbl_803E5E60 * dz;
                obj->anim.localPosZ = dz * timeDelta + obj->anim.localPosZ;
            }
            burstCount = state->burstCount;
            if (burstCount >= 0 || (burstCount < 0 && obj->unkF4 <= 0))
            {
                if (burstCount == 0)
                {
                    state->unk0C = 1;
                }
                obj->anim.rotX += 300;
                if (0 < state->burstCount)
                {
                    for (i = 0; (s16)i < state->burstCount; i++)
                    {
                        (*gPartfxInterface)->spawnObject(obj, state->particleEffectId, NULL, 4,
                                                         -1, NULL);
                    }
                }
                else
                {
                    (*gPartfxInterface)->spawnObject(obj, state->particleEffectId, NULL, 4,
                                                     -1, NULL);
                }
                /* cooldown: burstCount frames before the next burst
                   (negated; the guard above re-fires at <= 0) */
                obj->unkF4 = -state->burstCount;
            }
            else if (burstCount < 0 && obj->unkF4 > 0)
            {
                obj->unkF4 -= framesThisStep;
            }
        }
    }
    return;
}

#pragma opt_common_subs reset
void wmworm_init(GameObject* obj, WmWormSetup* setup)
{
    WmWormState* state;

    obj->anim.rotX = 0;
    state = obj->extra;
    state->effectScale = (f32)((s32)setup->effectScale << 2);
    state->particleEffectId = setup->particleEffectId;
    state->burstCount = setup->burstCount;
    state->unk0C = 0;
    if (state->burstCount < 1)
    {
        obj->unkF4 = state->burstCount;
    }
    else
    {
        obj->unkF4 = 0;
    }
    state->homeX = obj->anim.localPosX;
    state->homeY = obj->anim.localPosY;
    state->homeZ = obj->anim.localPosZ;
}

void wmworm_release(void)
{
}

void wmworm_initialise(void)
{
}
