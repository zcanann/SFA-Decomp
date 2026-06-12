/* DLL 0x0207 — wmworm (WarpZone Module worm enemy). TU: 0x801F3C2C–0x801F3F18. */
#include "main/dll_000A_expgfx.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/LGT/dll_0207_wmworm.h"

extern undefined4 FUN_8001753c();
extern void* Obj_GetPlayerObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern EffectInterface** gPartfxInterface;
extern byte framesThisStep;
extern f32 lbl_803E5E58;
extern f32 lbl_803E5E5C;
extern f32 lbl_803E5E60;
extern f32 timeDelta;

void wmworm_hitDetect(void)
{
}

int wmworm_getExtraSize(void) { return 0x1c; }
int wmworm_getObjectTypeId(void) { return 0x0; }

void wmworm_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void wmworm_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

#pragma peephole on
void wmworm_update(GameObject* obj)
{
    float fVar1;
    float fVar2;
    float fVar3;
    GameObject* player;
    WmWormState* state;
    ObjPlacement* placement;
    short burstCount;
    f32 dist;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    placement = (ObjPlacement*)obj->anim.placementData;
    if (player != NULL)
    {
        dist = Vec_xzDistance(&player->anim.worldPosX, &placement->posX);
        if (dist > lbl_803E5E58)
        {
            obj->anim.localPosX = state->homeX;
            obj->anim.localPosY = state->homeY;
            obj->anim.localPosZ = state->homeZ;
        }
        else
        {
            fVar1 = player->anim.worldPosX - obj->anim.localPosX;
            fVar2 = player->anim.worldPosY - obj->anim.localPosY;
            fVar3 = player->anim.worldPosZ - obj->anim.localPosZ;
            if ((fVar1 > lbl_803E5E5C) || (fVar1 < lbl_803E5E5C))
            {
                obj->anim.localPosX = lbl_803E5E60 * fVar1 * timeDelta + obj->anim.localPosX;
            }
            if ((fVar2 > lbl_803E5E5C) || (fVar2 < lbl_803E5E5C))
            {
                obj->anim.localPosY = lbl_803E5E60 * fVar2 * timeDelta + obj->anim.localPosY;
            }
            if ((fVar3 > lbl_803E5E5C) || (fVar3 < lbl_803E5E5C))
            {
                obj->anim.localPosZ = lbl_803E5E60 * fVar3 * timeDelta + obj->anim.localPosZ;
            }
            burstCount = state->burstCount;
            if ((-1 < burstCount) || ((-1 >= burstCount && (obj->unkF4 < 1))))
            {
                if (burstCount == 0)
                {
                    state->unk0C = 1;
                }
                obj->anim.rotY += 300;
                if (0 < state->burstCount)
                {
                    for (burstCount = 0; burstCount < state->burstCount; burstCount = burstCount + 1)
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
                obj->unkF4 = -state->burstCount;
            }
            else if ((burstCount < 0) && (0 < obj->unkF4))
            {
                obj->unkF4 = obj->unkF4 - (u32)framesThisStep;
            }
        }
    }
    return;
}

#pragma peephole off
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
