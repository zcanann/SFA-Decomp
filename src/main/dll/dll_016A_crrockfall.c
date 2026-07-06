/*
 * crrockfall (DLL 0x16A) - a scripted falling-rock / boulder object.
 *
 * On init the per-rock scale is derived from the placement params, the
 * capsule hitbox is sized from the sub-object bounds, and a config-table
 * variant is chosen by seqId (entry 1 of gRockfallCfgTable for seqId 0x600,
 * else entry 0). update() runs the fall state machine:
 *   mode 0 armed   - count down fallDelay while the player is in xz range
 *   mode 1 falling - gravity integrate Y, scrape sfx, until floorY+restOffsetY
 *   mode 2 resting - hitbox stays live
 *   mode 3 shattered - on a hit: stop scrape sfx, play impact sfx and
 *                      (for non-seqId-103 rocks) spawn an explosion
 * The fall is gated by the placement game bit (unk1C); render fades the
 * rock by height fraction and player distance and hides it once shattered.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/crrockfallplacement_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"

STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

/* anim.seqId rock variants: BIG selects gRockfallCfgTable entry 1;
 * QUARRY has its own scrape/impact sfx and skips the explosion. */
#define CRROCKFALL_SEQ_BIG    0x600
#define CRROCKFALL_SEQ_QUARRY 103

/* CrRockfallState.mode */
#define zcEn3_ROCKFALL_MODE_ARMED 0     /* count down fallDelay while player is in range */
#define zcEn3_ROCKFALL_MODE_FALLING 1   /* gravity integrate Y until floorY+restOffsetY */
#define zcEn3_ROCKFALL_MODE_RESTING 2   /* landed; hitbox stays live */
#define zcEn3_ROCKFALL_MODE_SHATTERED 3 /* hit: stop scrape sfx, play impact, maybe explode */
#define zcEn3_ROCKFALL_MODE_4 4

extern u32 ObjHitbox_SetCapsuleBounds();
extern u32 ObjHits_DisableObject();
extern void* Obj_GetPlayerObject(void);
extern void* gRockfallResource;
extern f32 lbl_803E4708;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern f32 lbl_803E4700;
extern f32 lbl_803E4704;
extern f32 Vec_distance(f32* a, f32* b);
extern f32 timeDelta;
extern u8 framesThisStep;
extern u8 gRockfallCfgTable[];
extern f32 gRockfallScaleDivisor;
extern void fn_800628CC(int* obj);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern void Sfx_PlayFromObject(int* obj, int sfx);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E46E8;
extern f32 lbl_803E46EC;
extern f32 lbl_803E46F0;
extern f32 lbl_803E470C;
extern f32 lbl_803E4710;
extern f32 lbl_803E4714;
extern f32 lbl_803E4718;
extern f32 lbl_803E471C;
extern f32 gRockfallGravity;

void crrockfall_free(void)
{
}

void crrockfall_hitDetect(void)
{
}

int crrockfall_getExtraSize(void) { return 0x14; }
int crrockfall_getObjectTypeId(void) { return 0x0; }

void crrockfall_initialise(void) { gRockfallResource = NULL; }

#pragma peephole off
void crrockfall_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    CrRockfallState* state = ((GameObject*)obj)->extra;
    if (state->mode != zcEn3_ROCKFALL_MODE_SHATTERED && visible != 0)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4, lbl_803E4708);
    }
}

#pragma dont_inline on
#pragma scheduling off
f32 fn_801ACCFC(int obj)
{
    CrRockfallState* state = ((GameObject*)obj)->extra;
    int* list;
    int count;
    int i;
    int bestIdx;
    f32 bestDist;
    count = hitDetectFn_80065e50(obj,
                                 ((GameObject*)obj)->anim.localPosX,
                                 ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ,
                                 &list, 0, 0);
    bestDist = lbl_803E4700;
    bestIdx = -1;
    for (i = 0; i < count; i++)
    {
        f32 dy;
        if ((dy = ((GameObject*)obj)->anim.localPosY - *(f32*)list[i]) > *(f32*)&lbl_803E4704 && dy < bestDist)
        {
            bestDist = dy;
            bestIdx = i;
        }
    }
    if (bestIdx != -1)
    {
        state->floorFound = 1;
        return *(f32*)list[bestIdx];
    }
    return ((GameObject*)obj)->anim.localPosY;
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void crrockfall_release(void)
{
    if (gRockfallResource != NULL)
    {
        Resource_Release(gRockfallResource);
    }
    gRockfallResource = NULL;
}

#pragma scheduling off
#pragma peephole off
void crrockfall_init(int* obj, u8* params)
{
    CrRockfallState* state = ((GameObject*)obj)->extra;
    int* sub;
    ObjModelState* modelState;

    state->mode = zcEn3_ROCKFALL_MODE_ARMED;
    state->startY = ((GameObject*)obj)->anim.localPosY;
    state->fallDelay = *(s16*)((char*)params + 0x1e);
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
    params[0x1b] / gRockfallScaleDivisor;

    sub = *(int**)&((GameObject*)obj)->anim.hitReactState;
    if (sub != NULL)
    {
        f32 scale = ((GameObject*)obj)->anim.rootMotionScale;
        ObjHitbox_SetCapsuleBounds(obj,
                                   (int)((f32)((ObjHitsPriorityState*)sub)->primaryRadius * scale),
                                   (int)((f32)((ObjHitsPriorityState*)sub)->primaryCapsuleOffsetA * scale),
                                   (int)((f32)((ObjHitsPriorityState*)sub)->primaryCapsuleOffsetB * scale));
        ObjHits_DisableObject(obj);
    }

    modelState = ((GameObject*)obj)->anim.modelState;
    if (modelState != NULL)
    {
        modelState->flags |= 0xb0;
        modelState->flags |= 0xc00;
        modelState->overrideWorldPosX = ((GameObject*)obj)->anim.localPosX;
        modelState->overrideWorldPosZ = ((GameObject*)obj)->anim.localPosZ;
        modelState->shadowScale = modelState->shadowScale * ((GameObject*)obj)->anim.rootMotionScale;
    }

    if (((GameObject*)obj)->anim.seqId == CRROCKFALL_SEQ_BIG)
    {
        state->cfg = (CrRockfallCfgEntry*)&gRockfallCfgTable[0xc];
    }
    else
    {
        state->cfg = (CrRockfallCfgEntry*)gRockfallCfgTable;
    }
}

#pragma opt_propagation off
void crrockfall_update(int* obj)
{
    CrRockfallState* state = ((GameObject*)obj)->extra;
    int* hitState = *(int**)&((GameObject*)obj)->anim.hitReactState;
    ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
    int* placement = *(int**)&((GameObject*)obj)->anim.placementData;

    if (gRockfallResource == NULL)
    {
        gRockfallResource = Resource_Acquire(91, 1);
    }

    if (state->floorFound == 0)
    {
        state->floorY = fn_801ACCFC((int)obj);
        if (state->floorFound != 0 && modelState != NULL)
        {
            modelState->overrideWorldPosY = state->floorY;
            fn_800628CC(obj);
        }
        return;
    }
    else
    {
        if (modelState != NULL)
        {
            f32 frac;
            f32 height;
            f32 dist;
            int n;
            int* player;
            frac = (((GameObject*)obj)->anim.localPosY - state->floorY) /
                (state->startY - state->floorY);
            if (frac > lbl_803E4708)
            {
                frac = lbl_803E4708;
            }
            else if (frac < lbl_803E46E8)
            {
                frac = lbl_803E46E8;
            }
            height = (*(f32*)&lbl_803E4708) - frac;
            player = Obj_GetPlayerObject();
            if (player != NULL)
            {
                dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
                if (dist > lbl_803E470C)
                {
                    dist = lbl_803E470C;
                }
                else if (dist < lbl_803E4710)
                {
                    dist = lbl_803E4710;
                }
            }
            else
            {
                dist = lbl_803E470C;
            }
            dist = (dist - lbl_803E4710) / lbl_803E4714;
            dist = lbl_803E4708 - dist;
            n = (int)(lbl_803E4718 * height) + 0x40;
            modelState->shadowAlpha =
                (int)(((f32)(u32) * (u8*)((char*)obj + 0x37) / lbl_803E471C) *
                    ((f32)n * dist));
        }

        if (((CrrockfallPlacement*)placement)->gameBitId == -1 ||
            GameBit_Get(((CrrockfallPlacement*)placement)->gameBitId) != 0)
        {
            switch (state->mode)
            {
            case zcEn3_ROCKFALL_MODE_ARMED:
                {
                    int cond;
                    int* player = Obj_GetPlayerObject();
                    if (player == NULL)
                    {
                        cond = 0;
                    }
                    else
                    {
                        int* def = *(int**)&((GameObject*)obj)->anim.placementData;
                        f32 xz = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                                                &((GameObject*)player)->anim.worldPosX);
                        f32 dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                        if (dy < lbl_803E46E8)
                        {
                            dy = lbl_803E46E8;
                        }
                        if (xz < lbl_803E46EC * (f32)(u32)((CrrockfallPlacement*)def)->triggerRange &&
                            dy < lbl_803E46F0)
                        {
                            cond = 1;
                        }
                        else
                        {
                            cond = 0;
                        }
                    }
                    if (cond != 0)
                    {
                        if ((state->fallDelay -= framesThisStep) <= 0)
                        {
                            state->mode = zcEn3_ROCKFALL_MODE_FALLING;
                        }
                    }
                    break;
                }
            case zcEn3_ROCKFALL_MODE_FALLING:
                if (state->fallStarted == 0)
                {
                    state->fallStarted = 1;
                    ((GameObject*)obj)->anim.velocityY = lbl_803E46E8;
                    if (((GameObject*)obj)->anim.seqId == CRROCKFALL_SEQ_QUARRY)
                    {
                        Sfx_PlayFromObject(obj, SFXwp_sexpl2_c);
                    }
                    Sfx_PlayFromObject(obj, SFXmv_blockscrape_lp);
                    ((ObjHitsPriorityState*)hitState)->flags |= 1;
                }
                *(int*)&((ObjHitsPriorityState*)hitState)->objectHitMask = 16;
                *(int*)&((ObjHitsPriorityState*)hitState)->skeletonHitMask = 16;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumeId = 1;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumePriority = 13;
                ((GameObject*)obj)->anim.velocityY =
                    gRockfallGravity * timeDelta + ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.localPosY =
                    ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
                if (((GameObject*)obj)->anim.localPosY <
                    state->floorY + state->cfg->restOffsetY)
                {
                    ((GameObject*)obj)->anim.localPosY =
                        state->cfg->restOffsetY * ((GameObject*)obj)->anim.rootMotionScale +
                        state->floorY;
                    state->mode = zcEn3_ROCKFALL_MODE_RESTING;
                    if (state->cfg->landSfx != 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)state->cfg->landSfx);
                    }
                }
                break;
            case zcEn3_ROCKFALL_MODE_RESTING:
                *(int*)&((ObjHitsPriorityState*)hitState)->objectHitMask = 16;
                *(int*)&((ObjHitsPriorityState*)hitState)->skeletonHitMask = 16;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumeId = 1;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumePriority = 13;
                break;
            case zcEn3_ROCKFALL_MODE_SHATTERED:
                break;
            }

            if (*(void**)&((ObjHitsPriorityState*)hitState)->lastHitObject != NULL)
            {
                ((ObjHitsPriorityState*)hitState)->flags &= ~1;
                state->mode = zcEn3_ROCKFALL_MODE_SHATTERED;
                Sfx_StopObjectChannel(obj, 8);
                if (((GameObject*)obj)->anim.seqId == CRROCKFALL_SEQ_QUARRY)
                {
                    Sfx_PlayFromObject(obj, SFXwp_simp1_c);
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_jbike_bombbeep);
                    spawnExplosion(obj, (f32)(u32)((CrrockfallPlacement*)placement)->explosionScale,
                                   1, 1, 0, 1, 1, 1, 1);
                }
            }
        }
    }

    {
        f32 z = lbl_803E46E8;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
}
#pragma opt_propagation reset

u8 gRockfallCfgTable[] = {
    0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x03, 0xE3, 0x41, 0xF0, 0x00, 0x00,
};
