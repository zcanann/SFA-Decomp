/*
 * mmpmoonrock (DLL 0x182) - Moon Mountain Pass carryable moon rock.
 *
 * A gCarryableInterface-backed object the player picks up and places on
 * pedestals. State tracks a "kind" gamebit (0..6) and a flag word driving
 * pickup/placement, throw physics, and a sink-and-respawn cycle when the
 * rock lands in lava (fn_801A7B10 integrates the throw + lava probe via
 * fn_801A78C8; fn_801A79E0 handles the impact/respawn). fn_801A7CC4
 * launches the rock from the player; fn_801A7D74 reconciles the
 * pedestal/inventory gamebit counts (0x88C / 0x894) when the rock is
 * placed or removed. update floats placed rocks with a sine wobble and
 * spawns ambient particles.
 */

#include "main/dll/partfx_interface.h"
#include "main/dll/objfx_api.h"
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/object_render_legacy.h"
#include "main/dll/savegame_object_api.h"
#include "main/object_api.h"
#include "main/track_dolphin_api.h"
#include "main/carryable_interface.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/track_bbox_api.h"
#include "main/obj_list.h"
#include "main/obj_group.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/dll/MMP/dll_0182_mmpmoonrock.h"
#include "main/dll/tricky_api.h"
#include "main/lightmap_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/object_descriptor.h"

#define MMPMOONROCK_OBJGROUP        4
#define MMPMOONROCK_HIT_VOLUME_SLOT 14
#define CARRYABLE_OBJGROUP          0x10
#define MMPMOONROCK_PARTFX          0x723

#define MMPMOONROCK_OBJFLAG_HITDETECT_DISABLED 0x2000

/* state->flags bits (single-bit roles; composites like 0x18/0x28/0x180 kept literal) */
#define MOONROCK_FLAG_PICKUP_PENDING 0x1   /* launch/pickup request queued for next tick */
#define MOONROCK_FLAG_ARMED          0x2   /* settled and ready to be re-picked */
#define MOONROCK_FLAG_FROZEN         0x4   /* held/disabled: update early-returns */
#define MOONROCK_FLAG_GRAB_FRAME     0x8   /* grabbable this frame (recomputed each tick) */
#define MOONROCK_FLAG_ICON_PLACE     0x10  /* A-button icon: place/carry mode */
#define MOONROCK_FLAG_ICON_THROW     0x20  /* A-button icon: throw mode */
#define MOONROCK_FLAG_THROWN         0x40  /* launched, running throw physics */
#define MOONROCK_FLAG_PROBE          0x80  /* transient lava/floor probe flag */
#define MOONROCK_FLAG_SUNK           0x100 /* landed in lava */
#define MOONROCK_FLAG_RESPAWNING     0x200 /* sinking + respawn timer running */
#define MOONROCK_FLAG_PLACED         0x400 /* placed on a pedestal */

STATIC_ASSERT(sizeof(MmpMoonrockState) == 0x30);

typedef struct MmpMoonrockPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 kindGameBit; /* 0x1A: gamebit whose value selects the moonrock kind */
    u8 pad1C[0x1E - 0x1C];
    s16 placedGameBit; /* 0x1E: gamebit set 0 when returned home, 1 when carried away */
    s16 gateBit;       /* 0x20: gamebit gating pickup (cleared = grabbable) */
    u8 pad22[0x28 - 0x22];
} MmpMoonrockPlacement;


#pragma scheduling on
#pragma peephole on

const f32 lbl_803E4548 = 0.707f;
const f32 lbl_803E454C = 8.0f;
const f32 lbl_803E4550 = 10.0f;
const f32 lbl_803E4554 = 0.0f;
const f32 gMoonRockRespawnTime = 120.0f;
const f32 gMoonRockGravity = 0.12f;
const f32 gMoonRockVelClampMin = -5.0f;
const f32 gMoonRockVelClampMax = 5.0f;
const f32 lbl_803E4568 = 20.0f;
const f32 lbl_803E456C = 2.2f;
const f32 lbl_803E4570 = 0.75f;
const f32 lbl_803E4574 = -2.2f;
const f32 lbl_803E4578 = -0.75f;
const f32 lbl_803E457C = 1.0f;
const f32 gMoonRockPickupRange = 40.0f;
const f32 gMoonRockAlphaMax = 255.0f;
const f32 lbl_803E4588 = 0.5f;
const f32 lbl_803E458C = 0.1f;
const f32 lbl_803E4590 = 0.03f;
const f32 lbl_803E4594 = 0.051f;
const f32 gMoonRockPi = 3.1415927f;
const f32 gMoonRockAngleScale = 32768.0f;
const f32 gMoonRockWobbleAmplitude = 182.0f;
const f32 lbl_803E45A4 = 0.0f;

void mmp_moonrock_hitDetect(void)
{
}

void mmp_moonrock_release(void)
{
}

void mmp_moonrock_initialise(void)
{
}

int mmp_moonrock_getExtraSize(void)
{
    return 0x30;
}
int mmp_moonrock_getObjectTypeId(void)
{
    return 0x0;
}


#pragma scheduling off
#pragma peephole off
void fn_801A7B10(GameObject* obj)
{
    MmpMoonrockState* state = obj->extra;
    int hitTypeOut[1];
    f32 floorYOut;
    int blockIdx;
    f32 posY;
    int probeResult;
    blockIdx = objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ);
    if (blockIdx == -1)
        return;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MMPMOONROCK_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject((int)obj);
    obj->anim.velocityY = obj->anim.velocityY - *(f32*)&gMoonRockGravity * timeDelta;
    {
        f32 vel = obj->anim.velocityX;
        f32 clamped;
        if (vel < *(f32*)&gMoonRockVelClampMin)
        {
            clamped = *(f32*)&gMoonRockVelClampMin;
        }
        else if (vel > *(f32*)&gMoonRockVelClampMax)
        {
            clamped = *(f32*)&gMoonRockVelClampMax;
        }
        else
        {
            clamped = vel;
        }
        obj->anim.velocityX = clamped;
    }
    {
        f32 vel = obj->anim.velocityY;
        f32 clamped;
        if (vel < *(f32*)&gMoonRockVelClampMin)
        {
            clamped = *(f32*)&gMoonRockVelClampMin;
        }
        else if (vel > *(f32*)&gMoonRockVelClampMax)
        {
            clamped = *(f32*)&gMoonRockVelClampMax;
        }
        else
        {
            clamped = vel;
        }
        obj->anim.velocityY = clamped;
    }
    {
        f32 vel = obj->anim.velocityX;
        f32 clamped;
        if (vel < *(f32*)&gMoonRockVelClampMin)
        {
            clamped = *(f32*)&gMoonRockVelClampMin;
        }
        else if (vel > *(f32*)&gMoonRockVelClampMax)
        {
            clamped = *(f32*)&gMoonRockVelClampMax;
        }
        else
        {
            clamped = vel;
        }
        obj->anim.velocityX = clamped;
    }
    objMove((GameObject*)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
    state->flags &= ~MOONROCK_FLAG_PROBE;
    posY = obj->anim.localPosY;
    probeResult = fn_801A78C8(obj, obj->anim.localPosX, posY, obj->anim.localPosZ, *(f32*)&lbl_803E4568 + posY, &floorYOut,
                              hitTypeOut);
    if (probeResult == 0)
        return;
    if (probeResult == 2)
    {
        f32 zeroVel;
        state->flags |= MOONROCK_FLAG_SUNK;
        zeroVel = *(f32*)&lbl_803E4554;
        obj->anim.velocityX = zeroVel;
        obj->anim.velocityY = zeroVel;
        obj->anim.velocityZ = zeroVel;
    }
    else
    {
        f32 zeroVel;
        state->flags |= MOONROCK_FLAG_PROBE | MOONROCK_FLAG_SUNK;
        obj->anim.localPosY = floorYOut;
        zeroVel = *(f32*)&lbl_803E4554;
        obj->anim.velocityX = zeroVel;
        obj->anim.velocityY = zeroVel;
        obj->anim.velocityZ = zeroVel;
    }
}


#pragma dont_inline on
void fn_801A79E0(GameObject* obj)
{
    TrackBBoxHit hitScratch;
    int hitObjOut;
    MmpMoonrockState* state;
    int hit;
    state = (obj)->extra;
    hit = ObjHits_GetPriorityHit(obj, &hitObjOut, 0, 0);
    if (hit == 0)
    {
        hit = objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, *(f32*)&lbl_803E454C, 1, &hitScratch,
                                 obj, 1, -1, 0xff, 0);
    }
    if ((hit != 0) || ((((ObjHitsPriorityState*)(obj)->anim.hitReactState)->contactFlags != 0 &&
                        (state->flags & MOONROCK_FLAG_THROWN) != 0) ||
                       (state->flags & MOONROCK_FLAG_SUNK) != 0))
    {
        (obj)->anim.localPosY = (obj)->anim.localPosY + *(f32*)&lbl_803E4550;
        spawnExplosionLegacy((int)obj, *(f32*)&lbl_803E4554, 1, 1, 0, 0, 0, 1, 0);
        state->flags |= MOONROCK_FLAG_RESPAWNING;
        state->respawnTimer = *(f32*)&gMoonRockRespawnTime;
        (obj)->anim.alpha = 0;
        (obj)->anim.localPosX = state->homeX;
        (obj)->anim.localPosY = state->homeY;
        (obj)->anim.localPosZ = state->homeZ;
        saveGame_saveObjectPos((GameObject*)obj);
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void fn_801A80C4(GameObject* obj, f32 x, f32 y, f32 z)
{
    (obj)->anim.localPosX = x;
    (obj)->anim.localPosY = y;
    (obj)->anim.localPosZ = z;
    saveGame_saveObjectPos((GameObject*)obj);
}

#pragma scheduling off
void mmp_moonrock_free(int obj)
{
    ObjGroup_RemoveObject((u32)obj, MMPMOONROCK_OBJGROUP);
    (*gCarryableInterface)->free(obj);
}

void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if ((*gCarryableInterface)->isVisible(obj, visible) != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, *(f32*)&lbl_803E457C);
    }
}


#pragma dont_inline on
#pragma peephole off
void fn_801A7CC4(GameObject* obj)
{
    MmpMoonrockState* state = obj->extra;
    struct
    {
        s16 angleX;
        s16 angleY;
        s16 angleZ;
        s16 _pad;
        f32 length;
        f32 x;
        f32 y;
        f32 z;
    } rotIn;
    GameObject* player = Obj_GetPlayerObject();
    u8* playerState = player->extra;
    f32 zeroVel = *(f32*)&lbl_803E4554;
    obj->anim.velocityX = zeroVel;
    obj->anim.velocityY = *(f32*)&lbl_803E4570 * *(f32*)((char*)playerState + 0x298) + *(f32*)&lbl_803E456C;
    obj->anim.velocityZ = *(f32*)&lbl_803E4578 * *(f32*)((char*)playerState + 0x298) + *(f32*)&lbl_803E4574;
    rotIn.x = zeroVel;
    rotIn.y = zeroVel;
    rotIn.z = zeroVel;
    rotIn.length = *(f32*)&lbl_803E457C;
    rotIn.angleZ = 0;
    rotIn.angleY = 0;
    rotIn.angleX = player->anim.rotX;
    vecRotateZXY(&rotIn, &obj->anim.velocityX);
    state->flags |= MOONROCK_FLAG_THROWN;
}
#pragma dont_inline reset

void fn_801A80F0(GameObject* obj, u8 flag)
{
    MmpMoonrockState* state = obj->extra;
    if (flag != 0)
    {
        state->flags |= MOONROCK_FLAG_FROZEN;
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        state->flags &= ~MOONROCK_FLAG_FROZEN;
        *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    }
}


int fn_801A78C8(GameObject* obj, f32 x, f32 y, f32 z, f32 y2, f32* out1, int* out2)
{
    TrackGroundHit** results;
    f32* e;
    int i;
    int count;

    count = hitDetectFn_80065e50(obj, x, y, z, &results, 0, 1);
    *out1 = y;
    *out2 = 0;
    for (i = 0; i < count; i++)
    {
        if ((s8)results[i]->surfaceType != 0xE && y < results[i]->height &&
            (y2 > results[i]->height || i == count - 1))
        {
            *out2 = (int)results[i]->object;
            *out1 = results[i]->height;
            return (results[i]->normalY < *(f32*)&lbl_803E4548) + 1;
        }
    }
    return 0;
}

void mmp_moonrock_init(GameObject* obj, int param2)
{
    MmpMoonrockState* state = (obj)->extra;
    u8 kind;
    (obj)->objectFlags = (obj)->objectFlags | MMPMOONROCK_OBJFLAG_HITDETECT_DISABLED;
    *(s16*)&state->flags = 0;
    state->kind = mainGetBit(((MmpMoonrockPlacement*)param2)->kindGameBit);
    kind = state->kind;
    if (kind != 0)
    {
        if ((u8)(kind - 3) <= 1 || kind == 6)
        {
            state->flags = state->flags | MOONROCK_FLAG_PLACED;
        }
        (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 0);
    }
    else
    {
        (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 1);
    }
    {
        f32 z = (obj)->anim.localPosY;
        state->baseY = z;
        state->baseY2 = z;
    }
    (*gCarryableInterface)->initAnim((void*)obj, *(int*)&(obj)->extra, 0x32);
    (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x2c))((int)state, 1);
    ObjGroup_AddObject((int)obj, MMPMOONROCK_OBJGROUP);
    state->homeX = (obj)->anim.localPosX;
    state->homeY = (obj)->anim.localPosY;
    state->homeZ = (obj)->anim.localPosZ;
    ObjHits_DisableObject((int)obj);
    fn_801A7D74(obj, 1, 2);
}



void fn_801A7D74(GameObject* obj, u8 place, u8 mode)
{
    int i;
    int count;
    int* list;
    MmpMoonrockState* state;
    MmpMoonrockPlacement* odef;
    MmpMoonrockPlacement* mydef;
    s8 pedestalCount;
    s8 inventoryCount;

    state = obj->extra;
    list = ObjList_GetObjects(&i, &count);
    for (; i < count; i++)
    {
        u32 otherObj = list[i];
        if (otherObj != (u32)obj && ((GameObject*)otherObj)->anim.seqId == 0x518 &&
            Vec_distance(&obj->anim.worldPosX, (void*)(otherObj + 0x18)) < *(f32*)&gMoonRockPickupRange)
        {
            u32 kind;
            odef = (MmpMoonrockPlacement*)((GameObject*)list[i])->anim.placementData;
            mydef = (MmpMoonrockPlacement*)obj->anim.placementData;
            pedestalCount = mainGetBit(0x88C);
            inventoryCount = mainGetBit(0x894);
            if (place == 0)
            {
                (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 1);
                if (odef->placedGameBit != -1)
                {
                    mainSetBits(odef->placedGameBit, 0);
                }
                kind = state->kind;
                if (kind == 3)
                    goto dec;
                if (kind == 4)
                    goto dec;
                if (kind == 6)
                {
                dec:
                    pedestalCount -= 1;
                }
                else
                {
                    inventoryCount -= 1;
                }
                if (mydef->kindGameBit != -1)
                {
                    mainSetBits(mydef->kindGameBit, 0);
                    state->kind = 0;
                }
                {
                    f32 y = obj->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                state->flags &= ~MOONROCK_FLAG_PLACED;
                obj->anim.localPosX = state->homeX;
                obj->anim.localPosY = state->homeY;
                obj->anim.localPosZ = state->homeZ;
                saveGame_saveObjectPos((GameObject*)obj);
            }
            else
            {
                (*(int (**)(int, int))((u8*)*gCarryableInterface + 0x20))((int)state, 0);
                if (odef->placedGameBit != -1)
                {
                    mainSetBits(odef->placedGameBit, 1);
                }
                if (mode == 0)
                {
                    obj->anim.localPosX = ((GameObject*)list[i])->anim.localPosX;
                    obj->anim.localPosY = ((GameObject*)list[i])->anim.localPosY;
                    obj->anim.localPosZ = ((GameObject*)list[i])->anim.localPosZ;
                    saveGame_saveObjectPos((GameObject*)obj);
                }
                {
                    f32 y = obj->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                if (mydef->kindGameBit != -1)
                {
                    mainSetBits(mydef->kindGameBit, odef->kindGameBit);
                    state->kind = odef->kindGameBit;
                }
                kind = state->kind;
                if (kind == 3)
                    goto held;
                if (kind == 4)
                    goto held;
                if (kind == 6)
                {
                held:
                    if (mode != 2)
                    {
                        pedestalCount = pedestalCount + 1;
                    }
                    if (mode == 0)
                    {
                        Sfx_PlayFromObject(0, pedestalCount < 3 ? SFXTRIG_menuups16k : SFXTRIG_mpick1_b);
                        mainSetBits(0x9AE, 1);
                    }
                    state->flags |= MOONROCK_FLAG_PLACED;
                    setAButtonIcon(0);
                }
                else if (mode != 2)
                {
                    inventoryCount += 1;
                }
            }
            if (pedestalCount >= 3)
            {
                mainSetBits(GAMEBIT_MMP_MovedMeteor, 1);
            }
            else
            {
                mainSetBits(GAMEBIT_MMP_MovedMeteor, 0);
            }
            if (pedestalCount > 3)
            {
                pedestalCount = 3;
            }
            else if (pedestalCount < 0)
            {
                pedestalCount = 0;
            }
            if (inventoryCount > 3)
            {
                inventoryCount = 3;
            }
            else if (inventoryCount < 0)
            {
                inventoryCount = 0;
            }
            mainSetBits(0x88C, pedestalCount);
            mainSetBits(0x894, inventoryCount);
        }
    }
}

char gMoonRockSpawnParams[0x18];

void mmp_moonrock_update(GameObject* obj)
{
    MmpMoonrockState* state = obj->extra;
    u8 grabbed;
    int particleHeight;
    int count;
    MmpMoonrockPlacement* def = (MmpMoonrockPlacement*)obj->anim.placementData;
    if (objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY,
                            obj->anim.localPosZ) == -1)
    {
        return;
    }
    if ((state->flags & MOONROCK_FLAG_FROZEN) != 0)
    {
        return;
    }
    if ((state->flags & MOONROCK_FLAG_RESPAWNING) != 0)
    {
        f32 v = state->respawnTimer;
        f32 k = lbl_803E4554;
        if (v > k)
        {
            state->respawnTimer = v - timeDelta;
            if (state->respawnTimer <= k)
            {
                *(s16*)&state->flags = 0;
                obj->anim.alpha = 0xFF;
                ObjHits_DisableObject((int)obj);
                fn_801A7D74(obj, 1, 1);
            }
            else
            {
                obj->anim.alpha =
                    (u8)(int)(*(f32*)&gMoonRockAlphaMax * (*(f32*)&lbl_803E457C - state->respawnTimer / *(f32*)&gMoonRockRespawnTime));
                objParticleFn_80099d84(obj, *(f32*)&lbl_803E4588, 2, *(f32*)&lbl_803E457C - state->respawnTimer / *(f32*)&gMoonRockRespawnTime,
                                       0);
                objParticleFn_80099d84(obj, *(f32*)&lbl_803E4588, 2, *(f32*)&lbl_803E457C - state->respawnTimer / *(f32*)&gMoonRockRespawnTime,
                                       0);
            }
        }
        return;
    }
    objfx_spawnDirectionalBurstLegacy(obj, 1, *(f32*)&lbl_803E457C, 5, 1, 0xA, *(f32*)&lbl_803E454C, 0, 0);
    objfx_spawnDirectionalBurstLegacy(obj, 5, *(f32*)&lbl_803E457C, 5, 1, 0x14, *(f32*)&lbl_803E454C, 0, 0);
    if ((state->flags & MOONROCK_FLAG_THROWN) != 0)
    {
        fn_801A7B10(obj);
        fn_801A79E0(obj);
        return;
    }
    grabbed = 0;
    if ((state->flags & MOONROCK_FLAG_GRAB_FRAME) != 0 && (u8)(*gMapEventInterface)->getObjGroupStatus(0x12, 6) == 0)
    {
        state->flags |= MOONROCK_FLAG_PICKUP_PENDING;
    }
    else if ((state->flags & MOONROCK_FLAG_PLACED) == 0)
    {
        if (def->gateBit != -1 && mainGetBit(def->gateBit) == 0)
        {
            *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        else if ((*gCarryableInterface)->getAnimState((int)obj, *(int*)&obj->extra) != 0)
        {
            grabbed = 1;
        }
    }
    else
    {
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    state->flags &= ~MOONROCK_FLAG_GRAB_FRAME;
    if (grabbed != 0)
    {
        int stateCopy;
        int i;
        int* list;
        u8 found;
        if ((playerGetStateFlag310(Obj_GetPlayerObject()) & 0x4000) != 0)
        {
            setAButtonIcon(5);
            state->flags |= MOONROCK_FLAG_GRAB_FRAME | MOONROCK_FLAG_ICON_PLACE;
            state->flags &= ~MOONROCK_FLAG_ICON_THROW;
        }
        else
        {
            setAButtonIcon(4);
            state->flags |= MOONROCK_FLAG_GRAB_FRAME | MOONROCK_FLAG_ICON_THROW;
            state->flags &= ~MOONROCK_FLAG_ICON_PLACE;
        }
        stateCopy = *(int*)&obj->extra;
        (*gCarryableInterface)->setVisible(stateCopy, 0);
        {
            f32 k;
            def = (MmpMoonrockPlacement*)ObjGroup_GetObjects(CARRYABLE_OBJGROUP, &count);
            i = 0;
            list = (int*)def;
            k = *(f32*)&gMoonRockPickupRange;
            for (; i < count; i++)
            {
                u32 o = (u32)*list;
                if (o != (u32)obj && ((GameObject*)o)->anim.seqId == 0x519 &&
                    Vec_xzDistance(&obj->anim.worldPosX, (f32*)(o + 0x18)) < k)
                {
                    (*gCarryableInterface)->setVisible(stateCopy, 1);
                    found = 0;
                    goto checked;
                }
                list++;
            }
        }
        found = 1;
    checked:
        if (found != 0)
        {
            state->flags |= MOONROCK_FLAG_PICKUP_PENDING;
        }
        if ((state->flags & MOONROCK_FLAG_ARMED) != 0)
        {
            fn_801A7D74(obj, 0, 0);
            state->flags &= ~MOONROCK_FLAG_ARMED;
        }
        return;
    }
    {
        u16 flags = state->flags;
        if ((flags & MOONROCK_FLAG_PLACED) == 0 && (flags & MOONROCK_FLAG_PICKUP_PENDING) != 0)
        {
            if ((flags & MOONROCK_FLAG_ICON_THROW) != 0)
            {
                fn_801A7CC4(obj);
            }
            else
            {
                fn_801A7D74(obj, 1, 0);
            }
            state->flags &= ~MOONROCK_FLAG_PICKUP_PENDING;
        }
    }
    state->flags |= MOONROCK_FLAG_ARMED;
    if (state->kind == 0)
    {
        return;
    }
    if ((state->flags & MOONROCK_FLAG_PLACED) != 0)
    {
        state->raised = mainGetBit(0x894);
    }
    else
    {
        state->raised = 0;
    }
    Sfx_PlayFromObject((u32)obj, SFXTRIG_en_diallp_c);
    Sfx_SetObjectChannelVolumePtrU8Legacy(obj, 0x40, state->raised * 0x20 + 0x20, *(f32*)&lbl_803E4588);
    {
        f32 speed = obj->anim.velocityY;
        if (speed < *(f32*)&lbl_803E458C * ((*(f32*)&lbl_803E4568 * state->raised + state->baseY) - obj->anim.localPosY))
        {
            obj->anim.velocityY = speed + *(f32*)&lbl_803E4590;
        }
        else
        {
            obj->anim.velocityY = speed - *(f32*)&lbl_803E4594;
        }
    }
    state->bobPhase += 0x1000;
    state->rollPhase += 0xDAC;
    state->pitchPhase += 0x800;
    ((void (*)(void*, f32, f32, f32))objMove)(obj, *(f32*)&lbl_803E4554, obj->anim.velocityY * timeDelta,
                                            *(f32*)&lbl_803E4554);
    obj->anim.localPosY =
        obj->anim.localPosY + mathSinf((*(f32*)&gMoonRockPi * state->bobPhase) / *(f32*)&gMoonRockAngleScale);
    if (obj->anim.localPosY < state->baseY)
    {
        obj->anim.localPosY = state->baseY;
    }
    obj->anim.rotZ =
        (s16)(obj->anim.rotZ +
              (int)(*(f32*)&gMoonRockWobbleAmplitude * mathSinf((*(f32*)&gMoonRockPi * state->rollPhase) / *(f32*)&gMoonRockAngleScale)));
    obj->anim.rotY =
        (s16)(obj->anim.rotY +
              (int)(*(f32*)&gMoonRockWobbleAmplitude * mathSinf((*(f32*)&gMoonRockPi * state->pitchPhase) / *(f32*)&gMoonRockAngleScale)));
    *(f32*)(gMoonRockSpawnParams + 8) = *(f32*)&lbl_803E457C;
    *(f32*)(gMoonRockSpawnParams + 0xC) = obj->anim.localPosX;
    *(f32*)(gMoonRockSpawnParams + 0x10) = state->baseY;
    *(f32*)(gMoonRockSpawnParams + 0x14) = obj->anim.localPosZ;
    particleHeight = (int)(obj->anim.localPosY - state->baseY);
    (*gPartfxInterface)
        ->spawnObject((void*)obj, MMPMOONROCK_PARTFX, gMoonRockSpawnParams, 0x200001, -1, &particleHeight);
}

ObjectDescriptor gMMP_moonrockObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmp_moonrock_initialise,
    (ObjectDescriptorCallback)mmp_moonrock_release,
    0,
    (ObjectDescriptorCallback)mmp_moonrock_init,
    (ObjectDescriptorCallback)mmp_moonrock_update,
    (ObjectDescriptorCallback)mmp_moonrock_hitDetect,
    (ObjectDescriptorCallback)mmp_moonrock_render,
    (ObjectDescriptorCallback)mmp_moonrock_free,
    (ObjectDescriptorCallback)mmp_moonrock_getObjectTypeId,
    mmp_moonrock_getExtraSize,
};

const f32 lbl_803E45B0 = 0.0f;
const f32 lbl_803E45B4 = 1.0f;
