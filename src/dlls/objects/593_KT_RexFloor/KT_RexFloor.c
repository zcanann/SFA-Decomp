/*
 * KT_RexFloor (DLL 0x251) - a stompable floor plate in the T-rex
 * (Galdon) arena that the player charges by standing on it.
 *
 * Its placement game bit (activeBit) gates three behaviours: standing on
 * the plate runs the charge timer up, raising a per-step level bit each
 * tick; once the level maxes out it flips the path-selection game bits
 * (0x55a/0x55b) and tells ktrexlevel to update the branch path. The plate
 * mesh rises/lowers between configured heights via curve-lookups (the rom
 * curve interface) and animates its texture scroll + particle/sfx cues.
 */
#include "dlls/object_descriptor.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/DR/dll_024F_ktrexlevel.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/DR/dll_0251_ktrexfloorswitch.h"

#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/objtexture.h"
#include "main/dll/rom_curve_interface.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"

int gKTrexFloorSwitchPrevMoved;

const Vec gKTrexFloorSwitchLocalEdgeZ = {0.0f, 0.0f, 55.0f};
const Vec gKTrexFloorSwitchLocalEdgeX = {55.0f, 0.0f, 0.0f};
int gKTrexFloorSwitchCurveFindResult = 0x19;

/* KtrexfloorswitchState.flags (offset 0x10) bits */
#define KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED 0x1 /* charge cycle maxed+reset; suppresses charging until reactivation */
#define KTREXFLOORSWITCH_FLAG_RISING        0x2 /* plate rising back up to baseHeight */
#define KTREXFLOORSWITCH_FLAG_SINKING       0x4 /* plate sinking down to baseHeight - sinkDepth */
#define KTREXFLOORSWITCH_FLAG_CHARGED       0x8 /* charge level reached max (0xf) */
#define KTREXFLOORSWITCH_FLAG_MOVING        (KTREXFLOORSWITCH_FLAG_RISING | KTREXFLOORSWITCH_FLAG_SINKING) /* 0x6 */

/* Partfx spawned while the plate moves vs after it settles. */
#define KTREXFLOORSWITCH_PARTFX_MOVING  0x488 /* emitted each frame the plate is actively rising/sinking */
#define KTREXFLOORSWITCH_PARTFX_SETTLED 0x486 /* emitted once the plate has stopped moving */

int KT_RexFloorSwitch_getExtraSize(void)
{
    return 0x14;
}

int KT_RexFloorSwitch_getObjectTypeId(void)
{
    return 0x0;
}

void KT_RexFloorSwitch_free(void)
{
}

void KT_RexFloorSwitch_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
    }
}

void KT_RexFloorSwitch_hitDetect(void)
{
}

void KT_RexFloorSwitch_update(GameObject* obj)
{
    KtrexfloorswitchPlacement* placement = (KtrexfloorswitchPlacement*)obj->anim.placementData;
    KtrexfloorswitchState* state = obj->extra;
    ObjTextureRuntimeSlot* tex;
    GameObject* player;
    int moved;
    u32 level;
    int scroll;
    Vec vecA;
    Vec vecB;
    f32 mtx[12];
    f32 height;
    f32 cx, cz, xLo, xHi, zLo, zHi;
    vecA = gKTrexFloorSwitchLocalEdgeZ;
    vecB = gKTrexFloorSwitchLocalEdgeX;
    obj->userData2 = obj->userData1;
    obj->userData1 = mainGetBit(placement->activeBit);
    tex = objFindTexture(obj, 0, 0);
    if (obj->userData1 <= 1) {
        tex->textureId = 0;
        if (obj->userData1 == 0 && obj->userData2 != 0) {
            state->flags |= KTREXFLOORSWITCH_FLAG_SINKING;
        }
        if (obj->userData1 != 0 && obj->userData2 == 0) {
            int curveId;
            int curveBits;
            state->flags |= KTREXFLOORSWITCH_FLAG_RISING;
            obj->anim.localPosY = placement->baseHeight - (f32)(u32)placement->sinkDepth;
            curveBits = mainGetBit(GAMEBIT_DR_KTrexPhaseCounter) >> 1;
            curveId = (*gRomCurveInterface)
                          ->find(((KtrexfloorswitchPlacement*)obj->anim.placementData)->curveX,
                                 ((KtrexfloorswitchPlacement*)obj->anim.placementData)->baseHeight,
                                 ((KtrexfloorswitchPlacement*)obj->anim.placementData)->curveZ,
                                 &gKTrexFloorSwitchCurveFindResult, 1, curveBits);
            if (curveId != -1)
            {
                RomCurvePathNode* curve = (RomCurvePathNode*)(*gRomCurveInterface)->getById(curveId);
                if (curve != NULL)
                {
                    obj->anim.localPosX = curve->x;
                    obj->anim.localPosZ = curve->z;
                }
            }
        }
        if ((state->flags & KTREXFLOORSWITCH_FLAG_MOVING) == 0)
        {
            return;
        }
    } else {
        if (obj->userData2 != 0) {
            tex->textureId = 0x100;
            state->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
        } else {
            int curveId;
            int curveBits;
            state->flags |= KTREXFLOORSWITCH_FLAG_RISING;
            obj->anim.localPosY = placement->baseHeight - (f32)(u32)placement->sinkDepth;
            curveBits = mainGetBit(GAMEBIT_DR_KTrexPhaseCounter) >> 1;
            curveId = (*gRomCurveInterface)
                          ->find(((KtrexfloorswitchPlacement*)obj->anim.placementData)->curveX,
                                 ((KtrexfloorswitchPlacement*)obj->anim.placementData)->baseHeight,
                                 ((KtrexfloorswitchPlacement*)obj->anim.placementData)->curveZ,
                                 &gKTrexFloorSwitchCurveFindResult, 1, curveBits);
            if (curveId != -1)
            {
                RomCurvePathNode* curve = (RomCurvePathNode*)(*gRomCurveInterface)->getById(curveId);
                if (curve != NULL)
                {
                    obj->anim.localPosX = curve->x;
                    obj->anim.localPosZ = curve->z;
                }
            }
        }
    }
    if ((state->graceTimer -= 1) < 0)
    {
        state->graceTimer = 0;
    }
    if (obj->anim.hitboxTransformState->contactObjectCount > 0 && obj->userData1 == 2) {
        player = Obj_GetPlayerObject();
        if (player != 0)
        {
            PSMTXRotRad((MtxPtr)mtx, 'y', (f32)(3.142 * (f64)obj->anim.rotX / 32768.0));
            PSMTXMultVecSR((MtxPtr)mtx, &vecA, &vecA);
            PSMTXMultVecSR((MtxPtr)mtx, &vecB, &vecB);
            cx = obj->anim.localPosX;
            xLo = cx;
            xHi = vecB.x + (cx + vecA.x);
            if (xHi < xLo)
            {
                f32 t = xHi;
                xHi = xLo;
                xLo = t;
            }
            cz = obj->anim.localPosZ;
            zLo = cz;
            zHi = vecB.z + (cz + vecA.z);
            if (zHi < zLo)
            {
                f32 t = zHi;
                zHi = zLo;
                zLo = t;
            }
            xLo += 5.0f;
            xHi -= 5.0f;
            zLo += 5.0f;
            zHi -= 5.0f;
            if (player->anim.localPosX >= xLo && player->anim.localPosX <= xHi && player->anim.localPosZ >= zLo &&
                player->anim.localPosZ <= zHi)
            {
                state->graceTimer = 5;
            }
        }
    }
    moved = 0;
    if ((state->flags & KTREXFLOORSWITCH_FLAG_SINKING) != 0)
    {
        height = placement->baseHeight -
                 (f32)(u32)placement->sinkDepth;
        if (obj->anim.localPosY > height) {
            obj->anim.localPosY = obj->anim.localPosY - 0.075f * timeDelta;
            if (obj->anim.localPosY <= height) {
                obj->anim.localPosY = height;
                state->flags &= ~KTREXFLOORSWITCH_FLAG_SINKING;
            } else {
                moved = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_MOVING, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((state->flags & KTREXFLOORSWITCH_FLAG_RISING) != 0)
    {
        if (obj->anim.localPosY < placement->baseHeight) {
            obj->anim.localPosY = 0.075f * timeDelta + obj->anim.localPosY;
            if (obj->anim.localPosY >= placement->baseHeight) {
                obj->anim.localPosY = placement->baseHeight;
                state->flags &= ~KTREXFLOORSWITCH_FLAG_RISING;
            } else {
                moved = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_MOVING, NULL, 2, -1, NULL);
            }
        }
    }
    else if (state->graceTimer != 0 &&
             (state->flags & KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED) == 0)
    {
        height = placement->baseHeight -
                 (f32)(u32)placement->retractDepth;
        if (obj->anim.localPosY > height) {
            obj->anim.localPosY = obj->anim.localPosY - 0.125f * timeDelta;
            if (obj->anim.localPosY < height) {
                obj->anim.localPosY = height;
            } else {
                moved = 1;
            }
        }
        if (state->chargeTimer < 0.0f)
        {
            state->chargeTimer =
                (f32)(u32)placement->chargeReload;
            level = mainGetBit(placement->levelBit) & 0xff;
            if (level < 0xf)
            {
                mainSetBits(placement->levelBit, (u8)(level += 1));
                if ((u8)level == 0xf)
                {
                    state->flags |= KTREXFLOORSWITCH_FLAG_CHARGED;
                }
            }
            else
            {
                state->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGED;
                state->flags |= KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
                mainSetBits(placement->levelBit, 0);
                if (mainGetBit(GAMEBIT_DR_KTrexPathA) != 0)
                {
                    mainSetBits(GAMEBIT_DR_KTrexPathA, 0);
                    mainSetBits(GAMEBIT_DR_KTrexPathB, 1);
                }
                else
                {
                    mainSetBits(GAMEBIT_DR_KTrexPathA, 1);
                    mainSetBits(GAMEBIT_DR_KTrexPathB, 0);
                }
                ktrexlevel_updatePathGameBits();
            }
        }
        state->chargeTimer -= timeDelta;
    }
    else
    {
        obj->anim.localPosY = 0.125f * timeDelta + obj->anim.localPosY;
        if (obj->anim.localPosY > placement->baseHeight) {
            obj->anim.localPosY = placement->baseHeight;
        } else {
            moved = 1;
        }
        if ((state->flags & KTREXFLOORSWITCH_FLAG_CHARGED) != 0)
        {
            if (state->chargeTimer < 0.0f)
            {
                state->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGED;
                state->flags |= KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
                mainSetBits(placement->levelBit, 0);
                if (mainGetBit(GAMEBIT_DR_KTrexPathA) != 0)
                {
                    mainSetBits(GAMEBIT_DR_KTrexPathA, 0);
                    mainSetBits(GAMEBIT_DR_KTrexPathB, 1);
                }
                else
                {
                    mainSetBits(GAMEBIT_DR_KTrexPathA, 1);
                    mainSetBits(GAMEBIT_DR_KTrexPathB, 0);
                }
                ktrexlevel_updatePathGameBits();
            }
            state->chargeTimer -= timeDelta;
        }
    }
    if ((state->flags & KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED) == 0 &&
        state->prevGraceTimer != state->graceTimer)
    {
        mainGetBit(placement->levelBit);
        mainSetBits(placement->levelBit, 0);
    }
    if ((s8)moved != 0 && gKTrexFloorSwitchPrevMoved == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_birdymornin11);
    }
    gKTrexFloorSwitchPrevMoved = (s8)moved;
    if (obj->userData1 == 2) {
        if (state->graceTimer != 0)
        {
            if (state->scrollSpeed == 0.0f)
            {
                state->scrollSpeed = 8.0f;
            }
            scroll = (int)(timeDelta * state->scrollSpeed + tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x200 - (scroll - 0x200);
                state->scrollSpeed = -state->scrollSpeed;
            }
            else if (scroll < 0x100)
            {
                scroll = 0x200 - scroll;
                state->scrollSpeed = -state->scrollSpeed;
            }
            tex->textureId = scroll;
        }
        else
        {
            scroll = (int)(timeDelta * state->scrollSpeed + tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x200 - (scroll - 0x200);
                state->scrollSpeed = -state->scrollSpeed;
            }
            else if (scroll < 0x100)
            {
                scroll = 0x100;
                state->scrollSpeed = 0.0f;
            }
            tex->textureId = scroll;
        }
        if ((state->flags & KTREXFLOORSWITCH_FLAG_MOVING) == 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_SETTLED, NULL, 2, -1, NULL);
        }
    } else {
        if (tex->textureId != 0)
        {
            scroll = (int)(timeDelta * state->scrollSpeed + tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x200 - (scroll - 0x200);
                state->scrollSpeed = -state->scrollSpeed;
            }
            else if (scroll < 0x100)
            {
                scroll = 0;
            }
            tex->textureId = scroll;
        }
    }
    state->prevGraceTimer = state->graceTimer;
}

void KT_RexFloorSwitch_init(GameObject* obj, const KtrexfloorswitchPlacement* placement)
{
    KtrexfloorswitchState* extra = obj->extra;
    int curveId;
    RomCurvePathNode* curve;
    obj->anim.rotX = (s16)(placement->rotByte << 8);
    extra->chargeTimer = (f32)(u32)placement->chargeReload;
    obj->userData1 = 1;
    obj->userData2 = 1;
    {
        KtrexfloorswitchPlacement* pl = (KtrexfloorswitchPlacement*)obj->anim.placementData;
        curveId = (*gRomCurveInterface)->find(
            pl->curveX, pl->baseHeight, pl->curveZ, &gKTrexFloorSwitchCurveFindResult, 1, 0);
    }
    if (curveId != -1)
    {
        curve = (RomCurvePathNode*)(*gRomCurveInterface)->getById(curveId);
        if (curve != NULL)
        {
            obj->anim.localPosX = curve->x;
            obj->anim.localPosZ = curve->z;
        }
    }
}

void KT_RexFloorSwitch_release(void)
{
}

void KT_RexFloorSwitch_initialise(void)
{
}

ObjectDescriptor gKtRexFloorSwitchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_initialise,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_release,
    0,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_init,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_update,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_hitDetect,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_render,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_free,
    (ObjectDescriptorCallback)KT_RexFloorSwitch_getObjectTypeId,
    KT_RexFloorSwitch_getExtraSize,
};
