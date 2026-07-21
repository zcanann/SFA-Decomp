/*
 * ktrexfloorswitch (DLL 0x251) - a stompable floor plate in the T-rex
 * (Galdon) arena that the player charges by standing on it.
 *
 * Its placement game bit (activeBit) gates three behaviours: standing on
 * the plate runs the charge timer up, raising a per-step level bit each
 * tick; once the level maxes out it flips the path-selection game bits
 * (0x55a/0x55b) and tells ktrexlevel to update the branch path. The plate
 * mesh rises/lowers between configured heights via curve-lookups (the rom
 * curve interface) and animates its texture scroll + particle/sfx cues.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/DR/dll_0251_ktrexfloorswitch.h"

#include "dolphin/mtx/mtx_legacy.h"
#include "main/newclouds.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/DR/dll_024F_ktrexlevel.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"

int gKTrexFloorSwitchPrevMoved;

const f32 lbl_802C2560[3] = {0.0f, 0.0f, 55.0f};
const f32 lbl_802C256C[3] = {55.0f, 0.0f, 0.0f};
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
    int* placement = *(int**)&(obj)->anim.placementData;
    KtrexfloorswitchState* state = (obj)->extra;
    ObjTextureRuntimeSlot* tex;
    GameObject* player;
    int moved;
    u32 level;
    int scroll;
    f32 vecA[3];
    f32 vecB[3];
    f32 mtx[12];
    f32 height;
    f32 cx, cz, xLo, xHi, zLo, zHi;
    *(Vec3Blob*)vecA = *(Vec3Blob*)lbl_802C2560;
    *(Vec3Blob*)vecB = *(Vec3Blob*)lbl_802C256C;
    (obj)->userData2 = (obj)->userData1;
    (obj)->userData1 = mainGetBit(((KtrexfloorswitchPlacement*)placement)->activeBit);
    tex = objFindTexture(obj, 0, 0);
    if ((obj)->userData1 <= 1)
    {
        tex->textureId = 0;
        if ((obj)->userData1 == 0 && (obj)->userData2 != 0)
        {
            state->flags |= KTREXFLOORSWITCH_FLAG_SINKING;
        }
        if ((obj)->userData1 != 0 && (obj)->userData2 == 0)
        {
            int curveId;
            int curveBits;
            state->flags |= KTREXFLOORSWITCH_FLAG_RISING;
            (obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                                    (f32)(u32)((KtrexfloorswitchPlacement*)placement)->sinkDepth;
            curveBits = mainGetBit(GAMEBIT_DR_KTrexPhaseCounter) >> 1;
            curveId = (*gRomCurveInterface)->find(
                ((KtrexfloorswitchPlacement*)*(int*)&(obj)->anim.placementData)->curveX,
                ((KtrexfloorswitchPlacement*)*(int*)&(obj)->anim.placementData)->baseHeight,
                ((KtrexfloorswitchPlacement*)*(int*)&(obj)->anim.placementData)->curveZ,
                &gKTrexFloorSwitchCurveFindResult, 1, curveBits);
            if (curveId != -1)
            {
                void* curve = (*gRomCurveInterface)->getById(curveId);
                if (curve != NULL)
                {
                    (obj)->anim.localPosX = *(f32*)((char*)curve + 0x8);
                    (obj)->anim.localPosZ = *(f32*)((char*)curve + 0x10);
                }
            }
        }
        if ((state->flags & KTREXFLOORSWITCH_FLAG_MOVING) == 0)
        {
            return;
        }
    }
    else
    {
        if ((obj)->userData2 != 0)
        {
            tex->textureId = 0x100;
            state->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
        }
        else
        {
            int curveId;
            int curveBits;
            state->flags |= KTREXFLOORSWITCH_FLAG_RISING;
            (obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                                    (f32)(u32)((KtrexfloorswitchPlacement*)placement)->sinkDepth;
            curveBits = mainGetBit(GAMEBIT_DR_KTrexPhaseCounter) >> 1;
            curveId = (*gRomCurveInterface)->find(
                ((KtrexfloorswitchPlacement*)*(int*)&(obj)->anim.placementData)->curveX,
                ((KtrexfloorswitchPlacement*)*(int*)&(obj)->anim.placementData)->baseHeight,
                ((KtrexfloorswitchPlacement*)*(int*)&(obj)->anim.placementData)->curveZ,
                &gKTrexFloorSwitchCurveFindResult, 1, curveBits);
            if (curveId != -1)
            {
                void* curve = (*gRomCurveInterface)->getById(curveId);
                if (curve != NULL)
                {
                    (obj)->anim.localPosX = *(f32*)((char*)curve + 0x8);
                    (obj)->anim.localPosZ = *(f32*)((char*)curve + 0x10);
                }
            }
        }
    }
    if ((s8)(state->graceTimer -= 1) < 0)
    {
        state->graceTimer = 0;
    }
    if ((s8) * (s8*)(*(int*)((char*)obj + 0x58) + 0x10f) > 0 && (obj)->userData1 == 2)
    {
        player = Obj_GetPlayerObject();
        if (player != 0)
        {
            PSMTXRotRad(mtx, 0x79, (f32)(3.142 * (f64)(obj)->anim.rotX / 32768.0));
            PSMTXMultVecSR(mtx, vecA, vecA);
            PSMTXMultVecSR(mtx, vecB, vecB);
            cx = (obj)->anim.localPosX;
            xLo = cx;
            xHi = vecB[0] + (cx + vecA[0]);
            if (xHi < xLo)
            {
                f32 t = xHi;
                xHi = xLo;
                xLo = t;
            }
            cz = (obj)->anim.localPosZ;
            zLo = cz;
            zHi = vecB[2] + (cz + vecA[2]);
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
        height = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                 (f32)(u32)((KtrexfloorswitchPlacement*)placement)->sinkDepth;
        if ((obj)->anim.localPosY > height)
        {
            (obj)->anim.localPosY = (obj)->anim.localPosY - 0.075f * timeDelta;
            if ((obj)->anim.localPosY <= height)
            {
                (obj)->anim.localPosY = height;
                state->flags &= ~KTREXFLOORSWITCH_FLAG_SINKING;
            }
            else
            {
                moved = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_MOVING, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((state->flags & KTREXFLOORSWITCH_FLAG_RISING) != 0)
    {
        if ((obj)->anim.localPosY < ((KtrexfloorswitchPlacement*)placement)->baseHeight)
        {
            (obj)->anim.localPosY = 0.075f * timeDelta + (obj)->anim.localPosY;
            if ((obj)->anim.localPosY >= ((KtrexfloorswitchPlacement*)placement)->baseHeight)
            {
                (obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight;
                state->flags &= ~KTREXFLOORSWITCH_FLAG_RISING;
            }
            else
            {
                moved = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_MOVING, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((s8)state->graceTimer != 0 &&
             (state->flags & KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED) == 0)
    {
        height = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                 (f32)(u32)((KtrexfloorswitchPlacement*)placement)->retractDepth;
        if ((obj)->anim.localPosY > height)
        {
            (obj)->anim.localPosY = (obj)->anim.localPosY - 0.125f * timeDelta;
            if ((obj)->anim.localPosY < height)
            {
                (obj)->anim.localPosY = height;
            }
            else
            {
                moved = 1;
            }
        }
        if (state->chargeTimer < 0.0f)
        {
            state->chargeTimer =
                (f32)(u32)((KtrexfloorswitchPlacement*)placement)->chargeReload;
            level = mainGetBit(((KtrexfloorswitchPlacement*)placement)->levelBit) & 0xff;
            if (level < 0xf)
            {
                mainSetBits(((KtrexfloorswitchPlacement*)placement)->levelBit, (u8)(level += 1));
                if ((u8)level == 0xf)
                {
                    state->flags |= KTREXFLOORSWITCH_FLAG_CHARGED;
                }
            }
            else
            {
                state->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGED;
                state->flags |= KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
                mainSetBits(((KtrexfloorswitchPlacement*)placement)->levelBit, 0);
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
        (obj)->anim.localPosY = 0.125f * timeDelta + (obj)->anim.localPosY;
        if ((obj)->anim.localPosY > ((KtrexfloorswitchPlacement*)placement)->baseHeight)
        {
            (obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight;
        }
        else
        {
            moved = 1;
        }
        if ((state->flags & KTREXFLOORSWITCH_FLAG_CHARGED) != 0)
        {
            if (state->chargeTimer < 0.0f)
            {
                state->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGED;
                state->flags |= KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
                mainSetBits(((KtrexfloorswitchPlacement*)placement)->levelBit, 0);
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
        (s8)state->prevGraceTimer != (s8)state->graceTimer)
    {
        mainGetBit(((KtrexfloorswitchPlacement*)placement)->levelBit);
        mainSetBits(((KtrexfloorswitchPlacement*)placement)->levelBit, 0);
    }
    if ((s8)moved != 0 && gKTrexFloorSwitchPrevMoved == 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_birdymornin11);
    }
    gKTrexFloorSwitchPrevMoved = (s8)moved;
    if ((obj)->userData1 == 2)
    {
        if ((s8)state->graceTimer != 0)
        {
            if (0.0f == state->scrollSpeed)
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
    }
    else
    {
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

void KT_RexFloorSwitch_init(GameObject* obj, char* placement)
{
    KtrexfloorswitchState* extra = obj->extra;
    int curve;
    obj->anim.rotX = (s16)(((KtrexfloorswitchPlacement*)placement)->rotByte << 8);
    extra->chargeTimer = (f32)(u32)((KtrexfloorswitchPlacement*)placement)->chargeReload;
    obj->userData1 = 1;
    obj->userData2 = 1;
    {
        KtrexfloorswitchPlacement* pl = (KtrexfloorswitchPlacement*)*(int*)&obj->anim.placementData;
        curve = (*gRomCurveInterface)->find(
            pl->curveX, pl->baseHeight, pl->curveZ, &gKTrexFloorSwitchCurveFindResult, 1, 0);
    }
    if (curve != -1)
    {
        curve = (int)(*gRomCurveInterface)->getById(curve);
        if ((u32)curve != 0)
        {
            obj->anim.localPosX = *(f32*)(curve + 0x8);
            obj->anim.localPosZ = *(f32*)(curve + 0x10);
        }
    }
}

void KT_RexFloorSwitch_release(void)
{
}

void KT_RexFloorSwitch_initialise(void)
{
}
