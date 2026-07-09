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
 *
 * spawnEnergyArc is a shared helper invoked by ktlazerwall with ITS object
 * (so 'runtime' there overlays KtlazerwallState, where 0x10 is the bolt
 * pointer - distinct from this object's flags byte at the same offset).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/dll/DR/dll_0251_ktrexfloorswitch.h"

/* KtrexfloorswitchState.flags (offset 0x10) bits */
#define KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED 0x1 /* charge cycle maxed+reset; suppresses charging until reactivation */
#define KTREXFLOORSWITCH_FLAG_RISING        0x2 /* plate rising back up to baseHeight */
#define KTREXFLOORSWITCH_FLAG_SINKING       0x4 /* plate sinking down to baseHeight - sinkDepth */
#define KTREXFLOORSWITCH_FLAG_CHARGED       0x8 /* charge level reached max (0xf) */
#define KTREXFLOORSWITCH_FLAG_MOVING        (KTREXFLOORSWITCH_FLAG_RISING | KTREXFLOORSWITCH_FLAG_SINKING) /* 0x6 */

/* Partfx spawned while the plate moves vs after it settles. */
#define KTREXFLOORSWITCH_PARTFX_MOVING  0x488 /* emitted each frame the plate is actively rising/sinking */
#define KTREXFLOORSWITCH_PARTFX_SETTLED 0x486 /* emitted once the plate has stopped moving */

void KT_RexFloorSwitch_free(void)
{
}

int KT_RexFloorSwitch_getExtraSize(void)
{
    return 0x14;
}

int KT_RexFloorSwitch_getObjectTypeId(void)
{
    return 0x0;
}

void KT_RexFloorSwitch_hitDetect(void)
{
}

void KT_RexFloorSwitch_initialise(void)
{
}

void KT_RexFloorSwitch_release(void)
{
}

void KT_RexFloorSwitch_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6858);
    }
}

void KT_RexFloorSwitch_init(struct GameObject *obj, char* placement)
{
    char* extra = ((GameObject*)obj)->extra;
    int curve;
    ((GameObject*)obj)->anim.rotX = (s16)(((KtrexfloorswitchPlacement*)placement)->rotByte << 8);
    ((KtrexfloorswitchState*)extra)->chargeTimer = (f32)(u32)((KtrexfloorswitchPlacement*)placement)->chargeReload;
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->unkF8 = 1;
    {
        KtrexfloorswitchPlacement* pl = (KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData;
        curve = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
            pl->curveX, pl->baseHeight, pl->curveZ, &gKTrexFloorSwitchCurveFindResult, 1, 0);
    }
    if (curve != -1)
    {
        curve = (int)(*gRomCurveInterface)->getById(curve);
        if ((u32)curve != 0)
        {
            ((GameObject*)obj)->anim.localPosX = *(f32*)(curve + 0x8);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)(curve + 0x10);
        }
    }
}

void ktrexfloorswitch_spawnEnergyArc(int obj, f32 scale, int angle)
{
    KtrexfloorswitchSpawnEnergyArcState* runtime = ((GameObject*)obj)->extra;
    f32 pos[3];
    f32 dir[3];
    if (runtime->boltObj != 0)
    {
        mm_free(runtime->boltObj);
        runtime->boltObj = 0;
    }
    pos[0] = ((GameObject*)obj)->anim.localPosX;
    pos[1] = ((GameObject*)obj)->anim.localPosY;
    pos[2] = ((GameObject*)obj)->anim.localPosZ;
    dir[0] = lbl_803E6898;
    {
        f32 fr = angle;
        fr = fr * runtime->angleScale;
        dir[1] = -(fr * lbl_803E689C);
    }
    dir[2] = scale;
    vecRotateZXY(obj, dir);
    dir[0] += ((GameObject*)obj)->anim.localPosX;
    dir[1] += ((GameObject*)obj)->anim.localPosY;
    dir[2] += ((GameObject*)obj)->anim.localPosZ;
    runtime->unk8 = (f32)(int)randomGetRange(10, angle);
    runtime->boltObj = lightningCreate(pos, dir, lbl_803E68A0, lbl_803E68A4, angle, 96, 0);
}

void KT_RexFloorSwitch_update(int obj)
{
    int* placement = *(int**)&((GameObject*)obj)->anim.placementData;
    int* state = ((GameObject*)obj)->extra;
    ObjTextureRuntimeSlot* tex;
    int* player;
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
    ((GameObject*)obj)->unkF8 = ((GameObject*)obj)->unkF4;
    ((GameObject*)obj)->unkF4 = mainGetBit(((KtrexfloorswitchPlacement*)placement)->activeBit);
    tex = objFindTexture((void*)obj, 0, 0);
    if (((GameObject*)obj)->unkF4 <= 1)
    {
        tex->textureId = 0;
        if (((GameObject*)obj)->unkF4 == 0 && ((GameObject*)obj)->unkF8 != 0)
        {
            ((KtrexfloorswitchState*)state)->flags |= KTREXFLOORSWITCH_FLAG_SINKING;
        }
        if (((GameObject*)obj)->unkF4 != 0 && ((GameObject*)obj)->unkF8 == 0)
        {
            int curveId;
            int curveBits;
            ((KtrexfloorswitchState*)state)->flags |= KTREXFLOORSWITCH_FLAG_RISING;
            ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                                                 (f32)(u32)((KtrexfloorswitchPlacement*)placement)->sinkDepth;
            curveBits = mainGetBit(GAMEBIT_DR_KTrexPhaseCounter) >> 1;
            curveId = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
                ((KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData)->curveX,
                ((KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData)->baseHeight,
                ((KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData)->curveZ,
                &gKTrexFloorSwitchCurveFindResult, 1, curveBits);
            if (curveId != -1)
            {
                void* curve = (*gRomCurveInterface)->getById(curveId);
                if (curve != NULL)
                {
                    ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)curve + 0x8);
                    ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)curve + 0x10);
                }
            }
        }
        if ((((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_MOVING) == 0)
        {
            return;
        }
    }
    else
    {
        if (((GameObject*)obj)->unkF8 != 0)
        {
            tex->textureId = 0x100;
            ((KtrexfloorswitchState*)state)->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
        }
        else
        {
            int curveId;
            int curveBits;
            ((KtrexfloorswitchState*)state)->flags |= KTREXFLOORSWITCH_FLAG_RISING;
            ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                                                 (f32)(u32)((KtrexfloorswitchPlacement*)placement)->sinkDepth;
            curveBits = mainGetBit(GAMEBIT_DR_KTrexPhaseCounter) >> 1;
            curveId = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
                ((KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData)->curveX,
                ((KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData)->baseHeight,
                ((KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData)->curveZ,
                &gKTrexFloorSwitchCurveFindResult, 1, curveBits);
            if (curveId != -1)
            {
                void* curve = (*gRomCurveInterface)->getById(curveId);
                if (curve != NULL)
                {
                    ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)curve + 0x8);
                    ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)curve + 0x10);
                }
            }
        }
    }
    if ((s8)(((KtrexfloorswitchState*)state)->graceTimer -= 1) < 0)
    {
        ((KtrexfloorswitchState*)state)->graceTimer = 0;
    }
    if ((s8) * (s8*)(*(int*)((char*)obj + 0x58) + 0x10f) > 0 && ((GameObject*)obj)->unkF4 == 2)
    {
        player = Obj_GetPlayerObject();
        if (player != 0)
        {
            PSMTXRotRad(
                mtx, 0x79,
                (f32)(gKTrexFloorSwitchPi * (f64)((GameObject*)obj)->anim.rotX / gKTrexFloorSwitchBamHalfCircle));
            PSMTXMultVecSR(mtx, vecA, vecA);
            PSMTXMultVecSR(mtx, vecB, vecB);
            cx = ((GameObject*)obj)->anim.localPosX;
            xLo = cx;
            xHi = vecB[0] + (cx + vecA[0]);
            if (xHi < xLo)
            {
                f32 t = xHi;
                xHi = xLo;
                xLo = t;
            }
            cz = ((GameObject*)obj)->anim.localPosZ;
            zLo = cz;
            zHi = vecB[2] + (cz + vecA[2]);
            if (zHi < zLo)
            {
                f32 t = zHi;
                zHi = zLo;
                zLo = t;
            }
            xLo += gKTrexFloorSwitchTriggerBoxInset;
            xHi -= gKTrexFloorSwitchTriggerBoxInset;
            zLo += gKTrexFloorSwitchTriggerBoxInset;
            zHi -= gKTrexFloorSwitchTriggerBoxInset;
            if (((GameObject*)player)->anim.localPosX >= xLo && ((GameObject*)player)->anim.localPosX <= xHi &&
                ((GameObject*)player)->anim.localPosZ >= zLo && ((GameObject*)player)->anim.localPosZ <= zHi)
            {
                ((KtrexfloorswitchState*)state)->graceTimer = 5;
            }
        }
    }
    moved = 0;
    if ((((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_SINKING) != 0)
    {
        height = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                 (f32)(u32)((KtrexfloorswitchPlacement*)placement)->sinkDepth;
        if (((GameObject*)obj)->anim.localPosY > height)
        {
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.localPosY - gKTrexFloorSwitchRiseSpeed * timeDelta;
            if (((GameObject*)obj)->anim.localPosY <= height)
            {
                ((GameObject*)obj)->anim.localPosY = height;
                ((KtrexfloorswitchState*)state)->flags &= ~KTREXFLOORSWITCH_FLAG_SINKING;
            }
            else
            {
                moved = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_MOVING, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_RISING) != 0)
    {
        if (((GameObject*)obj)->anim.localPosY < ((KtrexfloorswitchPlacement*)placement)->baseHeight)
        {
            ((GameObject*)obj)->anim.localPosY =
                gKTrexFloorSwitchRiseSpeed * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY >= ((KtrexfloorswitchPlacement*)placement)->baseHeight)
            {
                ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight;
                ((KtrexfloorswitchState*)state)->flags &= ~KTREXFLOORSWITCH_FLAG_RISING;
            }
            else
            {
                moved = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_MOVING, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((s8)((KtrexfloorswitchState*)state)->graceTimer != 0 &&
             (((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED) == 0)
    {
        height = ((KtrexfloorswitchPlacement*)placement)->baseHeight -
                 (f32)(u32)((KtrexfloorswitchPlacement*)placement)->retractDepth;
        if (((GameObject*)obj)->anim.localPosY > height)
        {
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.localPosY - gKTrexFloorSwitchRetractSpeed * timeDelta;
            if (((GameObject*)obj)->anim.localPosY < height)
            {
                ((GameObject*)obj)->anim.localPosY = height;
            }
            else
            {
                moved = 1;
            }
        }
        if (((KtrexfloorswitchState*)state)->chargeTimer < lbl_803E687C)
        {
            ((KtrexfloorswitchState*)state)->chargeTimer =
                (f32)(u32)((KtrexfloorswitchPlacement*)placement)->chargeReload;
            level = mainGetBit(((KtrexfloorswitchPlacement*)placement)->levelBit) & 0xff;
            if (level < 0xf)
            {
                mainSetBits(((KtrexfloorswitchPlacement*)placement)->levelBit, (u8)(level += 1));
                if ((u8)level == 0xf)
                {
                    ((KtrexfloorswitchState*)state)->flags |= KTREXFLOORSWITCH_FLAG_CHARGED;
                }
            }
            else
            {
                ((KtrexfloorswitchState*)state)->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGED;
                ((KtrexfloorswitchState*)state)->flags |= KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
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
        ((KtrexfloorswitchState*)state)->chargeTimer -= timeDelta;
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY =
            gKTrexFloorSwitchRetractSpeed * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY > ((KtrexfloorswitchPlacement*)placement)->baseHeight)
        {
            ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)placement)->baseHeight;
        }
        else
        {
            moved = 1;
        }
        if ((((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_CHARGED) != 0)
        {
            if (((KtrexfloorswitchState*)state)->chargeTimer < lbl_803E687C)
            {
                ((KtrexfloorswitchState*)state)->flags &= ~KTREXFLOORSWITCH_FLAG_CHARGED;
                ((KtrexfloorswitchState*)state)->flags |= KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED;
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
            ((KtrexfloorswitchState*)state)->chargeTimer -= timeDelta;
        }
    }
    if ((((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_CHARGE_LOCKED) == 0 &&
        (s8)((KtrexfloorswitchState*)state)->prevGraceTimer != (s8)((KtrexfloorswitchState*)state)->graceTimer)
    {
        mainGetBit(((KtrexfloorswitchPlacement*)placement)->levelBit);
        mainSetBits(((KtrexfloorswitchPlacement*)placement)->levelBit, 0);
    }
    if ((s8)moved != 0 && gKTrexFloorSwitchPrevMoved == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_birdymornin11);
    }
    gKTrexFloorSwitchPrevMoved = (s8)moved;
    if (((GameObject*)obj)->unkF4 == 2)
    {
        if ((s8)((KtrexfloorswitchState*)state)->graceTimer != 0)
        {
            if (lbl_803E687C == ((KtrexfloorswitchState*)state)->scrollSpeed)
            {
                ((KtrexfloorswitchState*)state)->scrollSpeed = gKTrexFloorSwitchScrollSpeed;
            }
            scroll = (int)(timeDelta * ((KtrexfloorswitchState*)state)->scrollSpeed + tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x200 - (scroll - 0x200);
                ((KtrexfloorswitchState*)state)->scrollSpeed = -((KtrexfloorswitchState*)state)->scrollSpeed;
            }
            else if (scroll < 0x100)
            {
                scroll = 0x200 - scroll;
                ((KtrexfloorswitchState*)state)->scrollSpeed = -((KtrexfloorswitchState*)state)->scrollSpeed;
            }
            tex->textureId = scroll;
        }
        else
        {
            scroll = (int)(timeDelta * ((KtrexfloorswitchState*)state)->scrollSpeed + tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x200 - (scroll - 0x200);
                ((KtrexfloorswitchState*)state)->scrollSpeed = -((KtrexfloorswitchState*)state)->scrollSpeed;
            }
            else if (scroll < 0x100)
            {
                scroll = 0x100;
                ((KtrexfloorswitchState*)state)->scrollSpeed = lbl_803E687C;
            }
            tex->textureId = scroll;
        }
        if ((((KtrexfloorswitchState*)state)->flags & KTREXFLOORSWITCH_FLAG_MOVING) == 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, KTREXFLOORSWITCH_PARTFX_SETTLED, NULL, 2, -1, NULL);
        }
    }
    else
    {
        if (tex->textureId != 0)
        {
            scroll = (int)(timeDelta * ((KtrexfloorswitchState*)state)->scrollSpeed + tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x200 - (scroll - 0x200);
                ((KtrexfloorswitchState*)state)->scrollSpeed = -((KtrexfloorswitchState*)state)->scrollSpeed;
            }
            else if (scroll < 0x100)
            {
                scroll = 0;
            }
            tex->textureId = scroll;
        }
    }
    ((KtrexfloorswitchState*)state)->prevGraceTimer = ((KtrexfloorswitchState*)state)->graceTimer;
}
