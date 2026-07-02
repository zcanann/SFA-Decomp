/*
 * drbarrelgr (DLL 0x283) - a barrel-grabber: a magnet/tractor device
 * that pulls a nearby gunpowder barrel to itself and carries it along a
 * rom-curve path.
 *
 * update is a small state machine (mode in state->mode): mode 0 scans
 * group 25 for a grabbable barrel in range/below it and locks on (mode
 * 4); mode 4 drags the held barrel toward the grab point and, once close,
 * marks it held; mode 5 follows the rom curve at a speed derived from the
 * placement speed; mode 2 ramps the carry speed; modes 1/3 release. A
 * placement game bit (0x20) gates the whole device. init clamps the
 * placement speed/range defaults, seeds the curve and start position,
 * and render draws the device, its path light pulses and the held barrel.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_trigger_ids.h"

#define DRBARRELGR_OBJFLAG_RENDERED 0x800

typedef struct DrbarrelgrPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 spawnYawByte; /* 0x18 */
    u8 speed;        /* 0x19: carry speed (defaults to 0xa) */
    s16 range;       /* 0x1A: grab range (defaults to 0x64) */
    u8 pad1C[0x20 - 0x1C];
    s16 gameBit;     /* 0x20: gates the device, -1 = always on */
    u8 pad22[0x28 - 0x22];
} DrbarrelgrPlacement;


typedef struct DrbarrelgrState
{
    s32 mode;          /* 0x00: state-machine mode */
    s32 prevMode;      /* 0x04: previous mode */
    s32 heldBarrel;    /* 0x08: barrel object currently grabbed, or 0 */
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 grabX;         /* 0x14 */
    f32 grabY;         /* 0x18 */
    f32 grabZ;         /* 0x1C */
    u8 pad20[0x88 - 0x20];
    f32 startPosX;     /* 0x88 */
    f32 startPosY;     /* 0x8C */
    f32 startPosZ;     /* 0x90 */
    u8 pad94[0x128 - 0x94];
    s16 carrySpeed;    /* 0x128: working carry speed */
    u8 pad12A[0x12C - 0x12A];
} DrbarrelgrState;

STATIC_ASSERT(offsetof(DrbarrelgrState, heldBarrel) == 0x8);
STATIC_ASSERT(offsetof(DrbarrelgrState, grabX) == 0x14);
STATIC_ASSERT(offsetof(DrbarrelgrState, startPosX) == 0x88);
STATIC_ASSERT(offsetof(DrbarrelgrState, carrySpeed) == 0x128);
STATIC_ASSERT(sizeof(DrbarrelgrState) == 0x12C);


int drbarrelgr_getExtraSize(void) { return 0x12c; }

int drbarrelgr_getObjectTypeId(void) { return 0; }

void drbarrelgr_free(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    void* heldObj = *(void**)&((DrbarrelgrState*)state)->heldBarrel;

    if (heldObj != NULL)
    {
        gunpowderbarrel_clearHeldState((int)heldObj);
        ((DrBarrelGrFlags*)(state + 0x12a))->bit80 = 0;
    }
}

void drbarrelgr_hitDetect(void)
{
}

void drbarrelgr_release(void)
{
}

void drbarrelgr_initialise(void)
{
}

void drbarrelgr_init(int obj, int setup)
{
    int one;
    int state;

    one = 1;
    state = *(int*)&((GameObject*)obj)->extra;
    if (((DrbarrelgrPlacement*)setup)->speed == 0)
    {
        ((DrbarrelgrPlacement*)setup)->speed = 0xa;
    }
    if (((DrbarrelgrPlacement*)setup)->range <= 0)
    {
        ((DrbarrelgrPlacement*)setup)->range = 0x64;
    }
    ((DrbarrelgrState*)state)->mode = 5;
    ((DrbarrelgrState*)state)->heldBarrel = 0;
    ((DrBarrelGrFlags*)(state + 0x12a))->bit80 = 0;
    ((DrbarrelgrState*)state)->carrySpeed = ((DrbarrelgrPlacement*)setup)->speed;
    ((DrbarrelgrState*)state)->unk10 = lbl_803E6CA4;
    ((DrbarrelgrState*)state)->prevMode = -3;
    ((DrBarrelGrFlags*)(state + 0x12a))->bit40 = 0;
    storeZeroToFloatParam((void*)(state + 0xc));
    s16toFloat((void*)(state + 0xc), ((DrbarrelgrPlacement*)setup)->range);
    ((GameObject*)obj)->anim.rotX = (s16)((s8)((DrbarrelgrPlacement*)setup)->spawnYawByte << 8);
    (*gRomCurveInterface)->initCurve((void*)(state + 0x20), (void*)obj, lbl_803E6CD0, &one, 0);
    ((GameObject*)obj)->anim.localPosX = ((DrbarrelgrState*)state)->startPosX;
    ((GameObject*)obj)->anim.localPosZ = ((DrbarrelgrState*)state)->startPosZ;
    ((GameObject*)obj)->anim.localPosY = ((DrbarrelgrState*)state)->startPosY;
}

#pragma scheduling off
void drbarrelgr_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    int newMode = -1;
    DrBarrelGrFlags* flags = (DrBarrelGrFlags*)(state + 0x12a);
    int nearest;
    int match;
    int gameBit;
    f32 vec[3];
    f32 tmp[3];

    {
        int held = ((DrbarrelgrState*)state)->heldBarrel;
        if ((void*)held != NULL)
        {
            nearest = ObjGroup_FindNearestObject(25, obj, 0);
            match = 0;
            if ((u32)nearest != 0 && (u32)held == nearest)
            {
                match = 1;
            }
            if (match == 0 ||
                (flags->bit80 != 0 && gunpowderbarrel_isHeld(((DrbarrelgrState*)state)->heldBarrel) == 0))
            {
                ((DrbarrelgrState*)state)->heldBarrel = 0;
                flags->bit80 = 0;
            }
        }
    }

    gameBit = ((DrbarrelgrPlacement*)setup)->gameBit;
    if (gameBit != -1 && GameBit_Get(gameBit) == 0)
    {
        flags->bit40 = 0;
        return;
    }
    flags->bit40 = 1;
    Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_bcrek1_c);

    switch (((DrbarrelgrState*)state)->mode)
    {
    case 0:
        if (*(void**)&((DrbarrelgrState*)state)->heldBarrel == 0)
        {
            nearest = ObjGroup_FindNearestObject(25, obj, 0);
            if ((u32)nearest != 0 &&
                Vec_xzDistance(obj + 24, nearest + 24) < gDrBarrelGenGrabRange &&
                ((GameObject*)nearest)->anim.localPosY < ((GameObject*)obj)->anim.localPosY)
            {
                vec[0] = ((GameObject*)nearest)->anim.localPosX;
                vec[1] = lbl_803E6CB4 + ((GameObject*)nearest)->anim.localPosY;
                vec[2] = ((GameObject*)nearest)->anim.localPosZ;
                if (voxmaps_traceWorldLine((void*)&((GameObject*)obj)->anim.localPosX, vec) != 0 &&
                    gunpowderbarrel_canBeGrabbed(nearest) != 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_jbike_snowspray);
                    newMode = 4;
                    ((DrbarrelgrState*)state)->heldBarrel = nearest;
                }
                break;
            }
        }
        if (timerCountDown((void*)(state + 12)) != 0)
        {
            newMode = 5;
        }
        break;
    case 4:
        if (*(void**)&((DrbarrelgrState*)state)->heldBarrel == 0 ||
            gunpowderbarrel_canBeGrabbed(((DrbarrelgrState*)state)->heldBarrel) == 0)
        {
            ((DrbarrelgrState*)state)->mode = 0;
            ((DrbarrelgrState*)state)->heldBarrel = 0;
            flags->bit80 = 0;
            break;
        }
        if (Vec_xzDistance(obj + 24, ((DrbarrelgrState*)state)->heldBarrel + 24) > gDrBarrelGenGrabRange)
        {
            newMode = ((DrbarrelgrState*)state)->prevMode;
            flags->bit80 = 0;
            ((DrbarrelgrState*)state)->heldBarrel = 0;
            break;
        }
        PSVECSubtract((void*)(state + 0x14),
                      (void*)&((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosX, tmp);
        if (tmp[0] != lbl_803E6CA4 || tmp[1] != lbl_803E6CA4 || tmp[2] != lbl_803E6CA4)
        {
            PSVECNormalize(tmp, tmp);
        }
        PSVECScale(tmp, tmp, lbl_803DC3B0);
        gunpowderbarrel_addThrowVelocity(((DrbarrelgrState*)state)->heldBarrel, tmp);
        if (PSVECDistance((void*)(state + 0x14),
                          (void*)&((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosX) < lbl_803E6CA0 ||
            ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosY > ((DrbarrelgrState*)state)->grabY)
        {
            Sfx_PlayFromObject((int)(GameObject*)obj, SFXTRIG_jbike_boost);
            gunpowderbarrel_setHeldState(((DrbarrelgrState*)state)->heldBarrel);
            newMode = ((DrbarrelgrState*)state)->prevMode;
            flags->bit80 = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        break;
    case 5:
        {
            f32 spd = gDrBarrelGenCarrySpeedScale * (f32)((DrbarrelgrState*)state)->carrySpeed;
            int r = Obj_UpdateRomCurveFollowVelocity(obj, state + 0x20,
                                                     spd * timeDelta,
                                                     lbl_803E6CBC, lbl_803E6CB4, 1);
            objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                    ((GameObject*)obj)->anim.velocityZ);
            if (r != 0)
            {
                newMode = r - 1;
                storeZeroToFloatParam((void*)(state + 12));
                s16toFloat((void*)(state + 12), ((DrbarrelgrPlacement*)setup)->range);
                {
                    f32 z = lbl_803E6CA4;
                    ((GameObject*)obj)->anim.velocityX = z;
                    ((GameObject*)obj)->anim.velocityY = z;
                    ((GameObject*)obj)->anim.velocityZ = z;
                }
            }
            break;
        }
    case 2:
        if (((DrbarrelgrState*)state)->carrySpeed == ((DrbarrelgrPlacement*)setup)->speed)
        {
            ((DrbarrelgrState*)state)->carrySpeed =
                (f32)((DrbarrelgrState*)state)->carrySpeed * lbl_803E6CA8;
        }
        else
        {
            ((DrbarrelgrState*)state)->carrySpeed = ((DrbarrelgrPlacement*)setup)->speed;
        }
        storeZeroToFloatParam((void*)(state + 12));
        newMode = 5;
        break;
    case 1:
        if (*(void**)&((DrbarrelgrState*)state)->heldBarrel != 0)
        {
            newMode = 3;
        }
        else if (timerCountDown((void*)(state + 12)) != 0)
        {
            newMode = 5;
        }
        break;
    case 3:
        if (*(void**)&((DrbarrelgrState*)state)->heldBarrel != 0)
        {
            gunpowderbarrel_clearHeldState(((DrbarrelgrState*)state)->heldBarrel);
            flags->bit80 = 0;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        ((DrbarrelgrState*)state)->heldBarrel = 0;
        newMode = ((DrbarrelgrState*)state)->prevMode;
        break;
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E6CC0, timeDelta, 0);
    if (newMode != -1 && newMode != ((DrbarrelgrState*)state)->mode)
    {
        ((DrbarrelgrState*)state)->prevMode = ((DrbarrelgrState*)state)->mode;
        ((DrbarrelgrState*)state)->mode = newMode;
    }
    if ((((GameObject*)obj)->objectFlags & DRBARRELGR_OBJFLAG_RENDERED) == 0 && *(void**)&((DrbarrelgrState*)state)->heldBarrel != 0)
    {
        ((DrbarrelgrState*)state)->grabX = ((GameObject*)obj)->anim.localPosX;
        ((DrbarrelgrState*)state)->grabY = ((GameObject*)obj)->anim.localPosY + gDrBarrelGenGrabYOffset;
        ((DrbarrelgrState*)state)->grabZ = ((GameObject*)obj)->anim.localPosZ;
        ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosX = ((DrbarrelgrState*)state)->grabX;
        ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosY = ((DrbarrelgrState*)state)->grabY;
        ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosZ = ((DrbarrelgrState*)state)->grabZ;
    }
}
#pragma scheduling reset

void drbarrelgr_render(int obj, int p2, int p3, int p4, int p5)
{
    f32* vp2;
    f32* vp1;
    f32* vp;
    int state = *(int*)&((GameObject*)obj)->extra;
    int objRef;
    int nearest;
    int match;
    int i;
    f32 dval;
    f32 vec[3];
    DrBarrelGrRenderParams params;
    extern void objfx_spawnLightPulse(int obj, f32 a, int b, int c, int d, f32 e, void* params);

    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CA0);
    ObjPath_GetPointWorldPosition(obj, 0, (f32*)(state + 0x14), (f32*)(state + 0x18),
                                  (f32*)(state + 0x1c), 0);
    params.a = 0;
    params.c = 0;
    params.b = 0x4000;
    i = 0;
    vp2 = &vec[2];
    vp1 = &vec[1];
    vp = &vec[0];
    dval = lbl_803E6CA4;
    for (; i < 4; i++)
    {
        ObjPath_GetPointWorldPosition(obj, i + 1, vp, vp1, vp2, 0);
        PSVECSubtract(vp, (void*)(obj + 0xc), vp);
        params.d = dval;
        objfx_spawnLightPulse(obj, lbl_803E6CA8, 3, 0, 0, lbl_803E6CAC, &params);
    }
    objRef = *(u32*)&((DrbarrelgrState*)state)->heldBarrel;
    if ((u32)objRef != 0)
    {
        nearest = ObjGroup_FindNearestObject(0x19, obj, 0);
        match = 0;
        if ((u32)nearest != 0 && (u32)objRef == nearest)
        {
            match = 1;
        }
        if (match && *(int*)state != 4)
        {
            ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosX = ((DrbarrelgrState*)state)->grabX;
            ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosY = ((DrbarrelgrState*)state)->grabY;
            ((GameObject*)((DrbarrelgrState*)state)->heldBarrel)->anim.localPosZ = ((DrbarrelgrState*)state)->grabZ;
            objRenderFn_8003b8f4(((DrbarrelgrState*)state)->heldBarrel, p2, p3, p4, p5, lbl_803E6CA0);
        }
    }
}
