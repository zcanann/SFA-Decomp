#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct DrbarrelgrPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 unk19;
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} DrbarrelgrPlacement;


typedef struct DrbarrelgrState
{
    s32 unk0;
    s32 unk4;
    s32 unk8;
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    u8 pad20[0x88 - 0x20];
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    u8 pad94[0x128 - 0x94];
    s16 unk128;
    u8 pad12A[0x12C - 0x12A];
} DrbarrelgrState;


int drbarrelgr_getExtraSize(void) { return 0x12c; }

int drbarrelgr_getObjectTypeId(void) { return 0; }

void drbarrelgr_free(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    void* heldObj = *(void**)&((DrbarrelgrState*)state)->unk8;

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
    if (((DrbarrelgrPlacement*)setup)->unk19 == 0)
    {
        ((DrbarrelgrPlacement*)setup)->unk19 = 0xa;
    }
    if (((DrbarrelgrPlacement*)setup)->unk1A <= 0)
    {
        ((DrbarrelgrPlacement*)setup)->unk1A = 0x64;
    }
    ((DrbarrelgrState*)state)->unk0 = 5;
    ((DrbarrelgrState*)state)->unk8 = 0;
    ((DrBarrelGrFlags*)(state + 0x12a))->bit80 = 0;
    ((DrbarrelgrState*)state)->unk128 = ((DrbarrelgrPlacement*)setup)->unk19;
    ((DrbarrelgrState*)state)->unk10 = lbl_803E6CA4;
    ((DrbarrelgrState*)state)->unk4 = -3;
    ((DrBarrelGrFlags*)(state + 0x12a))->bit40 = 0;
    storeZeroToFloatParam((void*)(state + 0xc));
    s16toFloat((void*)(state + 0xc), ((DrbarrelgrPlacement*)setup)->unk1A);
    *(s16*)obj = (s16)((s8)((DrbarrelgrPlacement*)setup)->unk18 << 8);
    (*gRomCurveInterface)->initCurve((void*)(state + 0x20), (void*)obj, lbl_803E6CD0, &one, 0);
    ((GameObject*)obj)->anim.localPosX = ((DrbarrelgrState*)state)->startPosX;
    ((GameObject*)obj)->anim.localPosZ = ((DrbarrelgrState*)state)->startPosZ;
    ((GameObject*)obj)->anim.localPosY = ((DrbarrelgrState*)state)->startPosY;
}

void drbarrelgr_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    int newMode = -1;
    DrBarrelGrFlags* flags = (DrBarrelGrFlags*)(state + 0x12a);
    int nearest;
    int match;
    int gbId;
    f32 vec[3];
    f32 tmp[3];

    if (*(void**)&((DrbarrelgrState*)state)->unk8 != 0)
    {
        nearest = ObjGroup_FindNearestObject(25, obj, 0);
        match = 0;
        if ((u32)nearest != 0 && *(u32*)&((DrbarrelgrState*)state)->unk8 == (u32)nearest)
        {
            match = 1;
        }
        if (match == 0 ||
            (flags->bit80 != 0 && gunpowderbarrel_isHeld(((DrbarrelgrState*)state)->unk8) == 0))
        {
            ((DrbarrelgrState*)state)->unk8 = 0;
            flags->bit80 = 0;
        }
    }

    gbId = ((DrbarrelgrPlacement*)setup)->unk20;
    if (gbId != -1 && (u32)GameBit_Get(gbId) == 0)
    {
        flags->bit40 = 0;
        return;
    }
    flags->bit40 = 1;
    Sfx_KeepAliveLoopedObjectSound(obj, 958);

    switch (((DrbarrelgrState*)state)->unk0)
    {
    case 0:
        if (*(void**)&((DrbarrelgrState*)state)->unk8 == 0)
        {
            nearest = ObjGroup_FindNearestObject(25, obj, 0);
            if ((u32)nearest != 0 &&
                Vec_xzDistance(obj + 24, nearest + 24) < lbl_803E6CB0 &&
                *(f32*)(nearest + 16) < ((GameObject*)obj)->anim.localPosY)
            {
                vec[0] = *(f32*)(nearest + 12);
                vec[1] = lbl_803E6CB4 + *(f32*)(nearest + 16);
                vec[2] = *(f32*)(nearest + 20);
                if (voxmaps_traceWorldLine((void*)&((GameObject*)obj)->anim.localPosX, vec) != 0 &&
                    gunpowderbarrel_canBeGrabbed(nearest) != 0)
                {
                    Sfx_PlayFromObject(obj, 959);
                    newMode = 4;
                    ((DrbarrelgrState*)state)->unk8 = nearest;
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
        if (*(void**)&((DrbarrelgrState*)state)->unk8 == 0 ||
            gunpowderbarrel_canBeGrabbed(((DrbarrelgrState*)state)->unk8) == 0)
        {
            ((DrbarrelgrState*)state)->unk0 = 0;
            ((DrbarrelgrState*)state)->unk8 = 0;
            flags->bit80 = 0;
            break;
        }
        if (Vec_xzDistance(obj + 24, ((DrbarrelgrState*)state)->unk8 + 24) > lbl_803E6CB0)
        {
            newMode = ((DrbarrelgrState*)state)->unk4;
            flags->bit80 = 0;
            ((DrbarrelgrState*)state)->unk8 = 0;
            break;
        }
        PSVECSubtract((void*)(state + 0x14), (void*)(((DrbarrelgrState*)state)->unk8 + 12), tmp);
        if (tmp[0] != lbl_803E6CA4 || tmp[1] != lbl_803E6CA4 || tmp[2] != lbl_803E6CA4)
        {
            PSVECNormalize(tmp, tmp);
        }
        PSVECScale(tmp, tmp, lbl_803DC3B0);
        gunpowderbarrel_setScale(((DrbarrelgrState*)state)->unk8, tmp);
        if (PSVECDistance((void*)(state + 0x14), (void*)(((DrbarrelgrState*)state)->unk8 + 12)) < lbl_803E6CA0 ||
            *(f32*)(((DrbarrelgrState*)state)->unk8 + 16) > ((DrbarrelgrState*)state)->unk18)
        {
            Sfx_PlayFromObject(obj, 960);
            gunpowderbarrel_setHeldState(((DrbarrelgrState*)state)->unk8);
            newMode = ((DrbarrelgrState*)state)->unk4;
            flags->bit80 = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        break;
    case 5:
        {
            int r = Obj_UpdateRomCurveFollowVelocity(obj, state + 0x20,
                                                     lbl_803E6CB8 * (f32)((DrbarrelgrState*)state)->unk128 * timeDelta,
                                                     lbl_803E6CBC, lbl_803E6CB4, 1);
            objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                    ((GameObject*)obj)->anim.velocityZ);
            if (r != 0)
            {
                newMode = r - 1;
                storeZeroToFloatParam((void*)(state + 12));
                s16toFloat((void*)(state + 12), ((DrbarrelgrPlacement*)setup)->unk1A);
                ((GameObject*)obj)->anim.velocityX = lbl_803E6CA4;
                ((GameObject*)obj)->anim.velocityY = lbl_803E6CA4;
                ((GameObject*)obj)->anim.velocityZ = lbl_803E6CA4;
            }
            break;
        }
    case 2:
        if (((DrbarrelgrState*)state)->unk128 == ((DrbarrelgrPlacement*)setup)->unk19)
        {
            ((DrbarrelgrState*)state)->unk128 =
                (int)((f32)((DrbarrelgrState*)state)->unk128 * lbl_803E6CA8);
        }
        else
        {
            ((DrbarrelgrState*)state)->unk128 = ((DrbarrelgrPlacement*)setup)->unk19;
        }
        storeZeroToFloatParam((void*)(state + 12));
        newMode = 5;
        break;
    case 1:
        if (*(void**)&((DrbarrelgrState*)state)->unk8 != 0)
        {
            newMode = 3;
        }
        else if (timerCountDown((void*)(state + 12)) != 0)
        {
            newMode = 5;
        }
        break;
    case 3:
        if (*(void**)&((DrbarrelgrState*)state)->unk8 != 0)
        {
            gunpowderbarrel_clearHeldState(((DrbarrelgrState*)state)->unk8);
            flags->bit80 = 0;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        ((DrbarrelgrState*)state)->unk8 = 0;
        newMode = ((DrbarrelgrState*)state)->unk4;
        break;
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E6CC0, timeDelta, 0);
    if (newMode != -1 && newMode != ((DrbarrelgrState*)state)->unk0)
    {
        ((DrbarrelgrState*)state)->unk4 = ((DrbarrelgrState*)state)->unk0;
        ((DrbarrelgrState*)state)->unk0 = newMode;
    }
    if ((((GameObject*)obj)->objectFlags & 0x800) == 0 && *(void**)&((DrbarrelgrState*)state)->unk8 != 0)
    {
        ((DrbarrelgrState*)state)->unk14 = ((GameObject*)obj)->anim.localPosX;
        ((DrbarrelgrState*)state)->unk18 = ((GameObject*)obj)->anim.localPosY + lbl_803DC3B4;
        ((DrbarrelgrState*)state)->unk1C = ((GameObject*)obj)->anim.localPosZ;
        *(f32*)(((DrbarrelgrState*)state)->unk8 + 12) = ((DrbarrelgrState*)state)->unk14;
        *(f32*)(((DrbarrelgrState*)state)->unk8 + 16) = ((DrbarrelgrState*)state)->unk18;
        *(f32*)(((DrbarrelgrState*)state)->unk8 + 20) = ((DrbarrelgrState*)state)->unk1C;
    }
}

void drbarrelgr_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    int objRef;
    int nearest;
    int match;
    f32 dval;
    f32 vec[3];
    DrBarrelGrRenderParams params;

    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CA0);
    ObjPath_GetPointWorldPosition(obj, 0, (f32*)(state + 0x14), (f32*)(state + 0x18),
                                  (f32*)(state + 0x1c), 0);
    params.a = 0;
    params.c = 0;
    params.b = 0x4000;
    dval = lbl_803E6CA4;
    for (i = 0; i < 4; i++)
    {
        ObjPath_GetPointWorldPosition(obj, i + 1, &vec[0], &vec[1], &vec[2], 0);
        PSVECSubtract(&vec[0], (void*)(obj + 0xc), &vec[0]);
        params.d = dval;
        objfx_spawnLightPulse(obj, lbl_803E6CA8, 3, 0, 0, lbl_803E6CAC, (int)&params);
    }
    objRef = ((DrbarrelgrState*)state)->unk8;
    if (objRef != 0)
    {
        match = 0;
        nearest = ObjGroup_FindNearestObject(0x19, obj, 0);
        if (nearest != 0 && nearest == objRef)
        {
            match = 1;
        }
        if (match && *(int*)state != 4)
        {
            *(f32*)(((DrbarrelgrState*)state)->unk8 + 0xc) = ((DrbarrelgrState*)state)->unk14;
            *(f32*)(((DrbarrelgrState*)state)->unk8 + 0x10) = ((DrbarrelgrState*)state)->unk18;
            *(f32*)(((DrbarrelgrState*)state)->unk8 + 0x14) = ((DrbarrelgrState*)state)->unk1C;
            objRenderFn_8003b8f4(((DrbarrelgrState*)state)->unk8, p2, p3, p4, p5, lbl_803E6CA0);
        }
    }
}
