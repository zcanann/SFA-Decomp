/*
 * DragonRock Palace force-field object (DLL 0x231; "DFP_ForceAw"),
 * implemented on the shared TrickyCurve state machine and sfxplayer: a
 * curve-driven hazard/barrier with per-state update handlers.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/trickycurve_state.h"
#include "main/mapEvent.h"
#include "main/dll/sfxplayer.h"
#include "main/dll/infopoint.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

#define DFPFORCEAW_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct TrickyCurveObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 rangeYRaw; /* 0x18 << 2 -> state.rangeY */
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 rangeZ;         /* 0x1C -> state.rangeZ */
    s16 triggerGameBit; /* 0x1E -> state.triggerGameBit */
    s16 gateGameBit;    /* 0x20 -> state.gateGameBit */
    u8 pad22[0x28 - 0x22];
} TrickyCurveObjectDef;

extern u32 FUN_80006824();
extern u32 FUN_800068c4();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern u32 FUN_80017748();
extern int randomGetRange(int lo, int hi);
extern int FUN_80017a98();
extern int Obj_GetPlayerObject(void);
extern u32 ObjMsg_SendToObject();
extern u32 FUN_80286838();
extern u32 FUN_80286884();
extern u32 FUN_80294c40();
extern f64 DOUBLE_803e70d8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6438;
extern f32 lbl_803E70E0;
extern f32 lbl_803E70F0;
extern f32 lbl_803E70F4;
extern f32 lbl_803E70F8;
extern f32 lbl_803E70FC;
extern f32 lbl_803E7100;

extern void vecRotateZXY(u8* p, f32* v);
extern f32 lbl_803E6460;
extern f32 lbl_803E6464;
extern f32 lbl_803E6468;

typedef struct TrickyCurveBurstFxParams
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad;
    f32 scale;
    f32 xOffset;
    f32 yOffset;
    f32 zOffset;
} TrickyCurveBurstFxParams;

extern void fn_80206C18(int* obj);
extern void fn_80206968(int* obj);

void TrickyCurve_updateBurstTrigger(int obj)
{
    u8* state;
    int player;
    f32 dx;
    f32 dz;
    f32 dy;
    u8 insideCount;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    TrickyCurveBurstFxParams fxParams;
    int burstParticles;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    insideCount = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;
    dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dz = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;

    if ((((TrickyCurveObjState*)state)->gateGameBit != -1) && (GameBit_Get(((TrickyCurveObjState*)state)->gateGameBit) != 0))
    {
        return;
    }

    if (GameBit_Get(((TrickyCurveObjState*)state)->triggerGameBit) != 0)
    {
        GameBit_Set(((TrickyCurveObjState*)state)->triggerGameBit, 0);
    }

    if (dx <= 0.0f)
    {
        if (dx > -(f32) * (s16*)state)
        {
            insideCount = 1;
            xSide = 1;
        }
    }
    if (dx > 0.0f)
    {
        if (dx < (f32) * (s16*)state)
        {
            insideCount++;
            xSide--;
        }
    }
    if (dz <= 0.0f)
    {
        if (dz > -(f32)((TrickyCurveObjState*)state)->rangeZ)
        {
            insideCount++;
            zSide = 1;
        }
    }
    if (dz > 0.0f)
    {
        if (dz < (f32)((TrickyCurveObjState*)state)->rangeZ)
        {
            insideCount++;
            zSide--;
        }
    }
    if (dy <= 0.0f)
    {
        if (dy > -(f32)((TrickyCurveObjState*)state)->rangeY)
        {
            insideCount++;
            ySide = 1;
        }
    }
    if (dy > 0.0f)
    {
        if (dy < (f32)((TrickyCurveObjState*)state)->rangeY)
        {
            insideCount++;
            ySide--;
        }
    }

    if (insideCount == 3)
    {
        fxParams.xOffset = dx;
        fxParams.yOffset = dy;
        fxParams.zOffset = dz;
        fxParams.scale = lbl_803E70E0;
        fxParams.rotZ = 0;
        fxParams.rotY = 0;
        fxParams.rotX = 0;
        if (xSide != state[0x10])
        {
            fxParams.rotX = 0x3fff;
        }

        if (GameBit_Get(0x1d9) != 0)
        {
            GameBit_Set(0x468, 1);
            ObjMsg_SendToObject(player, 0x60004, obj, 0);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x5ed, &fxParams, 2, -1, NULL);
            burstParticles = 9;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x5fd, &fxParams, 2, -1, NULL);
            }
            while (burstParticles-- != 0);
        }
        else
        {
            ObjMsg_SendToObject(player, 0x60004, obj, 1);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x5ed, &fxParams, 2, -1, NULL);
            burstParticles = 9;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x5fd, &fxParams, 2, -1, NULL);
            }
            while (burstParticles-- != 0);
        }
        GameBit_Set(((TrickyCurveObjState*)state)->triggerGameBit, 1);
        Sfx_PlayFromObject(obj, SFXfoot_water_walk_3);
    }

    state[0x10] = xSide;
    state[0x11] = ySide;
    state[0x12] = zSide;
}

#pragma scheduling on
#pragma peephole on
void TrickyCurve_updateBoundsTrigger(int obj)
{
    float dx;
    float dy;
    float dz;
    int ref;
    int insideCount;
    short* state;

    state = ((GameObject*)obj)->extra;
    ref = FUN_80017a98();
    insideCount = 0;
    dx = ((GameObject*)ref)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy = ((GameObject*)ref)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dz = ((GameObject*)ref)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    if ((dx <= lbl_803E6438) &&
        (-(float)((double)(int)*state) < dx))
    {
        insideCount = 1;
    }
    if ((lbl_803E6438 < dx) &&
        (dx < (float)((double)(int)*state)))
    {
        insideCount = insideCount + 1;
    }
    if ((dz <= lbl_803E6438) &&
        (-(float)((double)(int)state[1]) < dz))
    {
        insideCount = insideCount + 1;
    }
    if ((lbl_803E6438 < dz) &&
        (dz < (float)((double)(int)state[1])))
    {
        insideCount = insideCount + 1;
    }
    if ((dy <= lbl_803E6438) &&
        (-(float)((double)(int)state[2]) < dy))
    {
        insideCount = insideCount + 1;
    }
    if ((lbl_803E6438 < dy) &&
        (dy < (float)((double)(int)state[2])))
    {
        insideCount = insideCount + 1;
    }
    if (insideCount == 3)
    {
        randomGetRange(0xffffffe9, 0x17);
        randomGetRange(0xffffffe9, 0x17);
        FUN_80294c40();
    }
    return;
}

void TrickyCurve_updateEffectRingTrigger(u64 arg1, u64 arg2, u64 arg3,
                                         u64 arg4, u64 arg5, u64 arg6,
                                         u64 arg7, u64 arg8)
{
    bool flag;
    u32 obj;
    int ref;
    u32 bitVal;
    u32 unusedArg7;
    u32 unusedArg8;
    u32 unusedArg9;
    u32 unusedArg10;
    char zSide;
    char ySide;
    char xSide;
    int insideCount;
    short* state;
    double ftmp;
    u64 pairWord;
    double savedF29;
    double dy;
    double savedF30;
    double dz;
    double savedF31;
    double dx;
    double savedPs29;
    double savedPs30;
    double savedPs31;
    u16 rotX;
    u16 rotY;
    u16 rotZ;
    float scale;
    float fdx;
    float fdy;
    float fdz;
    u32 convHi0;
    u32 convLo0;
    float save31Hi;
    float save31Lo;
    float save30Hi;
    float save30Lo;
    float save29Hi;
    float save29Lo;

    save31Hi = (float)savedF31;
    save31Lo = (float)savedPs31;
    save30Hi = (float)savedF30;
    save30Lo = (float)savedPs30;
    save29Hi = (float)savedF29;
    save29Lo = (float)savedPs29;
    obj = FUN_80286838();
    state = ((GameObject *)obj)->extra;
    ref = FUN_80017a98();
    insideCount = 0;
    xSide = '\0';
    ySide = '\0';
    zSide = '\0';
    dx = (double)(((GameObject*)ref)->anim.localPosX - ((GameObject *)obj)->anim.localPosX);
    dy = (double)(((GameObject*)ref)->anim.localPosY - ((GameObject *)obj)->anim.localPosY);
    ftmp = (double)((GameObject*)ref)->anim.localPosZ;
    dz = (double)(float)(ftmp - (double)((GameObject *)obj)->anim.localPosZ);
    if (((int)state[4] == 0xffffffff) || (bitVal = FUN_80017690((int)state[4]), bitVal == 0))
    {
        bitVal = FUN_80017690((int)state[5]);
        if (bitVal != 0)
        {
            ftmp = (double)FUN_80017698((int)state[5], 0);
        }
        if (dx <= (double)lbl_803E6438)
        {
            convLo0 = (int)*state ^ 0x80000000;
            convHi0 = 0x43300000;
            ftmp = DOUBLE_803e70d8;
            if (-(double)(f32)(s32)convLo0 < dx
            )
            {
                insideCount = 1;
                xSide = '\x01';
            }
        }
        if ((double)lbl_803E6438 < dx)
        {
            convLo0 = (int)*state ^ 0x80000000;
            convHi0 = 0x43300000;
            ftmp = DOUBLE_803e70d8;
            if (dx < (double)(f32)(s32)convLo0
            )
            {
                insideCount = insideCount + 1;
                xSide = xSide + -1;
            }
        }
        if (dz <= (double)lbl_803E6438)
        {
            convLo0 = state[1] ^ 0x80000000;
            convHi0 = 0x43300000;
            ftmp = DOUBLE_803e70d8;
            if (-(double)(f32)(s32)convLo0 < dz
            )
            {
                insideCount = insideCount + 1;
                zSide = '\x01';
            }
        }
        if ((double)lbl_803E6438 < dz)
        {
            convLo0 = state[1] ^ 0x80000000;
            convHi0 = 0x43300000;
            ftmp = DOUBLE_803e70d8;
            if (dz < (double)(f32)(s32)convLo0
            )
            {
                insideCount = insideCount + 1;
                zSide = zSide + -1;
            }
        }
        if (dy <= (double)lbl_803E6438)
        {
            convLo0 = state[2] ^ 0x80000000;
            convHi0 = 0x43300000;
            ftmp = DOUBLE_803e70d8;
            if (-(double)(f32)(s32)convLo0 < dy
            )
            {
                insideCount = insideCount + 1;
                ySide = '\x01';
            }
        }
        if ((double)lbl_803E6438 < dy)
        {
            convLo0 = state[2] ^ 0x80000000;
            convHi0 = 0x43300000;
            ftmp = DOUBLE_803e70d8;
            if (dy < (double)(f32)(s32)convLo0
            )
            {
                insideCount = insideCount + 1;
                ySide = ySide + -1;
            }
        }
        if (insideCount == 3)
        {
            fdx = (float)dx;
            fdy = (float)dy;
            fdz = (float)dz;
            scale = lbl_803E70E0;
            rotZ = 0;
            rotY = 0;
            rotX = 0;
            if (xSide != *(char*)(state + 8))
            {
                rotX = 0x3fff;
            }
            bitVal = FUN_80017690(0x1d9);
            if (bitVal == 0)
            {
                ObjMsg_SendToObject(ftmp, arg2, arg3, arg4, arg5, arg6, arg7, arg8, ref,
                                    0x60004,
                                    obj, 1, unusedArg7, unusedArg8, unusedArg9, unusedArg10);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x5ed, &rotX, 2, -1, NULL);
                ref = 9;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x5fd, &rotX, 2, -1, NULL);
                    ref = ref + -1;
                }
                while (ref != -1);
            }
            else
            {
                pairWord = FUN_80017698(0x468, 1);
                ObjMsg_SendToObject(pairWord, arg2, arg3, arg4, arg5, arg6, arg7, arg8, ref,
                                    0x60004,
                                    obj, 0, unusedArg7, unusedArg8, unusedArg9, unusedArg10);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x5ed, &rotX, 2, -1, NULL);
                ref = 9;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x5fd, &rotX, 2, -1, NULL);
                    ref = ref + -1;
                }
                while (ref != -1);
            }
            FUN_80017698((int)state[5], 1);
            FUN_80006824(obj, SFXfoot_water_walk_3);
        }
        *(char*)(state + 8) = xSide;
        *(char*)((int)state + 0x11) = ySide;
        *(char*)(state + 9) = zSide;
    }
    FUN_80286884();
    return;
}

void TrickyCurve_updateState(u64 arg1, u64 arg2, u64 arg3,
                             u64 arg4, u64 arg5, u64 arg6,
                             u64 arg7, u64 arg8, int obj)
{
    char triggerKind;

    triggerKind = *(char*)(*(int*)&((GameObject*)obj)->extra + 0xe);
    if (triggerKind == '\0')
    {
        TrickyCurve_updateEffectRingTrigger(arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                                            arg8);
    }
    else if (triggerKind == '\x01')
    {
        TrickyCurve_updateBoundsTrigger(obj);
    }
    else if (triggerKind == '\x02')
    {
        TrickyCurve_updateBurstTrigger(obj);
    }
    else if (triggerKind == '\x03')
    {
        TrickyCurve_updateCooldownTrigger(obj);
    }
    return;
}

void sfxplayer_updateEffectHandlePositions(short* obj)
{
    int angleDelta;
    char mode;
    short i;
    int state;
    short angleStep;
    int* handles;
    u16 rotation[4];
    float baseSeed;
    float baseOffX;
    float baseOffY;
    float baseOffZ;
    u32 convHi0;
    u32 convLo0;
    s64 convResult;

    state = *(int*)&((GameObject*)obj)->extra;
    if ((((*(u8*)(state + 8) >> 4 & 1) != 0) && ((*(u8*)(state + 8) >> 5 & 1) == 0)) &&
        (0x32 < *(short*)(state + 4)))
    {
        FUN_800068c4((u32)obj, 0x459);
        mode = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
        if (mode == '\x02')
        {
            convLo0 = (u32) * (u8*)(state + 7);
            convHi0 = 0x43300000;
            angleDelta = (int)((lbl_803E70F0 +
                    (float)((double)(u32)convLo0)) *
                lbl_803E70F4 * lbl_803DC074);
            convResult = (s64)angleDelta;
            *obj = *obj + angleDelta;
        }
        else
        {
            convResult = (s64)(int)(lbl_803E70F4 * lbl_803DC074);
            *obj = *obj + (short)(int)(lbl_803E70F4 * lbl_803DC074);
        }
    }
    if ((*(short*)(state + 4) != 0) && ((*(u8*)(state + 8) >> 4 & 1) != 0))
    {
        convResult = (s64)(int)
        lbl_803DC074;
        *(short*)(state + 4) = *(short*)(state + 4) - (short)(int)lbl_803DC074;
        if (*(short*)(state + 4) < 1)
        {
            *(u16*)(state + 4) = 200;
        }
    }
    baseOffX = lbl_803E70F8;
    baseOffY = lbl_803E70F8;
    baseOffZ = lbl_803E70F8;
    baseSeed = lbl_803E70F0;
    angleStep = 0;
    rotation[2] = 0;
    rotation[1] = 0;
    handles = gSfxplayerEffectHandles;
    for (i = 0; i < 4; i = i + 1)
    {
        if (*handles != 0)
        {
            *(float*)(*handles + 0xc) = lbl_803E70F8;
            *(float*)(*handles + 0x10) = lbl_803E70FC;
            *(float*)(*handles + 0x14) = lbl_803E7100;
            rotation[0] = *obj + angleStep;
            FUN_80017748(rotation, (float*)(*handles + 0xc));
            *(float*)(*handles + 0xc) = *(float*)(*handles + 0xc) + *(float*)(obj + 6);
            *(float*)(*handles + 0x10) = *(float*)(*handles + 0x10) + *(float*)(obj + 8);
            *(float*)(*handles + 0x14) = *(float*)(*handles + 0x14) + *(float*)(obj + 10);
        }
        if (handles[1] != 0)
        {
            *(float*)(handles[1] + 0xc) = lbl_803E70F8;
            *(float*)(handles[1] + 0x10) = lbl_803E70FC;
            *(float*)(handles[1] + 0x14) = lbl_803E7100;
            rotation[0] = *obj + angleStep;
            FUN_80017748(rotation, (float*)(handles[1] + 0xc));
            *(float*)(handles[1] + 0xc) = *(float*)(handles[1] + 0xc) + *(float*)(obj + 6);
            *(float*)(handles[1] + 0x10) = *(float*)(handles[1] + 0x10) + *(float*)(obj + 8);
            *(float*)(handles[1] + 0x14) = *(float*)(handles[1] + 0x14) + *(float*)(obj + 10);
        }
        handles = handles + 2;
        angleStep = angleStep + 0x3fff;
    }
    return;
}

#define SFXPLAYER_UPDATE_EFFECT_HANDLE_POS(handle, obj, rot, angleStep) \
    do { \
        if ((handle) != 0) { \
            *(f32 *)((handle) + 0xc) = lbl_803E6460; \
            *(f32 *)((handle) + 0x10) = lbl_803E6464; \
            *(f32 *)((handle) + 0x14) = lbl_803E6468; \
            (rot)[0] = (s16)(*(s16 *)(obj) + (angleStep)); \
            vecRotateZXY((rot), (f32 *)((handle) + 0xc)); \
            *(f32 *)((handle) + 0xc) += *(f32 *)((obj) + 0xc); \
            *(f32 *)((handle) + 0x10) += *(f32 *)((obj) + 0x10); \
            *(f32 *)((handle) + 0x14) += *(f32 *)((obj) + 0x14); \
        } \
    } while (0)

#undef SFXPLAYER_UPDATE_EFFECT_HANDLE_POS

#pragma scheduling off
#pragma peephole off
void TrickyCurve_render(void)
{
}

void TrickyCurve_hitDetect(void)
{
}

void TrickyCurve_release(void)
{
}

void TrickyCurve_initialise(void)
{
}

void sfxplayer_render(void);

int TrickyCurve_getExtraSize(void) { return 0x14; }
int TrickyCurve_getObjectTypeId(void) { return 0x0; }
int sfxplayer_getExtraSize(void);

void TrickyCurve_update(int* obj)
{
    u8* inner = ((GameObject*)obj)->extra;
    u32 state = inner[0xe];
    if (state == 0)
    {
        TrickyCurve_updateBurstTrigger((int)obj);
    }
    else if (state == 1)
    {
        TrickyCurve_updateCooldownTrigger((int)obj);
    }
    else if (state == 2)
    {
        fn_80206C18(obj);
    }
    else if (state == 3)
    {
        fn_80206968(obj);
    }
}

void TrickyCurve_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void TrickyCurve_init(int* obj, u8* def)
{
    u8* state = ((GameObject*)obj)->extra;
    state[0xc] = def[0x19];
    ((TrickyCurveObjState*)state)->rangeY = (s16)((s32)((TrickyCurveObjectDef*)def)->rangeYRaw << 2);
    *(s16*)state = ((TrickyCurveObjectDef*)def)->unk1A;
    ((TrickyCurveObjState*)state)->rangeZ = ((TrickyCurveObjectDef*)def)->rangeZ;
    state[0xe] = def[0x19];
    state[0x10] = 0;
    state[0x11] = 0;
    state[0x12] = 0;
    ((TrickyCurveObjState*)state)->gateGameBit = ((TrickyCurveObjectDef*)def)->gateGameBit;
    ((TrickyCurveObjState*)state)->triggerGameBit = ((TrickyCurveObjectDef*)def)->triggerGameBit;
    ((TrickyCurveObjState*)state)->unk6 = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DFPFORCEAW_OBJFLAG_HITDETECT_DISABLED);
}
