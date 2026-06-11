#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/trickycurve_state.h"
#include "main/mapEvent.h"
#include "main/dll/TrickyCurve.h"
#include "main/dll/sfxplayer.h"

typedef struct TrickyCurveObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} TrickyCurveObjectDef;


extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern int Obj_GetPlayerObject(void);
extern undefined4 ObjMsg_SendToObject();
extern void TrickyCurve_updateCooldownTrigger(int obj);
extern uint FUN_80286838();
extern uint FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294c40();
extern int FUN_80294d6c();

extern MapEventInterface** gMapEventInterface;
extern u8 gTrickyCurveBurstCounter;
extern f64 DOUBLE_803e70d8;
extern f64 DOUBLE_803e7108;
extern f32 lbl_803DC074;
extern f32 lbl_803E6438;
extern f32 lbl_803E70E0;
extern f32 lbl_803E70F0;
extern f32 lbl_803E70F4;
extern f32 lbl_803E70F8;
extern f32 lbl_803E70FC;
extern f32 lbl_803E7100;

extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int objType);
extern int Obj_SetupObject(int setup, int mode, int mapLayer, int objIndex, int parent);
extern void Obj_FreeObject(int obj);
extern void gameTimerStop(void);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void vecRotateZXY(s16 * rotation, f32 * outVec);
extern EffectInterface** gPartfxInterface;

extern u32 lbl_803E6450;
extern u32 lbl_803E6454;
extern f32 timeDelta;
extern f32 lbl_803E6458;
extern f32 lbl_803E645C;
extern f32 lbl_803E6460;
extern f32 lbl_803E6464;
extern f32 lbl_803E6468;
extern f64 lbl_803E6470;
extern f32 lbl_803E6478;

#define SFXPLAYER_OBJECT_FLAGS_OFFSET 0xB0
#define SFXPLAYER_OBJECT_STATE_OFFSET 0xB8
#define SFXPLAYER_EFFECT_RING_COUNT 4
#define SFXPLAYER_EFFECT_HANDLES_PER_RING 2
#define SFXPLAYER_MODE_SEQUENCE 2
#define SFXPLAYER_RING_START_SFX 0x459
#define SFXPLAYER_TIMEOUT_RESET_SFX 0x1CE
#define SFXPLAYER_GAMEBIT_RING_ACTIVE 0xEDF
#define SFXPLAYER_RING_VISUAL_SETUP_SIZE 0x2C
#define SFXPLAYER_RING_VISUAL_OBJECT_ID 0x6E8
#define SFXPLAYER_RING_HIT_SETUP_SIZE 4
#define SFXPLAYER_RING_HIT_OBJECT_ID 0x71C
#define SFXPLAYER_RING_SETUP_MODE 5
#define SFXPLAYER_EFFECT_RING_ROT_STEP 0x3FFF

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

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateBurstTrigger
 * EN v1.0 Address: 0x8020718C
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80207250
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    dx = *(f32*)(player + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dy = *(f32*)(player + 0x10) - ((GameObject*)obj)->anim.localPosY;
    dz = *(f32*)(player + 0x14) - ((GameObject*)obj)->anim.localPosZ;

    if ((((TrickyCurveObjState*)state)->unk8 != -1) && (GameBit_Get(((TrickyCurveObjState*)state)->unk8) != 0))
    {
        return;
    }

    if (GameBit_Get(((TrickyCurveObjState*)state)->unkA) != 0)
    {
        GameBit_Set(((TrickyCurveObjState*)state)->unkA, 0);
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
        if (dz > -(f32)((TrickyCurveObjState*)state)->unk2)
        {
            insideCount++;
            zSide = 1;
        }
    }
    if (dz > 0.0f)
    {
        if (dz < (f32)((TrickyCurveObjState*)state)->unk2)
        {
            insideCount++;
            zSide--;
        }
    }
    if (dy <= 0.0f)
    {
        if (dy > -(f32)((TrickyCurveObjState*)state)->unk4)
        {
            insideCount++;
            ySide = 1;
        }
    }
    if (dy > 0.0f)
    {
        if (dy < (f32)((TrickyCurveObjState*)state)->unk4)
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
        GameBit_Set(((TrickyCurveObjState*)state)->unkA, 1);
        Sfx_PlayFromObject(obj, SFXfoot_water_walk_3);
    }

    state[0x10] = xSide;
    state[0x11] = ySide;
    state[0x12] = zSide;
}

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateBoundsTrigger
 * EN v1.0 Address: 0x802074FC
 * EN v1.0 Size: 520b
 * EN v1.1 Address: 0x80207568
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    dx = *(float*)(ref + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dy = *(float*)(ref + 0x10) - ((GameObject*)obj)->anim.localPosY;
    dz = *(float*)(ref + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    if ((dx <= lbl_803E6438) &&
        (-(float)((double)CONCAT44(0x43300000, (int)*state ^ 0x80000000) - DOUBLE_803e70d8) < dx))
    {
        insideCount = 1;
    }
    if ((lbl_803E6438 < dx) &&
        (dx < (float)((double)CONCAT44(0x43300000, (int)*state ^ 0x80000000) - DOUBLE_803e70d8)))
    {
        insideCount = insideCount + 1;
    }
    if ((dz <= lbl_803E6438) &&
        (-(float)((double)CONCAT44(0x43300000, (int)state[1] ^ 0x80000000) - DOUBLE_803e70d8) < dz))
    {
        insideCount = insideCount + 1;
    }
    if ((lbl_803E6438 < dz) &&
        (dz < (float)((double)CONCAT44(0x43300000, (int)state[1] ^ 0x80000000) - DOUBLE_803e70d8)))
    {
        insideCount = insideCount + 1;
    }
    if ((dy <= lbl_803E6438) &&
        (-(float)((double)CONCAT44(0x43300000, (int)state[2] ^ 0x80000000) - DOUBLE_803e70d8) < dy))
    {
        insideCount = insideCount + 1;
    }
    if ((lbl_803E6438 < dy) &&
        (dy < (float)((double)CONCAT44(0x43300000, (int)state[2] ^ 0x80000000) - DOUBLE_803e70d8)))
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

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateEffectRingTrigger
 * EN v1.0 Address: 0x80207704
 * EN v1.0 Size: 1292b
 * EN v1.1 Address: 0x802077C4
 * EN v1.1 Size: 1008b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateEffectRingTrigger(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                         undefined8 param_4, undefined8 param_5, undefined8 param_6,
                                         undefined8 param_7, undefined8 param_8)
{
    bool flag;
    uint obj;
    int ref;
    uint bitVal;
    undefined4 unusedArg7;
    undefined4 unusedArg8;
    undefined4 unusedArg9;
    undefined4 unusedArg10;
    char zSide;
    char ySide;
    char xSide;
    int insideCount;
    short* state;
    double ftmp;
    undefined8 pairWord;
    double savedF29;
    double dy;
    double savedF30;
    double dz;
    double savedF31;
    double dx;
    double savedPs29;
    double savedPs30;
    double savedPs31;
    undefined2 rotX;
    undefined2 rotY;
    undefined2 rotZ;
    float scale;
    float fdx;
    float fdy;
    float fdz;
    undefined4 convHi0;
    uint convLo0;
    float local_28;
    float fStack_24;
    float local_18;
    float fStack_14;
    float local_8;
    float fStack_4;

    local_8 = (float)savedF31;
    fStack_4 = (float)savedPs31;
    local_18 = (float)savedF30;
    fStack_14 = (float)savedPs30;
    local_28 = (float)savedF29;
    fStack_24 = (float)savedPs29;
    obj = FUN_80286838();
    state = *(short**)(obj + 0xb8);
    ref = FUN_80017a98();
    insideCount = 0;
    xSide = '\0';
    ySide = '\0';
    zSide = '\0';
    dx = (double)(*(float*)(ref + 0xc) - *(float*)(obj + 0xc));
    dy = (double)(*(float*)(ref + 0x10) - *(float*)(obj + 0x10));
    ftmp = (double)*(float*)(ref + 0x14);
    dz = (double)(float)(ftmp - (double)*(float*)(obj + 0x14));
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
            convLo0 = (int)state[1] ^ 0x80000000;
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
            convLo0 = (int)state[1] ^ 0x80000000;
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
            convLo0 = (int)state[2] ^ 0x80000000;
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
            convLo0 = (int)state[2] ^ 0x80000000;
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
                ObjMsg_SendToObject(ftmp, param_2, param_3, param_4, param_5, param_6, param_7, param_8, ref,
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
                ObjMsg_SendToObject(pairWord, param_2, param_3, param_4, param_5, param_6, param_7, param_8, ref,
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

/*
 * --INFO--
 *
 * Function: FUN_80207c10
 * EN v1.0 Address: 0x80207C10
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80207BB4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: TrickyCurve_updateState
 * EN v1.0 Address: 0x80207C44
 * EN v1.0 Size: 640b
 * EN v1.1 Address: 0x80207BEC
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void TrickyCurve_updateState(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                             undefined8 param_4, undefined8 param_5, undefined8 param_6,
                             undefined8 param_7, undefined8 param_8, int obj)
{
    char triggerKind;

    triggerKind = *(char*)(*(int*)&((GameObject*)obj)->extra + 0xe);
    if (triggerKind == '\0')
    {
        TrickyCurve_updateEffectRingTrigger(param_1, param_2, param_3, param_4, param_5, param_6, param_7,
                                            param_8);
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

/*
 * --INFO--
 *
 * Function: sfxplayer_updateEffectHandlePositions
 * EN v1.0 Address: 0x80207EC4
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x80207CC4
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_updateEffectHandlePositions(short* obj)
{
    int angleDelta;
    char mode;
    short i;
    int state;
    short angleStep;
    int* handles;
    ushort rotation[4];
    float baseSeed;
    float baseOffX;
    float baseOffY;
    float baseOffZ;
    undefined4 convHi0;
    uint convLo0;
    longlong convResult;

    state = *(int*)(obj + 0x5c);
    if ((((*(byte*)(state + 8) >> 4 & 1) != 0) && ((*(byte*)(state + 8) >> 5 & 1) == 0)) &&
        (0x32 < *(short*)(state + 4)))
    {
        FUN_800068c4((uint)obj, 0x459);
        mode = (*gMapEventInterface)->getMode((int)*(char*)(obj + 0x56));
        if (mode == '\x02')
        {
            convLo0 = (uint) * (byte*)(state + 7);
            convHi0 = 0x43300000;
            angleDelta = (int)((lbl_803E70F0 +
                    (float)((double)CONCAT44(0x43300000, convLo0) - DOUBLE_803e7108)) *
                lbl_803E70F4 * lbl_803DC074);
            convResult = (longlong)angleDelta;
            *obj = *obj + (short)angleDelta;
        }
        else
        {
            convResult = (longlong)(int)(lbl_803E70F4 * lbl_803DC074);
            *obj = *obj + (short)(int)(lbl_803E70F4 * lbl_803DC074);
        }
    }
    if ((*(short*)(state + 4) != 0) && ((*(byte*)(state + 8) >> 4 & 1) != 0))
    {
        convResult = (longlong)(int)
        lbl_803DC074;
        *(short*)(state + 4) = *(short*)(state + 4) - (short)(int)lbl_803DC074;
        if (*(short*)(state + 4) < 1)
        {
            *(undefined2*)(state + 4) = 200;
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

#pragma scheduling off
#pragma peephole off
void TrickyCurve_updateEffectHandleRing(int obj)
{
    SfxplayerState* state = *(SfxplayerState**)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
    SfxplayerStateFlags* flags = &state->flags;
    s16 rotation[3];
    f32 baseVec[4];
    int* handles;
    s16 angleStep;
    s16 i;
    int handle;

    if (flags->bit10 != 0 && flags->bit20 == 0 && state->variantSfxTimer > 0x32)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXPLAYER_RING_START_SFX);
        if ((*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) ==
            SFXPLAYER_MODE_SEQUENCE)
        {
            *(s16*)obj += (s16)((lbl_803E6458 + (f32)state->ringCount) * lbl_803E645C * timeDelta);
        }
        else
        {
            *(s16*)obj += (s16)(lbl_803E645C * timeDelta);
        }
    }

    if (state->variantSfxTimer != 0 && flags->bit10 != 0)
    {
        state->variantSfxTimer -= (s16)(int)
        timeDelta;
        if (state->variantSfxTimer <= 0)
        {
            state->variantSfxTimer = 200;
        }
    }

    baseVec[1] = lbl_803E6460;
    baseVec[2] = lbl_803E6460;
    baseVec[3] = lbl_803E6460;
    baseVec[0] = lbl_803E6458;
    angleStep = 0;
    rotation[2] = 0;
    rotation[1] = 0;
    handles = gSfxplayerEffectHandles;

    for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
    {
        handle = handles[0];
        SFXPLAYER_UPDATE_EFFECT_HANDLE_POS(handle, obj, rotation, angleStep);
        handle = handles[1];
        SFXPLAYER_UPDATE_EFFECT_HANDLE_POS(handle, obj, rotation, angleStep);
        handles += SFXPLAYER_EFFECT_HANDLES_PER_RING;
        angleStep += SFXPLAYER_EFFECT_RING_ROT_STEP;
    }
}

int sfxplayer_ensureEffectHandlePair(int obj, u8 ringIndex)
{
    u32 ringIdWords[2];
    int* handles;
    int* pair;
    int setup;
    int handleOffset;
    s16* ringIds;

    ringIdWords[0] = lbl_803E6450;
    ringIdWords[1] = lbl_803E6454;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }

    handleOffset = (ringIndex & 0xff) * 8;
    handles = gSfxplayerEffectHandles;
    if (*(int*)((int)handles + handleOffset) == 0)
    {
        setup = Obj_AllocObjectSetup(SFXPLAYER_RING_VISUAL_SETUP_SIZE, SFXPLAYER_RING_VISUAL_OBJECT_ID);
        *(u8*)(setup + 6) = 0xff;
        *(u8*)(setup + 7) = 0xff;
        *(u8*)(setup + 4) = 2;
        *(u8*)(setup + 5) = 1;
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x24) = -1;
        *(u8*)(setup + 0x1a) = 0;
        *(u8*)(setup + 0x18) = 0;
        *(u8*)(setup + 0x19) = 0;
        if ((*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) ==
            SFXPLAYER_MODE_SEQUENCE)
        {
            ringIds = (s16*)ringIdWords;
            *(u8*)(setup + 0x1b) = (u8)ringIds[ringIndex & 0xff];
        }
        else
        {
            *(u8*)(setup + 0x1b) = (u8) * (s16*)((char*)ringIdWords + 6);
        }
        *(u8*)(setup + 0x1c) = 0;
        *(u8*)(setup + 0x1d) = 0;
        *(u8*)(setup + 0x26) = 0x64;
        *(u8*)(setup + 0x27) = 0;
        *(u8*)(setup + 0x28) = 0;
        *(f32*)(setup + 0x20) = lbl_803E6478;
        *(u8*)(setup + 0x29) = 0xd2;
        *(u8*)(setup + 0x2a) = 0;
        *(int*)((int)handles + handleOffset) =
            Obj_SetupObject(setup, SFXPLAYER_RING_SETUP_MODE,
                            ((GameObject*)obj)->anim.mapEventSlot, -1,
                            *(int*)&((GameObject*)obj)->anim.parent);
    }

    pair = (int*)((int)gSfxplayerEffectHandles + handleOffset + 4);
    if (*pair == 0)
    {
        setup = Obj_AllocObjectSetup(SFXPLAYER_RING_HIT_SETUP_SIZE, SFXPLAYER_RING_HIT_OBJECT_ID);
        *(u8*)(setup + 6) = 0xff;
        *(u8*)(setup + 7) = 0xff;
        *(u8*)(setup + 4) = 2;
        *(u8*)(setup + 5) = 1;
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *pair = Obj_SetupObject(setup, SFXPLAYER_RING_SETUP_MODE,
                                ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
    }

    return 1;
}

int TrickyCurve_activateEffectHandleRing(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    SfxplayerState* state = *(SfxplayerState**)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
    int i;

    state->flags.bit80 = 1;
    gameTimerStop();
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            state->flags.bit10 = 1;
            state->ringCount = 0;
            GameBit_Set(state->activationEventId, 0);
            GameBit_Set(SFXPLAYER_GAMEBIT_RING_ACTIVE, 1);
            for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
            {
                sfxplayer_ensureEffectHandlePair(obj, i);
            }
            state->flags.bit40 = 1;
        }
    }

    TrickyCurve_updateEffectHandleRing(obj);
    return 0;
}

void sfxplayer_free(int obj, int arg1)
{
    int* handles;
    s16 i;

    if (arg1 == 0)
    {
        handles = gSfxplayerEffectHandles;
        for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
        {
            if (handles[0] != 0)
            {
                Obj_FreeObject(handles[0]);
            }
            handles[0] = 0;
            if (handles[1] != 0)
            {
                Obj_FreeObject(handles[1]);
            }
            handles[1] = 0;
            Sfx_PlayFromObject(obj, SFXPLAYER_TIMEOUT_RESET_SFX);
            handles += SFXPLAYER_EFFECT_HANDLES_PER_RING;
        }
    }
    gameTimerStop();
}

#undef SFXPLAYER_UPDATE_EFFECT_HANDLE_POS


/* Trivial 4b 0-arg blr leaves. */
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

void sfxplayer_render(void)
{
}

void sfxplayer_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int TrickyCurve_getExtraSize(void) { return 0x14; }
int TrickyCurve_getObjectTypeId(void) { return 0x0; }
int sfxplayer_getExtraSize(void) { return 0xa; }
int sfxplayer_getObjectTypeId(void) { return 0x0; }

extern void fn_80206C18(int* obj);
extern void fn_80206968(int* obj);

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
    ((TrickyCurveObjState*)state)->unk4 = (s16)((s32)((TrickyCurveObjectDef*)def)->unk18 << 2);
    *(s16*)state = ((TrickyCurveObjectDef*)def)->unk1A;
    ((TrickyCurveObjState*)state)->unk2 = ((TrickyCurveObjectDef*)def)->unk1C;
    state[0xe] = def[0x19];
    state[0x10] = 0;
    state[0x11] = 0;
    state[0x12] = 0;
    ((TrickyCurveObjState*)state)->unk8 = ((TrickyCurveObjectDef*)def)->unk20;
    ((TrickyCurveObjState*)state)->unkA = ((TrickyCurveObjectDef*)def)->unk1E;
    ((TrickyCurveObjState*)state)->unk6 = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}
