#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/TrickyCurve.h"
#include "main/dll/sfxplayer.h"
#include "main/dll/infopoint.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
extern u32 FUN_80006824();
extern u32 FUN_800068c4();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern u32 FUN_80017748();
extern int randomGetRange(int lo, int hi);
extern int FUN_80017a98();
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
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int objType);
extern int Obj_SetupObject(int setup, int mode, int mapLayer, int objIndex, int parent);
extern void Obj_FreeObject(int obj);

extern void vecRotateZXY(s16 * rotation, f32 * outVec);
extern u32 lbl_803E6450;
typedef struct RingIdPair { u32 a; u32 b; } RingIdPair;
extern f32 timeDelta;
extern f32 lbl_803E6458;
extern f32 lbl_803E645C;
extern f32 lbl_803E6460;
extern f32 lbl_803E6464;
extern f32 lbl_803E6468;
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

/* Obj_AllocObjectSetup(0x2C,...) ring-visual spawn buffer composed in
 * sfxplayer_ensureEffectHandlePair. Head is the common ObjPlacement
 * (the 0x04..0x07 bytes live in ObjPlacement.color); tail (0x18..0x2B)
 * is file-local. */
typedef struct SfxplayerRingVisualSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 unk18;          /* 0x18 */
    u8 unk19;          /* 0x19 */
    u8 unk1A;          /* 0x1A */
    u8 ringId;         /* 0x1B */
    u8 unk1C;          /* 0x1C */
    u8 unk1D;          /* 0x1D */
    u8 pad1E[2];       /* 0x1E..0x1F */
    f32 unk20;         /* 0x20 */
    s16 unk24;         /* 0x24 */
    u8 unk26;          /* 0x26 */
    u8 unk27;          /* 0x27 */
    u8 unk28;          /* 0x28 */
    u8 unk29;          /* 0x29 */
    u8 unk2A;          /* 0x2A */
    u8 pad2B[1];       /* 0x2B */
} SfxplayerRingVisualSetup;

STATIC_ASSERT(offsetof(SfxplayerRingVisualSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(SfxplayerRingVisualSetup, ringId) == 0x1B);
STATIC_ASSERT(offsetof(SfxplayerRingVisualSetup, unk20) == 0x20);
STATIC_ASSERT(offsetof(SfxplayerRingVisualSetup, unk24) == 0x24);
STATIC_ASSERT(offsetof(SfxplayerRingVisualSetup, unk2A) == 0x2A);
STATIC_ASSERT(sizeof(SfxplayerRingVisualSetup) == 0x2C);

#pragma scheduling on
#pragma peephole on
extern int ObjHits_GetPriorityHit(int obj, u32* outHitObject, int* outSphereIndex, u32* outHitVolume);




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
    float savedF29Lo;
    float savedF29Hi;
    float savedF30Lo;
    float savedF30Hi;
    float savedF31Lo;
    float savedF31Hi;

    savedF31Lo = (float)savedF31;
    savedF31Hi = (float)savedPs31;
    savedF30Lo = (float)savedF30;
    savedF30Hi = (float)savedPs30;
    savedF29Lo = (float)savedF29;
    savedF29Hi = (float)savedPs29;
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
                rotX = SFXPLAYER_EFFECT_RING_ROT_STEP;
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
        FUN_800068c4((u32)obj, SFXPLAYER_RING_START_SFX);
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
    for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i = i + 1)
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
        angleStep = angleStep + SFXPLAYER_EFFECT_RING_ROT_STEP;
    }
    return;
}

#define SFXPLAYER_UPDATE_EFFECT_HANDLE_POS(handleExpr, obj, rot, angleStep) \
    do { \
        if ((void *)(handleExpr) != NULL) { \
            *(f32 *)((handleExpr) + 0xc) = lbl_803E6460; \
            *(f32 *)((handleExpr) + 0x10) = lbl_803E6464; \
            *(f32 *)((handleExpr) + 0x14) = lbl_803E6468; \
            (rot)[0] = (s16)(*(s16 *)(obj) + (angleStep)); \
            vecRotateZXY((rot), (f32 *)((handleExpr) + 0xc)); \
            *(f32 *)((handleExpr) + 0xc) += *(f32 *)((obj) + 0xc); \
            *(f32 *)((handleExpr) + 0x10) += *(f32 *)((obj) + 0x10); \
            *(f32 *)((handleExpr) + 0x14) += *(f32 *)((obj) + 0x14); \
        } \
    } while (0)

#pragma scheduling off
#pragma peephole off
void TrickyCurve_updateEffectHandleRing(int obj)
{
    struct
    {
        s16 rotation[4];
        f32 baseVec[4];
    } buf;
    int* handles;
    SfxplayerState* state = *(SfxplayerState**)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
    s16 i;

    if (state->flags.bit10 != 0 && state->flags.bit20 == 0 && state->variantSfxTimer > 0x32)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXPLAYER_RING_START_SFX);
        if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) ==
            SFXPLAYER_MODE_SEQUENCE)
        {
            *(s16*)obj += (int)((lbl_803E6458 + state->ringCount) * (lbl_803E645C * timeDelta));
        }
        else
        {
            *(s16*)obj += (int)(lbl_803E645C * timeDelta);
        }
    }

    if (state->variantSfxTimer != 0 && state->flags.bit10 != 0)
    {
        state->variantSfxTimer -= (s16)timeDelta;
        if (state->variantSfxTimer <= 0)
        {
            state->variantSfxTimer = 200;
        }
    }

    buf.baseVec[1] = lbl_803E6460;
    buf.baseVec[2] = lbl_803E6460;
    buf.baseVec[3] = lbl_803E6460;
    buf.baseVec[0] = lbl_803E6458;
    buf.rotation[1] = buf.rotation[2] = 0;
    handles = gSfxplayerEffectHandles;

    for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
    {
        SFXPLAYER_UPDATE_EFFECT_HANDLE_POS(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING], obj, buf.rotation, i * SFXPLAYER_EFFECT_RING_ROT_STEP);
        SFXPLAYER_UPDATE_EFFECT_HANDLE_POS(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1], obj, buf.rotation, i * SFXPLAYER_EFFECT_RING_ROT_STEP);
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

    *(RingIdPair*)ringIdWords = *(RingIdPair*)&lbl_803E6450;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }

    handleOffset = (ringIndex & 0xff) * 8;
    handles = gSfxplayerEffectHandles;
    if (*(void**)((int)handles + handleOffset) == NULL)
    {
        setup = Obj_AllocObjectSetup(SFXPLAYER_RING_VISUAL_SETUP_SIZE, SFXPLAYER_RING_VISUAL_OBJECT_ID);
        ((SfxplayerRingVisualSetup*)setup)->base.color[2] = 0xff;
        ((SfxplayerRingVisualSetup*)setup)->base.color[3] = 0xff;
        ((SfxplayerRingVisualSetup*)setup)->base.color[0] = 2;
        ((SfxplayerRingVisualSetup*)setup)->base.color[1] = 1;
        ((SfxplayerRingVisualSetup*)setup)->base.posX = ((GameObject*)obj)->anim.localPosX;
        ((SfxplayerRingVisualSetup*)setup)->base.posY = ((GameObject*)obj)->anim.localPosY;
        ((SfxplayerRingVisualSetup*)setup)->base.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((SfxplayerRingVisualSetup*)setup)->unk24 = -1;
        ((SfxplayerRingVisualSetup*)setup)->unk1A = 0;
        ((SfxplayerRingVisualSetup*)setup)->unk18 = 0;
        ((SfxplayerRingVisualSetup*)setup)->unk19 = 0;
        if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) ==
            SFXPLAYER_MODE_SEQUENCE)
        {
            ringIds = (s16*)ringIdWords;
            ((SfxplayerRingVisualSetup*)setup)->ringId = ringIds[ringIndex & 0xff];
        }
        else
        {
            ((SfxplayerRingVisualSetup*)setup)->ringId = (u8) * (s16*)((char*)ringIdWords + 6);
        }
        ((SfxplayerRingVisualSetup*)setup)->unk1C = 0;
        ((SfxplayerRingVisualSetup*)setup)->unk1D = 0;
        ((SfxplayerRingVisualSetup*)setup)->unk26 = 0x64;
        ((SfxplayerRingVisualSetup*)setup)->unk27 = 0;
        ((SfxplayerRingVisualSetup*)setup)->unk28 = 0;
        ((SfxplayerRingVisualSetup*)setup)->unk20 = lbl_803E6478;
        ((SfxplayerRingVisualSetup*)setup)->unk29 = 0xd2;
        ((SfxplayerRingVisualSetup*)setup)->unk2A = 0;
        *(int*)((int)handles + handleOffset) =
            Obj_SetupObject(setup, SFXPLAYER_RING_SETUP_MODE,
                            ((GameObject*)obj)->anim.mapEventSlot, -1,
                            *(int*)&((GameObject*)obj)->anim.parent);
    }

    {
        u8* pairBase = (u8*)gSfxplayerEffectHandles + 4;
        pair = (int*)(pairBase + ((ringIndex & 0xff) * 8));
    }
    if (*(void**)pair == NULL)
    {
        setup = Obj_AllocObjectSetup(SFXPLAYER_RING_HIT_SETUP_SIZE, SFXPLAYER_RING_HIT_OBJECT_ID);
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        ((ObjPlacement*)setup)->color[0] = 2;
        ((ObjPlacement*)setup)->color[1] = 1;
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
        switch ((int)animUpdate->eventIds[i])
        {
        case 1:
            state->flags.bit10 = 1;
            state->ringCount = 0;
            GameBit_Set(state->activationEventId, 0);
            GameBit_Set(SFXPLAYER_GAMEBIT_RING_ACTIVE, 1);
            for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
            {
                sfxplayer_ensureEffectHandlePair(obj, i);
            }
            state->flags.bit40 = 1;
            break;
        }
    }

    TrickyCurve_updateEffectHandleRing(obj);
    return 0;
}

void sfxplayer_free(int obj, int arg1)
{
    u32* handles;
    s16 i;

    if (arg1 == 0)
    {
        handles = (u32*)gSfxplayerEffectHandles;
        for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
        {
            if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] != 0)
            {
                Obj_FreeObject(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING]);
            }
            handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] = 0;
            if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1] != 0)
            {
                Obj_FreeObject(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1]);
            }
            handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1] = 0;
            Sfx_PlayFromObject(obj, SFXPLAYER_TIMEOUT_RESET_SFX);
        }
    }
    gameTimerStop();
}

#undef SFXPLAYER_UPDATE_EFFECT_HANDLE_POS

void TrickyCurve_render(void);

void sfxplayer_render(void)
{
}

void sfxplayer_hitDetect(void)
{
}

int TrickyCurve_getExtraSize(void);
int sfxplayer_getExtraSize(void) { return 0xa; }
int sfxplayer_getObjectTypeId(void) { return 0x0; }

#define SFXPLAYER_OBJECT_FLAGS_OFFSET 0xB0
#define SFXPLAYER_OBJECT_STATE_OFFSET 0xB8
#define SFXPLAYER_OBJECT_CALLBACK_OFFSET 0xBC
#define SFXPLAYER_CONFIG_MAP_ID_OFFSET 0x18
#define SFXPLAYER_CONFIG_MODE_OFFSET 0x19
#define SFXPLAYER_CONFIG_EVENT_ID_OFFSET 0x1E
#define SFXPLAYER_CONFIG_FIELD20_OFFSET 0x20
#define SFXPLAYER_EFFECT_RING_COUNT 4
#define SFXPLAYER_EFFECT_HANDLES_PER_RING 2
#define SFXPLAYER_COMPLETE_RING_COUNT 4
#define SFXPLAYER_TIMER_ID 0x1D
#define SFXPLAYER_TIMER_SHORT_FRAMES 0x96
#define SFXPLAYER_TIMER_LONG_FRAMES 0xB4
#define SFXPLAYER_MODE_SINGLE 1
#define SFXPLAYER_GAMEBIT_RING_ACTIVE 0xEDF
#define SFXPLAYER_GAMEBIT_SINGLE_COMPLETE 0x9F7
#define SFXPLAYER_SFX_COMPLETE 0x7E
#define SFXPLAYER_SFX_TIMEOUT_RESET 0x1CE
#define SFXPLAYER_SFX_RING_HIT 0x409
#define SFXPLAYER_HIT_TYPE_RING_TARGET 0x13
#define SFXPLAYER_OBJECT_FLAGS 0x6000

void sfxplayer_update(int obj)
{
    u32* handles;
    s16 i;
    s16 hitType;
    u8 mode;
    SfxplayerState* state;
    SfxplayerStateFlags* flags;
    u32 hitObj;

    state = *(SfxplayerState**)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
    flags = &state->flags;
    if ((flags->bit20 == 0) && (GameBit_Get(state->eventId) == 0))
    {
        if (state->ringCount == SFXPLAYER_COMPLETE_RING_COUNT)
        {
            Sfx_PlayFromObject(0,SFXPLAYER_SFX_COMPLETE);
            flags->bit20 = 1;
            flags->bit10 = 0;
            flags->bit40 = 0;
            GameBit_Set(state->eventId, 1);
            GameBit_Set(SFXPLAYER_GAMEBIT_RING_ACTIVE, 0);
            mode = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
            if (mode == SFXPLAYER_MODE_SINGLE)
            {
                GameBit_Set(SFXPLAYER_GAMEBIT_SINGLE_COMPLETE, 1);
            }
            gameTimerStop();
        }
        else
        {
            if (flags->bit80 != 0)
            {
                flags->bit80 = 0;
                if (flags->bit10 != 0)
                {
                    mode = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
                    if (mode == SFXPLAYER_MODE_SINGLE)
                    {
                        gameTimerInit(SFXPLAYER_TIMER_ID,SFXPLAYER_TIMER_SHORT_FRAMES);
                    }
                    else
                    {
                        gameTimerInit(SFXPLAYER_TIMER_ID,SFXPLAYER_TIMER_LONG_FRAMES);
                    }
                    timerSetToCountUp();
                }
            }
            if (isGameTimerDisabled() != 0)
            {
                handles = (u32*)gSfxplayerEffectHandles;
                for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
                {
                    if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] != 0)
                    {
                        Obj_FreeObject(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING]);
                    }
                    handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] = 0;
                    if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1] != 0)
                    {
                        Obj_FreeObject(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1]);
                    }
                    handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1] = 0;
                    Sfx_PlayFromObject(obj,SFXPLAYER_SFX_TIMEOUT_RESET);
                }
                state->ringCount = 0;
                flags->bit40 = 0;
                flags->bit10 = 0;
                GameBit_Set(SFXPLAYER_GAMEBIT_RING_ACTIVE, 0);
            }
            TrickyCurve_updateEffectHandleRing(obj);
            handles = (u32*)gSfxplayerEffectHandles;
            for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++)
            {
                if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] != 0)
                {
                    hitObj = 0;
                    hitType = ObjHits_GetPriorityHit(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1], &hitObj, 0x0, 0x0);
                    if (hitType == SFXPLAYER_HIT_TYPE_RING_TARGET)
                    {
                        mode = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
                        if ((mode == SFXPLAYER_MODE_SINGLE) || (*(int*)((int)hitObj + 0xf4) == i))
                        {
                            if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] != 0)
                            {
                                Obj_FreeObject(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING]);
                            }
                            handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING] = 0;
                            if (handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1] != 0)
                            {
                                Obj_FreeObject(handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1]);
                            }
                            handles[i * SFXPLAYER_EFFECT_HANDLES_PER_RING + 1] = 0;
                            Sfx_PlayFromObject(0,SFXPLAYER_SFX_RING_HIT);
                            state->ringCount++;
                        }
                    }
                }
            }
        }
    }
    return;
}

void sfxplayer_init(int obj, int config)
{
    SfxplayerState* state;

    state = *(SfxplayerState**)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
    *(s16*)obj = (s16)((s8) * (u8*)(config + SFXPLAYER_CONFIG_MAP_ID_OFFSET) << 8);
    *(void (**)(void))(obj + SFXPLAYER_OBJECT_CALLBACK_OFFSET) =
        (void (*)(void))TrickyCurve_activateEffectHandleRing;
    state->config19 = *(u8*)(config + SFXPLAYER_CONFIG_MODE_OFFSET);
    state->eventId = *(s16*)(config + SFXPLAYER_CONFIG_EVENT_ID_OFFSET);
    state->unk2 = *(s16*)(config + SFXPLAYER_CONFIG_FIELD20_OFFSET);
    state->unk4 = 1;
    gSfxplayerEffectHandles[0] = 0;
    gSfxplayerEffectHandles[1] = 0;
    gSfxplayerEffectHandles[2] = 0;
    gSfxplayerEffectHandles[3] = 0;
    gSfxplayerEffectHandles[4] = 0;
    gSfxplayerEffectHandles[5] = 0;
    gSfxplayerEffectHandles[6] = 0;
    gSfxplayerEffectHandles[7] = 0;
    gameTimerStop();
    if (GameBit_Get(state->eventId) != 0)
    {
        state->flags.bit20 = 1;
    }
    *(u16*)(obj + SFXPLAYER_OBJECT_FLAGS_OFFSET) =
        *(u16*)(obj + SFXPLAYER_OBJECT_FLAGS_OFFSET) | SFXPLAYER_OBJECT_FLAGS;
}

void sfxplayer_release(void)
{
}

void sfxplayer_initialise(void)
{
}
