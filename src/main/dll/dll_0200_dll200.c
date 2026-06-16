#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/objseq.h"

typedef struct IntVec3
{
    int a;
    int b;
    int c;
} IntVec3;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */

/* wmlasertarget_getExtraSize == 0x4. */

/* WM_colrise_getExtraSize == 0x4. */

/* wmtorch_getExtraSize == 0x10. */

/* lightsource_getExtraSize == 0x1c. */
typedef struct LightSourceState
{
    void* light;
    f32 fxTimer;
    u8 pad08[4];
    f32 sparkTimer;
    int gameBit; /* 0x10: -1 none */
    u8 mode; /* 0x14: 1 = hit-toggleable */
    u8 fxType;
    u8 fxArg;
    u8 lit; /* 0x17 */
    u8 litPrev;
    u8 sparks; /* 0x19 */
    u8 loopFlags; /* 0x1a: LightSourceFlagByte */
    u8 pad1B;
} LightSourceState;

STATIC_ASSERT(sizeof(LightSourceState) == 0x1c);

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern uint FUN_80017a98();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();
extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

extern f32 timeDelta;
extern void objRenderFn_8003b8f4(f32);
extern int GameBit_Get(int id);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E5DC0;
extern f32 lbl_803E5D98;
extern void playerAddRemoveMagic(int player, int amount);
extern void fn_80296474(int player, int a, int b);
extern void GameBit_Set(int slot, int val);
extern ObjHitReactEntry lbl_80328898[];

void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char hitCount;
    float floorY;
    float floorMargin;
    float fallVel;
    int iVar5;
    u8 wasReset;
    float* collider;
    uint inputBits;
    int colByteOff;
    float landedObj;
    int colIdx;
    undefined2* state;
    int colList[3];

    state = ((GameObject*)param_9)->extra;
    iVar5 = FUN_80017a98();
    if (*(char*)((int)state + 5) == '\0')
    {
        wasReset = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *state = 0;
            state[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            wasReset = 1;
        }
        *(u8*)((int)state + 5) = wasReset;
        if (*(char*)((int)state + 5) != '\0')
        {
            *(u8*)(state + 3) = 1;
        }
        if (((GameObject*)param_9)->unkF8 == 0)
        {
            ObjHits_EnableObject(param_9);
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode & 0xf7;
            ((GameObject*)param_9)->anim.velocityY = -(lbl_803E6A1C * lbl_803DC074 - ((GameObject*)param_9)->anim.
                velocityY);
            ((GameObject*)param_9)->anim.localPosY =
                ((GameObject*)param_9)->anim.velocityY * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosY;
            iVar5 = FUN_800632f4((double)((GameObject*)param_9)->anim.localPosX,
                                 (double)((GameObject*)param_9)->anim.localPosY,
                                 (double)((GameObject*)param_9)->anim.localPosZ, param_9, colList, 0, 1);
            fallVel = lbl_803E6A24;
            floorMargin = lbl_803E6A20;
            landedObj = 0.0;
            colIdx = 0;
            colByteOff = 0;
            if (0 < iVar5)
            {
                do
                {
                    collider = *(float**)(colList[0] + colByteOff);
                    if (*(char*)(collider + 5) != '\x0e')
                    {
                        floorY = *collider;
                        if ((((GameObject*)param_9)->anim.localPosY < floorY) &&
                            ((floorY - floorMargin < ((GameObject*)param_9)->anim.localPosY || (colIdx == 0))))
                        {
                            landedObj = collider[4];
                            ((GameObject*)param_9)->anim.localPosY = floorY;
                            ((GameObject*)param_9)->anim.velocityY = fallVel;
                        }
                    }
                    colByteOff = colByteOff + 4;
                    colIdx = colIdx + 1;
                    iVar5 = iVar5 + -1;
                }
                while (iVar5 != 0);
            }
            if (landedObj != 0.0)
            {
                iVar5 = *(int*)((int)landedObj + 0x58);
                hitCount = *(char*)(iVar5 + 0x10f);
                *(char*)(iVar5 + 0x10f) = hitCount + '\x01';
                *(uint*)(iVar5 + hitCount * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        inputBits = FUN_80006c00(0);
        if ((inputBits & 0x100) != 0)
        {
            *(u8*)(state + 3) = 0;
            FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)state + 5) = 2;
        }
        if ((*(char*)((int)state + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)state + 5) = 0;
            *(u8*)(state + 3) = 0;
        }
        if (*(char*)(state + 3) != '\0')
        {
            ObjMsg_SendToObject(iVar5, 0x100008, param_9, CONCAT22(state[1], *state));
        }
    }
    return;
}

#pragma dont_inline on
void fn_801F20D4(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern int lbl_802C247C[];
    extern void buttonDisable(int a, int b);
    extern u8 framesThisStep;
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    extern f32 lbl_803E5DA0;
    extern void GameBit_Set(int slot, int val);
    extern uint GameBit_Get(int id);
    int sub;
    IntVec3 stk;

    sub = *(int*)&((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    stk = *(IntVec3*)lbl_802C247C;
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x8) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode ^= 0x8;
    }
    if (GameBit_Get(763) == 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 7)
        {
            ObjAnim_SetCurrentMove(obj, 7, lbl_803E5D98, 0);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
            (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
            (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x1) != 0 && GameBit_Get(763) == 0)
    {
        GameBit_Set(763, 1);
        *(u8*)(sub + 0x27) = 0;
        buttonDisable(0, 256);
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x1) != 0)
    {
        if ((*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&stk, 3) > -1)
        {
            GameBit_Set(784, 1);
            *(u8*)(sub + 0x27) += 1;
            buttonDisable(0, 256);
        }
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_801F27E4(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern int fn_80296A14(void);
    extern void buttonDisable(int a, int b);
    extern u8 framesThisStep;
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    extern f32 lbl_803E5DA0;
    extern void GameBit_Set(int slot, int val);
    extern uint GameBit_Get(int id);
    int sub;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.currentMove != 2)
    {
        ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    *(u8*)(sub + 0x24) = 1;
    if (*(u8*)(sub + 0x24) == 0)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x1) != 0)
        {
            GameBit_Set(208, 1);
            *(u8*)(sub + 0x24) = 1;
            buttonDisable(0, 256);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x1) != 0)
        {
            Obj_GetPlayerObject();
            if (fn_80296A14() > 0)
            {
                *(u8*)(sub + 0x25) = 2;
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                buttonDisable(0, 256);
            }
            else
            {
                if (GameBit_Get(177) == 0 || GameBit_Get(178) == 0 || GameBit_Get(179) == 0)
                {
                    *(u8*)(sub + 0x25) = 1;
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    buttonDisable(0, 256);
                }
            }
        }
    }
}
#pragma dont_inline reset

void FUN_801f2b94(short* param_1)
{
    int player;
    double dist;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    player = FUN_80017a98();
    dist = (double)FUN_8001771c((float*)(player + 0x18), (float*)(param_1 + 0xc));
    if ((double)lbl_803E6A80 <= dist)
    {
        FUN_8000680c((int)param_1, 0x40);
    }
    else
    {
        FUN_80006824((uint)param_1,SFXmn_eggylaugh216);
    }
    return;
}

void dll_200_free_nop(void)
{
}

void dll_200_hitDetect_nop(void)
{
}

void dll_200_release_nop(void)
{
}

void dll_200_initialise_nop(void)
{
}

void WM_colrise_free(void);

int dll_200_getExtraSize_ret_40(void) { return 0x28; }
int dll_200_getObjectTypeId(void) { return 0x1; }
int WM_colrise_getExtraSize(void);

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */

void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    s32 v = visible;
    int areaId;
    if (v == 0) return;
    areaId = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    if ((u8)areaId == 4)
    {
        if ((u32)GameBit_Get(0x2bd) == 0u) return;
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5DC0);
        return;
    }
    objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5DC0);
}

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */

void dll_200_init(int* obj, int* arg)
{
    Dll200State* b;
    ((GameObject*)obj)->unkF4 = 0;
    *(s16*)obj = (s16)((s32)*(s8*)((char*)arg + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dll_200_SeqFn;
    b = ((GameObject*)obj)->extra;
    b->defNoLow = (u8)*(s16*)arg;
    b->unk1C = 0;
    b->unk18 = 0;
    b->homeX = *(f32*)((char*)arg + 0x8);
    b->homeY = *(f32*)((char*)arg + 0xc);
    b->homeZ = *(f32*)((char*)arg + 0x10);
    b->latch24 = (u8)GameBit_Get(0xd0);
    b->counter27 = 0;
    b->mode = 1;
    b->prevMode = 0xc;
    b->modeTimer = 0x12c;
    b->animSpeed = lbl_803E5D98;
    b->unk14 = lbl_803E5DC0;
}

int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

#pragma opt_strength_reduction off
int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int arg3)
{
    u8 mode;
    int i;
    int state;

    mode = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        fn_801F2974((int*)obj, unused, animUpdate, arg3);
        break;
    case 4:
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        break;
    case 6:
        state = *(int*)&((GameObject*)obj)->extra;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        for (i = 0; i < (int)animUpdate->eventCount; i++)
        {
            switch (animUpdate->eventIds[i])
            {
            case 0:
                break;
            case 1:
                if (*(u8*)&((Dll200State*)state)->counter27 >= 2)
                {
                    GameBit_Set(0x314, 1);
                }
                break;
            }
        }
        break;
    case 0:
        break;
    case 2:
        break;
    case 3:
        break;
    case 5:
        break;
    }
    return 0;
}

#pragma opt_strength_reduction off
int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3)
{
    int state;
    int player;
    int i;

    player = Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);

    for (i = 0; i < (int)animUpdate->eventCount; i++)
    {
        u8 mode = ((Dll200State*)state)->mode25;
        if (mode == 1)
        {
            if (animUpdate->eventIds[i] == 4)
            {
                playerAddRemoveMagic(player, 5);
            }
        }
        else if (mode != 2)
        {
            u8 eventId = animUpdate->eventIds[i];
            if (eventId == 1)
            {
                GameBit_Set(208, 1);
                ((Dll200State*)state)->latch24 = 1;
            }
            else if (eventId == 2)
            {
                fn_80296474(player, 0, 1);
                playerAddRemoveMagic(player, 5);
            }
        }
    }
    return 0;
}

void fn_801F2290(int obj);

void dll_200_update(int obj)
{
    extern u8 framesThisStep;
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    u8 ev;
    u8 ret;
    Dll200State* b;

    b = ((GameObject*)obj)->extra;
    ret = ObjHitReact_Update(obj, lbl_80328898, 11,
                             (u8)((b->mode & 0x80) ? 1 : 0),
                             &b->hitReactVec);
    if (ret != 0)
    {
        b->mode = (u8)(b->mode | 0x80);
    }
    else
    {
        b->mode = (u8)(b->mode & ~0x80);
        ev = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
        switch (ev)
        {
        case 1:
            fn_801F27E4(obj);
            break;
        case 2:
            fn_801F2290(obj);
            break;
        case 4:
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
            if (((GameObject*)obj)->anim.currentMove != 2)
            {
                ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
            }
            ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
            break;
        case 6:
            fn_801F20D4(obj);
            break;
        case 0:
            return;
        case 3:
            return;
        case 5:
            return;
        }
    }
}

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

#pragma opt_common_subs off
#pragma opt_common_subs reset


typedef struct ArwAttachTarget
{
    f32 x;
    f32 y;
    f32 moveId;
    f32 altMoveId;
    f32 speed;
} ArwAttachTarget;

void fn_801F2290(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int id);
    extern void GameBit_Set(int slot, int val);
    extern void buttonDisable(int a, int b);
    extern int getAngle(f32 x, f32 y);
    extern f32 sqrtf(f32 x);
    extern void fn_80137948(char* fmt, ...);
    extern int lbl_802C2470[];
    extern ArwAttachTarget lbl_80328974[];
    extern char sArwingAttachmentDiffFormat[];
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5DA8;
    extern f32 lbl_803E5DAC;
    extern f32 lbl_803E5DB0;
    extern f32 lbl_803E5DB4;
    Dll200State* b;
    u8 m;
    s16 ang;
    s16 diff;
    f32 dx;
    f32 dy;
    f32 dist;
    f32 spd;
    IntVec3 stk;
    ObjAnimEventList animEvents;

    b = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    stk = *(IntVec3*)lbl_802C2470;
    ((GameObject*)obj)->anim.localPosY = b->homeY;
    if (GameBit_Get(0x1fc) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0 &&
            (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&stk, 3) > -1)
        {
            GameBit_Set(0x4d1, 1);
            b->counter27 += 1;
            GameBit_Set(0x310, 1);
            buttonDisable(0, 0x100);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        if (b->modeTimer <= 0)
        {
            switch (randomGetRange(1, 4))
            {
            case 1:
                b->prevMode = (u8)b->mode;
                b->mode = 1;
                b->modeTimer = 400;
                break;
            case 2:
                b->prevMode = (u8)b->mode;
                b->mode = 2;
                b->modeTimer = 400;
                break;
            case 3:
                b->prevMode = (u8)b->mode;
                b->mode = 3;
                b->modeTimer = 400;
                break;
            case 4:
                b->prevMode = (u8)b->mode;
                b->mode = 4;
                b->modeTimer = 400;
                break;
            case 5:
                b->prevMode = (u8)b->mode;
                b->mode = 5;
                b->modeTimer = 400;
                break;
            }
        }
        else
        {
            m = b->mode;
            if (m == 12)
            {
                ang = getAngle(lbl_80328974[b->prevMode].x,
                               lbl_80328974[b->prevMode].y);
                diff = (s16)(ang - *(s16*)obj);
                fn_80137948(sArwingAttachmentDiffFormat, diff);
                if (diff < -1000 || diff > 1000)
                {
                    if (diff > 0)
                    {
                        *(s16*)obj = (s16)(*(s16*)obj + framesThisStep * 100);
                    }
                    else
                    {
                        *(s16*)obj = (s16)(*(s16*)obj - framesThisStep * 100);
                    }
                }
                else
                {
                    ObjAnim_SetCurrentMove(obj, (int)lbl_80328974[b->prevMode].moveId,
                                           lbl_803E5D98, 0);
                    b->animSpeed = lbl_80328974[b->prevMode].speed;
                    b->mode = 13;
                }
            }
            else if (m == 13)
            {
                if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, b->animSpeed, timeDelta, &animEvents) != 0)
                {
                    if ((f32)(int)((GameObject*)obj)->anim.currentMove ==
                        lbl_80328974[b->prevMode].moveId)
                    {
                        ObjAnim_SetCurrentMove(obj,
                                               (int)lbl_80328974[b->prevMode].altMoveId,
                                               lbl_803E5D98, 0);
                        b->animSpeed = lbl_80328974[b->prevMode].speed;
                    }
                }
                b->modeTimer -= framesThisStep;
                if (b->modeTimer <= 0)
                {
                    b->modeTimer = 0;
                }
            }
            else
            {
                dx = lbl_80328974[m].x - (((GameObject*)obj)->anim.localPosX - b->homeX);
                dy = lbl_80328974[m].y - (((GameObject*)obj)->anim.localPosZ - b->homeZ);
                dist = sqrtf(dx * dx + dy * dy);
                ang = getAngle(dx, dy);
                diff = (s16)(ang - *(s16*)obj);
                if (diff >= -1000 && diff <= 1000)
                {
                    if (((GameObject*)obj)->anim.currentMove != 59)
                    {
                        ObjAnim_SetCurrentMove(obj, 59, lbl_803E5D98, 0);
                        b->animSpeed = lbl_803E5DA8;
                    }
                    spd = lbl_803E5DAC;
                    ((GameObject*)obj)->anim.velocityX = spd * (dx / dist);
                    ((GameObject*)obj)->anim.velocityZ = spd * (dy / dist);
                    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)
                        (obj, spd, &b->animSpeed);
                }
                else
                {
                    if (((GameObject*)obj)->anim.currentMove != 12)
                    {
                        ObjAnim_SetCurrentMove(obj, 12, lbl_803E5D98, 0);
                        b->animSpeed = lbl_803E5DB0;
                    }
                    if (diff > 0)
                    {
                        *(s16*)obj = (s16)(*(s16*)obj + framesThisStep * 300);
                    }
                    else
                    {
                        *(s16*)obj = (s16)(*(s16*)obj - framesThisStep * 300);
                    }
                }
                if (dist < lbl_803E5DB4)
                {
                    b->prevMode = (u8)b->mode;
                    b->mode = 12;
                    spd = lbl_803E5D98;
                    ((GameObject*)obj)->anim.velocityX = spd;
                    ((GameObject*)obj)->anim.velocityZ = spd;
                }
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)
                    ->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)
                    ->anim.localPosZ;
                ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, b->animSpeed, timeDelta, &animEvents);
            }
        }
    }
}
