#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objseq.h"

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

/* dll_1FF_getExtraSize == 0x8 (grabbable hook). */
typedef struct Dll1FFState
{
    s16 msgLo;
    s16 msgHi;
    u8 pad4;
    s8 grabPhase; /* 0 free, 1 held, 2 releasing */
    u8 sendFlag; /* 0x6 */
    u8 pad7;
} Dll1FFState;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern uint FUN_80017a98();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();

extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

extern f32 lbl_803E5D78;
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 timeDelta;
extern void objRenderFn_8003b8f4(f32);
extern int GameBit_Get(int id);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E5D80;
extern f32 lbl_803E5DC0;

void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char c;
    float entryY;
    float band;
    float riseVel;
    int iVar5;
    u8 phase;
    float* entry;
    uint buttons;
    int idx;
    float found;
    int i;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined2* b;
    undefined8 player;
    int local_18[3];

    b = ((GameObject*)param_9)->extra;
    iVar5 = FUN_80017a98();
    if (*(char*)((int)b + 5) == '\0')
    {
        phase = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *b = 0;
            b[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            phase = 1;
        }
        *(u8*)((int)b + 5) = phase;
        if (*(char*)((int)b + 5) != '\0')
        {
            *(u8*)(b + 3) = 1;
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
                                 (double)((GameObject*)param_9)->anim.localPosZ, param_9, local_18, 0, 1);
            riseVel = lbl_803E6A24;
            band = lbl_803E6A20;
            found = 0.0;
            i = 0;
            idx = 0;
            if (0 < iVar5)
            {
                do
                {
                    entry = *(float**)(local_18[0] + idx);
                    if (*(char*)(entry + 5) != '\x0e')
                    {
                        entryY = *entry;
                        if ((((GameObject*)param_9)->anim.localPosY < entryY) &&
                            ((entryY - band < ((GameObject*)param_9)->anim.localPosY || (i == 0))))
                        {
                            found = entry[4];
                            ((GameObject*)param_9)->anim.localPosY = entryY;
                            ((GameObject*)param_9)->anim.velocityY = riseVel;
                        }
                    }
                    idx = idx + 4;
                    i = i + 1;
                    iVar5 = iVar5 + -1;
                }
                while (iVar5 != 0);
            }
            if (found != 0.0)
            {
                iVar5 = *(int*)((int)found + 0x58);
                c = *(char*)(iVar5 + 0x10f);
                *(char*)(iVar5 + 0x10f) = c + '\x01';
                *(uint*)(iVar5 + c * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        player = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        buttons = FUN_80006c00(0);
        if ((buttons & 0x100) != 0)
        {
            *(u8*)(b + 3) = 0;
            player = FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)b + 5) = 2;
        }
        if ((*(char*)((int)b + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)b + 5) = 0;
            *(u8*)(b + 3) = 0;
        }
        if (*(char*)(b + 3) != '\0')
        {
            ObjMsg_SendToObject(player, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar5, 0x100008,
                                param_9,CONCAT22(b[1], *b), in_r7, in_r8, in_r9, in_r10);
        }
    }
    return;
}

void FUN_801f2b94(short* param_1)
{
    int handle;
    double dist;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    handle = FUN_80017a98();
    dist = (double)FUN_8001771c((float*)(handle + 0x18), (float*)(param_1 + 0xc));
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

void dll_1FF_free_nop(void)
{
}

void dll_1FF_hitDetect_nop(void)
{
}

void dll_1FF_release_nop(void)
{
}

void dll_1FF_initialise_nop(void)
{
}

int dll_1FF_getExtraSize_ret_8(void) { return 0x8; }
int dll_200_getExtraSize_ret_40(void);

int dll_1FF_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x146) return 0x2;
    return 0x0;
}

void LaserBeam_release(void);

void dll_1FF_init(s16* a, s8* b)
{
    a[0] = (s16)((s32)b[0x18] << 8);
    a[1] = -0x8000;
}

void WM_colrise_init(s16* a, s8* b);

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */

void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    s32 v;
    if (((GameObject*)obj)->unkF8 != 0)
    {
        v = visible;
        if (v != -1) return;
    }
    else
    {
        v = visible;
        if (v == 0) return;
    }
    if (((ObjAnimComponent*)obj)->modelInstance->shadowType == 2)
    {
        if (((GameObject*)obj)->seqIndex == -1)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        else
        {
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5D80);
}

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */

void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */

#pragma opt_strength_reduction off

#pragma opt_strength_reduction off

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

typedef struct Dll1FFSlot
{
    int obj;
} Dll1FFSlot;

typedef struct Dll1FFSlots
{
    u8 pad[0x100];
    Dll1FFSlot slots[3];
    u8 pad2[3];
    u8 count;
} Dll1FFSlots;

void dll_1FF_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern void buttonDisable(int a, int b);
    extern uint getButtonsJustPressed(int pad);
    extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int* list, int a, int b);
    extern f32 timeDelta;
    extern f32 lbl_803E5D84;
    extern const f32 lbl_803E5D88;
    extern const f32 lbl_803E5D8C;
    void* player;
    Dll1FFState* b;
    int flag;
    int count;
    char* found;
    int i;
    char* t;
    u8 c;
    char* p;
    int stk[2];

    b = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (b->grabPhase == 0)
    {
        flag = 0;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0 && ((GameObject*)obj)->unkF8 == 0)
        {
            b->msgLo = (s16)flag;
            b->msgHi = 0x28;
            buttonDisable(0, 0x100);
            flag = 1;
        }
        b->grabPhase = (s8)flag;
        if (b->grabPhase != 0)
        {
            b->sendFlag = 1;
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ObjHits_EnableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~
                8);
            ((GameObject*)obj)->anim.velocityY = -(lbl_803E5D84 * timeDelta - ((GameObject*)obj)->anim.velocityY);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->
                anim.localPosY;
            count = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                         ((GameObject*)obj)->anim.localPosZ, stk, 0, 1);
            found = NULL;
            for (i = 0; i < count; i++)
            {
                p = ((char**)stk[0])[i];
                if (*(s8*)(p + 0x14) != 14)
                {
                    if (((GameObject*)obj)->anim.localPosY < *(f32*)p)
                    {
                        if (((GameObject*)obj)->anim.localPosY > *(f32*)p - lbl_803E5D88 || i == 0)
                        {
                            found = *(char**)(p + 0x10);
                            ((GameObject*)obj)->anim.localPosY = *(f32*)p;
                            ((GameObject*)obj)->anim.velocityY = lbl_803E5D8C;
                        }
                    }
                }
            }
            if (found != NULL)
            {
                Dll1FFSlots* ts = *(Dll1FFSlots**)(found + 0x58);
                c = ts->count;
                ts->count += 1;
                ts->slots[(s8)c].obj = obj;
            }
        }
    }
    else
    {
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        if ((getButtonsJustPressed(0) & 0x100) != 0)
        {
            b->sendFlag = 0;
            buttonDisable(0, 0x100);
        }
        if (((GameObject*)obj)->unkF8 == 1)
        {
            b->grabPhase = 2;
        }
        if (b->grabPhase == 2 && ((GameObject*)obj)->unkF8 == 0)
        {
            b->grabPhase = 0;
            b->sendFlag = 0;
        }
        if (*(s8*)&b->sendFlag != 0)
        {
            ObjMsg_SendToObject(player, 0x100008, obj,
                                ((int)b->msgHi << 16) | ((int)b->msgLo & 0xffff));
        }
    }
}

#pragma opt_common_subs off
#pragma opt_common_subs reset
