#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objseq.h"

typedef struct WMColrisePlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
} WMColrisePlacement;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */

/* wmlasertarget_getExtraSize == 0x4. */

/* WM_colrise_getExtraSize == 0x4. */
typedef struct WMColriseState
{
    s16 gameBit;
    u8 raiseTimer;
    u8 pad3;
} WMColriseState;

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

void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char cVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    int iVar5;
    u8 uVar8;
    float* pfVar6;
    uint uVar7;
    int iVar9;
    float fVar10;
    int iVar11;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined2* puVar12;
    undefined8 uVar13;
    int local_18[3];

    puVar12 = ((GameObject*)param_9)->extra;
    iVar5 = FUN_80017a98();
    if (*(char*)((int)puVar12 + 5) == '\0')
    {
        uVar8 = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *puVar12 = 0;
            puVar12[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            uVar8 = 1;
        }
        *(u8*)((int)puVar12 + 5) = uVar8;
        if (*(char*)((int)puVar12 + 5) != '\0')
        {
            *(u8*)(puVar12 + 3) = 1;
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
            fVar4 = lbl_803E6A24;
            fVar3 = lbl_803E6A20;
            fVar10 = 0.0;
            iVar11 = 0;
            iVar9 = 0;
            if (0 < iVar5)
            {
                do
                {
                    pfVar6 = *(float**)(local_18[0] + iVar9);
                    if (*(char*)(pfVar6 + 5) != '\x0e')
                    {
                        fVar2 = *pfVar6;
                        if ((((GameObject*)param_9)->anim.localPosY < fVar2) &&
                            ((fVar2 - fVar3 < ((GameObject*)param_9)->anim.localPosY || (iVar11 == 0))))
                        {
                            fVar10 = pfVar6[4];
                            ((GameObject*)param_9)->anim.localPosY = fVar2;
                            ((GameObject*)param_9)->anim.velocityY = fVar4;
                        }
                    }
                    iVar9 = iVar9 + 4;
                    iVar11 = iVar11 + 1;
                    iVar5 = iVar5 + -1;
                }
                while (iVar5 != 0);
            }
            if (fVar10 != 0.0)
            {
                iVar5 = *(int*)((int)fVar10 + 0x58);
                cVar1 = *(char*)(iVar5 + 0x10f);
                *(char*)(iVar5 + 0x10f) = cVar1 + '\x01';
                *(uint*)(iVar5 + cVar1 * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        uVar13 = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        uVar7 = FUN_80006c00(0);
        if ((uVar7 & 0x100) != 0)
        {
            *(u8*)(puVar12 + 3) = 0;
            uVar13 = FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)puVar12 + 5) = 2;
        }
        if ((*(char*)((int)puVar12 + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)puVar12 + 5) = 0;
            *(u8*)(puVar12 + 3) = 0;
        }
        if (*(char*)(puVar12 + 3) != '\0')
        {
            ObjMsg_SendToObject(uVar13, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar5, 0x100008,
                                param_9,CONCAT22(puVar12[1], *puVar12), in_r7, in_r8, in_r9, in_r10);
        }
    }
    return;
}

void FUN_801f2b94(short* param_1)
{
    int iVar1;
    double dVar2;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    iVar1 = FUN_80017a98();
    dVar2 = (double)FUN_8001771c((float*)(iVar1 + 0x18), (float*)(param_1 + 0xc));
    if ((double)lbl_803E6A80 <= dVar2)
    {
        FUN_8000680c((int)param_1, 0x40);
    }
    else
    {
        FUN_80006824((uint)param_1,SFXmn_eggylaugh216);
    }
    return;
}

extern f32 lbl_803E5D78;

void WM_colrise_free(void)
{
}

void WM_colrise_hitDetect(void)
{
}

void WM_colrise_release(void)
{
}

void WM_colrise_initialise(void)
{
}

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 timeDelta;
extern const f32 lbl_803E5DCC;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;
extern f32 lbl_803E5DE0;

void WM_colrise_update(int* obj)
{
    u8* def;
    WMColriseState* sub;
    s32 reached;
    f32 target;
    int i;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    sub->raiseTimer -= 1;
    if ((s8)sub->raiseTimer < 0) sub->raiseTimer = 0;
    if ((s8)*(s8*)((char*)*(int**)((char*)obj + 0x58) + 0x10f) > 0)
    {
        for (i = 0; i < (s8)*(s8*)((char*)*(int**)((char*)obj + 0x58) + 0x10f); i++)
        {
            int* p = *(int**)((char*)*(int**)((char*)obj + 0x58) + 0x100 + i * 4);
            if (*(f32*)((char*)p + 0x10) - ((GameObject*)obj)->anim.localPosY > lbl_803E5DCC)
            {
                sub->raiseTimer = 0x3c;
            }
        }
    }
    reached = 0;
    if ((sub->gameBit == -1 || (u32)GameBit_Get(sub->gameBit) != 0) && (s8)sub->raiseTimer != 0)
    {
        target = lbl_803E5DD0 + (lbl_803E5DD4 + ((WMColrisePlacement*)def)->unkC);
        if (((GameObject*)obj)->anim.localPosY > target)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5DD8 * timeDelta;
            if (((GameObject*)obj)->anim.localPosY > target)
            {
                ((GameObject*)obj)->anim.localPosY = target;
            }
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E5DDC * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY > target)
            {
                ((GameObject*)obj)->anim.localPosY = target;
            }
            else
            {
                reached = 1;
            }
        }
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5DE0 * timeDelta;
        if (((GameObject*)obj)->anim.localPosY < ((WMColrisePlacement*)def)->unkC)
        {
            ((GameObject*)obj)->anim.localPosY = ((WMColrisePlacement*)def)->unkC;
        }
        else
        {
            reached = 1;
        }
    }
    if ((s8)reached != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXmn_crusty9c);
    }
    else
    {
        Sfx_StopObjectChannel((int)obj, 8);
    }
}

void wmtorch_hitDetect(void);

int WM_colrise_getExtraSize(void) { return 0x4; }
int WM_colrise_getObjectTypeId(void) { return 0x0; }
int wmtorch_getExtraSize(void);

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5DC8;

void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5DC8);
}

int dll_1FF_getObjectTypeId(int* obj);

int WM_colrise_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

void LaserBeam_release(void);

void WM_colrise_init(s16* a, s8* b)
{
    WMColriseState* inner = ((GameObject*)a)->extra;
    ((GameObject*)a)->animEventCallback = (void*)WM_colrise_SeqFn;
    a[0] = (s16)((s32)b[0x18] << 8);
    inner->gameBit = *(s16*)(b + 0x1e);
}

extern int GameBit_Get(int id);

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */

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

#pragma opt_common_subs off
#pragma opt_common_subs reset
