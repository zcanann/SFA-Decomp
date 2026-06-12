#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/dll/LGT/LGTpointlight.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "global.h"

typedef struct LaserBeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} LaserBeamPlacement;


typedef struct WMColrisePlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
} WMColrisePlacement;


typedef struct LightsourceState
{
    u8 pad0[0x4C - 0x0];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 pad2F9[0x300 - 0x2F9];
} LightsourceState;


typedef struct WmlasertargetPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x1A - 0x10];
    s16 cooldown;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WmlasertargetPlacement;


typedef struct PressureswitchPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x1A - 0x10];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} PressureswitchPlacement;


/* Per-object extra state for the WM laser beam emitter. */
typedef struct LaserBeamState
{
    int texture;
    f32 unk04; /* 0x04: cur/prev pair A (reset each update) */
    f32 unk08;

    f32 beamX; /* 0x0c: beam base position */
    f32 beamX2; /* 0x10 */
    f32 beamZ; /* 0x14 */
    f32 beamZ2; /* 0x18 */
    f32 sweepPhase; /* 0x1c */
    u8 pad20[4];
    u8 unk24;
    u8 unk25;
    u8 unk26;
    s8 unk27;
    s16 unk28;
    s16 sweepYaw; /* 0x2a */
    s16 fireTimer; /* 0x2c */
    s16 unk2E;
    s16 firePeriod; /* 0x30 */
    s16 emitterSlot; /* 0x32: modgfx handle head */
    u8 pad34[0xc];
    f32 targetX; /* 0x40 */
    u8 pad44[4];
    f32 targetZ; /* 0x48 */
    u8 unk4C;
    u8 active; /* 0x4d */
    u8 beamKind; /* 0x4e: 30/1/other texture pick */
} LaserBeamState;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */
typedef struct PressureSwitchState
{
    s8 holdTimer; /* frames the switch stays pressed */
    s8 chimeLatch;
    s16 retriggerTimer;
    s16 mapGameBit; /* 0xf45/0xf46 per-map bit, -1 none */
    u8 flags; /* PressureSwitchFlags / PswFlags overlay */
    u8 pad7;
} PressureSwitchState;

/* wmlasertarget_getExtraSize == 0x4. */
typedef struct WmLaserTargetState
{
    s16 cooldown;
    u8 toggleQueued;
    u8 pad3;
} WmLaserTargetState;

/* WM_colrise_getExtraSize == 0x4. */
typedef struct WMColriseState
{
    s16 gameBit;
    u8 raiseTimer;
    u8 pad3;
} WMColriseState;

/* wmtorch_getExtraSize == 0x10. */
typedef struct WmTorchState
{
    void* linkedObj;
    f32 unk04;
    u8 pad08[2];
    s16 unk0A;
    u8 torchType; /* params[0x19]: 0 / 0x7f / other */
    u8 pad0D[3];
} WmTorchState;

/* lightsource_getExtraSize == 0x1c.  LightSourceState lives in the shared
 * LGTpointlight header (same 0x206 DLL); this fragment's 0x0C timer is the
 * header's unk0C field. */

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

/* dll_200_getExtraSize == 0x28 (kid attachment actor). */
typedef struct Dll200State
{
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    f32 animSpeed; /* 0x0c */
    f32 hitReactVec; /* 0x10: head of the f32 pair ObjHitReact_Update fills */
    f32 unk14;
    s16 unk18;
    u8 pad1A[2];
    u32 unk1C;
    s16 modeTimer; /* 0x20 */
    u8 mode; /* 0x22: 1-5 wander, 12 turn, 13 play */
    u8 prevMode; /* 0x23 */
    u8 latch24; /* 0x24: GameBit 0xd0 latch */
    u8 mode25; /* 0x25: trigger pick */
    u8 defNoLow; /* 0x26 */
    s8 counter27; /* 0x27: hug/talk counter */
} Dll200State;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern uint FUN_80017a98();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern undefined8 ObjMsg_AllocQueue();
extern int FUN_800632f4();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ModgfxInterface** gModgfxInterface;
extern MapEventInterface** gMapEventInterface;
extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

/*
 * --INFO--
 *
 * Function: LaserBeam_update
 * EN v1.0 Address: 0x801F0B50
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801F0DA4
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void LaserBeam_update(int obj2);


/*
 * --INFO--
 *
 * Function: FUN_801f1634
 * EN v1.0 Address: 0x801F1634
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801F22BC
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


#pragma dont_inline on
void fn_801F20D4(int obj);
#pragma dont_inline reset


#pragma dont_inline on
void fn_801F27E4(int obj);
#pragma dont_inline reset


/*
 * --INFO--
 *
 * Function: FUN_801f2b94
 * EN v1.0 Address: 0x801F2B94
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801F37A8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/* Trivial 4b 0-arg blr leaves. */
void pressureswitch_free(void);

void pressureswitch_hitDetect(void);

void pressureswitch_release(void);

void pressureswitch_initialise(void);

extern f32 lbl_803E5D78;

typedef struct PressureSwitchFlags
{
    u8 unusedHighBit : 1;
    u8 mapBitLatched : 1;
    u8 otherFlags : 6;
} PressureSwitchFlags;

void pressureswitch_init(int* obj, u8* init);

void dll_1FF_free_nop(void);

void dll_1FF_hitDetect_nop(void);

void dll_1FF_release_nop(void);

void dll_1FF_initialise_nop(void);

void wmlasertarget_free(void);

void wmlasertarget_hitDetect(void);

void wmlasertarget_release(void);

void wmlasertarget_initialise(void);

extern void Obj_SetActiveModelIndex(int* obj, int idx);

void wmlasertarget_update(int* obj);

void dll_200_free_nop(void);

void dll_200_hitDetect_nop(void);

void dll_200_release_nop(void);

void dll_200_initialise_nop(void);

void WM_colrise_free(void);

void WM_colrise_hitDetect(void);

void WM_colrise_release(void);

void WM_colrise_initialise(void);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 timeDelta;
extern f32 lbl_803E5DCC;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;
extern f32 lbl_803E5DE0;

void WM_colrise_update(int* obj);

void wmtorch_hitDetect(void);

void wmtorch_release(void);

void wmtorch_initialise(void);

extern f32 lbl_803E5DEC;
extern f32 lbl_803E5DF0;
extern f32 lbl_803E5DF4;
extern f32 lbl_803E5DF8;

void wmtorch_init(u8* obj, u8* params);

void wmtorch_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

extern void* lbl_803DDC80;

void LaserBeam_initialise(void);

void lightsource_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int pressureswitch_getExtraSize(void);
int pressureswitch_getObjectTypeId(void);
int dll_1FF_getExtraSize_ret_8(void);
int wmlasertarget_getExtraSize(void);
int wmlasertarget_getObjectTypeId(void);
int dll_200_getExtraSize_ret_40(void);
int dll_200_getObjectTypeId(void);
int WM_colrise_getExtraSize(void);
int WM_colrise_getObjectTypeId(void);
int wmtorch_getExtraSize(void);
int wmtorch_getObjectTypeId(void);
int lightsource_getExtraSize(void) { return 0x1c; }
int lightsource_getObjectTypeId(void) { return 0x1; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5D58;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5D90;
extern f32 lbl_803E5DC8;
extern f32 lbl_803E5E08;
extern void queueGlowRender(void* light);

void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void lightsource_render(void* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 alpha);
    void* light = (*(LightSourceState**)&((GameObject*)obj)->extra)->light;
    if (light != NULL && ((LightsourceState*)light)->unk2F8 != 0 && ((LightsourceState*)light)->unk4C != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5E08);
    }
}

/* if (o->_X == K) return A; else return B; */
int dll_1FF_getObjectTypeId(int* obj);

/* init pattern: short=-1; byte=0; return 0; */
int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int WM_colrise_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/* fn_X(lbl); lbl = 0; */
void LaserBeam_release(void);

/* dll_1FF_init: stash (s8 b[0x18] << 8) into a[0] and -0x8000 into a[1]. */
void dll_1FF_init(s16* a, s8* b);

void WM_colrise_init(s16* a, s8* b);

extern int GameBit_Get(int id);

void wmlasertarget_init(char* obj, s8* p);

extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E5DE8;

void wmtorch_update(int obj);

extern void Obj_FreeObject(void* o);

void wmtorch_free(int obj, int mode);

extern void ModelLightStruct_free(void* light);

void lightsource_free(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (((LightSourceState*)state)->light != 0)
    {
        ModelLightStruct_free(((LightSourceState*)state)->light);
    }
}

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */
extern f32 lbl_803E5D80;

void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */
extern f32 lbl_803E5DC0;

void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */
extern f32 lbl_803E5D98;

void dll_200_init(int* obj, int* arg);

extern void playerAddRemoveMagic(int player, int amount);
extern void fn_80296474(int player, int a, int b);
extern void GameBit_Set(int slot, int val);

int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

#pragma opt_strength_reduction off
int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

#pragma opt_strength_reduction off
int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

extern int textureLoadAsset(int id);
extern f32 lbl_803E5D10;

void LaserBeam_free(s16* obj, char* arg);

extern ObjHitReactEntry lbl_80328898[];
void fn_801F2290(int obj);

void dll_200_update(int obj);

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

void lightsource_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern int ObjHits_GetPriorityHit(int obj, int a, int b, int c);
    extern uint GameBit_Get(int id);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_AddLoopedObjectSound(int obj, int sfx);
    extern void Sfx_RemoveLoopedObjectSound(int obj, int sfx);
    extern void fn_80098B18(int obj, f32 scale, u8 a, u8 b, int c, f32* vec);
    extern EffectInterface** gPartfxInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E5E08;
    extern f32 lbl_803E5E0C;
    extern f32 lbl_803E5E10;
    extern f32 lbl_803E5E14;
    extern f32 lbl_803E5E18;
    extern f32 lbl_803E5E1C;
    LightSourceState* b;
    char* t;
    s16 sum;
    u8 sfxFlag;
    f32 vec[3];
    struct
    {
        u8 pad[8];
        f32 scale;
        u8 pad2[0xc];
    } fx;

    b = ((GameObject*)obj)->extra;
    switch (b->mode)
    {
    case 0:
        break;
    case 1:
        b->litPrev = b->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            b->lit = (u8)(1 - b->lit);
        }
        if (b->lit != b->litPrev)
        {
            if (b->lit != 0)
            {
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) == 0)
                {
                    GameBit_Set(b->gameBit, 1);
                }
                Sfx_PlayFromObject(obj, 0x80);
            }
            else
            {
                (*gExpgfxInterface)->freeSource(obj);
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) != 0)
                {
                    GameBit_Set(b->gameBit, 0);
                }
            }
        }
        break;
    }
    if (b->lit != 0 && (((GameObject*)obj)->objectFlags & 0x800))
    {
        b->fxTimer = b->fxTimer - timeDelta;
        if (b->fxTimer <= lbl_803E5E0C)
        {
            sfxFlag = b->fxArg;
            b->fxTimer = b->fxTimer + lbl_803E5E10;
        }
        else
        {
            sfxFlag = 0;
        }
        if (b->fxType != 0 || b->fxArg != 0)
        {
            vec[0] = lbl_803E5E0C;
            if (((GameObject*)obj)->anim.seqId == 0x717)
            {
                vec[1] = vec[0];
            }
            else
            {
                vec[1] = lbl_803E5E14;
            }
            vec[2] = lbl_803E5E0C;
            fn_80098B18(obj, lbl_803E5E18 * ((GameObject*)obj)->anim.rootMotionScale, b->fxType, sfxFlag, 0, vec);
        }
        if (b->sparks != 0)
        {
            b->unk0C = b->unk0C - timeDelta;
            if (b->unk0C <= lbl_803E5E0C)
            {
                fx.scale = lbl_803E5E08;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7cb, &fx, 2, -1, NULL);
                b->unk0C = b->unk0C + lbl_803E5E1C;
            }
        }
    }
    t = (char*)b->light;
    if (t != NULL && *(u8*)(t + 0x2f8) != 0 && *(u8*)(t + 0x4c) != 0)
    {
        sum = (s16)(*(u8*)(t + 0x2f9) + *(s8*)(t + 0x2fa));
        if (sum < 0)
        {
            sum = 0;
            *(u8*)(t + 0x2fa) = 0;
        }
        else if (sum > 255)
        {
            sum = 255;
            *(u8*)(t + 0x2fa) = 0;
        }
        *(u8*)((char*)b->light + 0x2f9) = (u8)sum;
    }
    if (((GameObject*)obj)->anim.seqId != 0x705 && ((GameObject*)obj)->anim.seqId != 0x712)
    {
        if (b->lit != 0)
        {
            if (!((LightSourceFlagByte*)&b->loopFlags)->looped)
            {
                Sfx_AddLoopedObjectSound(obj, 0x72);
                ((LightSourceFlagByte*)&b->loopFlags)->looped = 1;
            }
        }
        else
        {
            if (((LightSourceFlagByte*)&b->loopFlags)->looped)
            {
                Sfx_RemoveLoopedObjectSound(obj, 0x72);
                ((LightSourceFlagByte*)&b->loopFlags)->looped = 0;
            }
        }
    }
}

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

void dll_1FF_update(int obj);

typedef struct PswFlags
{
    u8 active : 1;
    u8 latched : 1;
} PswFlags;

#pragma opt_common_subs off
void pressureswitch_update(int obj);
#pragma opt_common_subs reset

typedef struct IntVec3
{
    int a;
    int b;
    int c;
} IntVec3;

typedef struct ArwAttachTarget
{
    f32 x;
    f32 y;
    f32 moveId;
    f32 altMoveId;
    f32 speed;
} ArwAttachTarget;

void fn_801F2290(int obj);
