#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objseq.h"

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

void pressureswitch_free(void)
{
}

void pressureswitch_hitDetect(void)
{
}

void pressureswitch_release(void)
{
}

void pressureswitch_initialise(void)
{
}

extern f32 lbl_803E5D78;

typedef struct PressureSwitchFlags
{
    u8 unusedHighBit : 1;
    u8 mapBitLatched : 1;
    u8 otherFlags : 6;
} PressureSwitchFlags;

void pressureswitch_init(int* obj, u8* init)
{
    extern uint GameBit_Get(int id);
    PressureSwitchState* sub;
    uint mapId;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)PressureSwitch_SeqFn;
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    sub->retriggerTimer = (s16)(*(s16*)(init + 0x1e) * 0x3c);
    sub->chimeLatch = 0;
    mapId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    if (mapId == 0x1f1a)
    {
        sub->mapGameBit = 0xf45;
    }
    else if (mapId == 0x47293)
    {
        sub->mapGameBit = 0xf46;
    }
    else
    {
        sub->mapGameBit = -1;
    }
    if (sub->mapGameBit != -1)
    {
        if (GameBit_Get(sub->mapGameBit) != 0)
        {
            ((PressureSwitchFlags*)&sub->flags)->mapBitLatched = 1;
        }
    }
    if (GameBit_Get(*(s16*)(init + 0x1c)) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = *(f32*)(init + 0xc) - lbl_803E5D78;
        sub->holdTimer = 0x1e;
    }
}

void dll_1FF_free_nop(void);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 timeDelta;

int pressureswitch_getExtraSize(void) { return 0x8; }
int pressureswitch_getObjectTypeId(void) { return 0x0; }
int dll_1FF_getExtraSize_ret_8(void);

extern f32 lbl_803E5D58;
extern void objRenderFn_8003b8f4(f32);

void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5D58);
}

void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

void LaserBeam_release(void);

extern int GameBit_Get(int id);

extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);

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

extern void GameBit_Set(int slot, int val);

#pragma opt_strength_reduction off

#pragma opt_strength_reduction off

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

typedef struct PswFlags
{
    u8 active : 1;
    u8 latched : 1;
} PswFlags;

#pragma opt_common_subs off
void pressureswitch_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern void*getTrickyObject(void);
    extern f32 Vec_distance(void* a, void* b);
    extern uint GameBit_Get(int id);
    extern void GameBit_Set(int slot, int val);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_StopObjectChannel(int obj, int ch);
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D5C;
    extern f32 lbl_803E5D60;
    extern f32 lbl_803E5D64;
    extern f32 lbl_803E5D68;
    extern f32 lbl_803E5D6C;
    extern f32 lbl_803E5D74;
    extern f32 lbl_803E5D70;
    char* t;
    PressureSwitchState* b;
    s8 far;
    int i;
    void* player;
    void* tricky;
    int ac;
    int v;
    s8 played;
    char* slots;
    f32 cur;
    f32 lim;
    f32 thr;
    f32 f;

    player = Obj_GetPlayerObject();
    t = *(char**)&((GameObject*)obj)->anim.placementData;
    b = ((GameObject*)obj)->extra;
    far = 0;
    if (Vec_distance((char*)obj + 0x18, (char*)player + 0x18) > lbl_803E5D5C)
    {
        far = 1;
    }
    b->holdTimer -= 1;
    if (b->holdTimer < 0)
    {
        b->holdTimer = 0;
        b->chimeLatch = 0;
    }
    ((PswFlags*)&b->flags)->active = 0;
    if (*(char**)(obj + 0x58) != NULL && *(s8*)(*(char**)(obj + 0x58) + 0x10f) > 0)
    {
        b->retriggerTimer = (s16)(((PressureswitchPlacement*)t)->unk1E * 60);
        i = 0;
        thr = lbl_803E5D60;
        for (; i < *(s8*)((slots = *(char**)(obj + 0x58)) + 0x10f); i++)
        {
            char* ent = *(char**)(slots + i * 4 + 0x100);
            if (*(s16*)(ent + 0x46) == 0x6d)
            {
                ((PswFlags*)&b->flags)->active = 1;
            }
            if (*(f32*)(ent + 0x10) - ((GameObject*)obj)->anim.localPosY > thr)
            {
                b->holdTimer = 5;
            }
            if (b->chimeLatch == 0 && ent != NULL && *(s16*)(ent + 0x46) == 0x146)
            {
                if (far == 0)
                {
                    Sfx_PlayFromObject(obj, 0x7e);
                }
                b->chimeLatch = 1;
            }
        }
    }
    else
    {
        ac = ((GameObject*)obj)->anim.mapEventSlot;
        if (ac == 11 && (*gMapEventInterface)->getMode(ac) == 3 &&
            (tricky = getTrickyObject()) != NULL &&
            Vec_distance((char*)obj + 0x18, (char*)tricky + 0x18) < lbl_803E5D64)
        {
            b->holdTimer = 5;
        }
    }
    ac = ((GameObject*)obj)->anim.mapEventSlot;
    if (ac == 11 && (*gMapEventInterface)->getMode(ac) == 1 && far == 0)
    {
        if (b->holdTimer != 0)
        {
            f = ((PressureswitchPlacement*)t)->unkC - ((GameObject*)obj)->anim.localPosY;
            if (f > lbl_803E5D68 && f < lbl_803E5D6C && GameBit_Get(b->mapGameBit) == 0)
            {
                GameBit_Set(0x905, 1);
            }
            else if (GameBit_Get(0x905) != 0)
            {
                GameBit_Set(0x905, 0);
            }
        }
        else if (GameBit_Get(0x905) != 0)
        {
            GameBit_Set(0x905, 0);
        }
    }
    played = 0;
    if (b->holdTimer != 0)
    {
        lim = ((PressureswitchPlacement*)t)->unkC - lbl_803E5D6C;
        cur = ((GameObject*)obj)->anim.localPosY;
        if (cur < lim)
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E5D70 * timeDelta + cur;
            if (((GameObject*)obj)->anim.localPosY > lim)
            {
                ((GameObject*)obj)->anim.localPosY = lim;
            }
            GameBit_Set(((PressureswitchPlacement*)t)->unk1C, 1);
            if (((PswFlags*)&b->flags)->active)
            {
                GameBit_Set(b->mapGameBit, 1);
            }
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY = -(lbl_803E5D74 * timeDelta - cur);
            if (((GameObject*)obj)->anim.localPosY < lim)
            {
                ((GameObject*)obj)->anim.localPosY = lim;
                GameBit_Set(((PressureswitchPlacement*)t)->unk1C, 1);
                v = b->mapGameBit;
                if (v != -1)
                {
                    GameBit_Set(v, 1);
                    if (((PswFlags*)&b->flags)->active)
                    {
                        ((PswFlags*)&b->flags)->latched = 1;
                    }
                }
            }
            else
            {
                played = 1;
            }
        }
    }
    else
    {
        if (b->retriggerTimer == 0)
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E5D74 * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY > ((PressureswitchPlacement*)t)->unkC)
            {
                ((GameObject*)obj)->anim.localPosY = ((PressureswitchPlacement*)t)->unkC;
            }
            else
            {
                played = 1;
            }
            GameBit_Set(((PressureswitchPlacement*)t)->unk1C, 0);
            v = b->mapGameBit;
            if (v != -1)
            {
                if (!((PswFlags*)&b->flags)->latched)
                {
                    GameBit_Set(v, 0);
                }
            }
        }
    }
    if (played != 0)
    {
        Sfx_PlayFromObject(obj, 0x7f);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 8);
    }
    if (b->retriggerTimer != 0)
    {
        b->retriggerTimer -= framesThisStep;
        if (b->retriggerTimer < 0)
        {
            b->retriggerTimer = 0;
        }
    }
}
#pragma opt_common_subs reset
