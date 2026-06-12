#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/transporter.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct IceblastPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 unk19;
    s16 unk1A;
    s8 unk1C;
    s8 unk1D;
    s8 unk1E;
    u8 unk1F;
} IceblastPlacement;


typedef struct PushablePlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s8 unk1C;
    s8 unk1D;
    s8 unk1E;
    u8 unk1F;
    u8 pad20[0x23 - 0x20];
    s8 unk23;
    u8 pad24[0x28 - 0x24];
} PushablePlacement;


typedef struct InvhitState
{
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 pad9[0xC - 0x9];
} InvhitState;


typedef struct FlameblastState
{
    u8 pad0[0x10 - 0x0];
    u8 unk10;
    u8 unk11;
    u8 pad12[0x14 - 0x12];
} FlameblastState;


typedef struct InvhitObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void* unk1C;
} InvhitObjectDef;


typedef struct WarpPointObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void* unk1C;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WarpPointObjectDef;


typedef struct PushableObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    s16 unk1A;
    void* unk1C;
    s16 unk20;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} PushableObjectDef;


typedef struct WarpPointPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void* unk1C;
    s16 unk20;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x48 - 0x24];
    f32 unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x114 - 0x54];
    f32 unk114;
    f32 unk118;
    u8 pad11C[0x128 - 0x11C];
    f32 unk128;
    f32 unk12C;
} WarpPointPlacement;


typedef struct WarpPointState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    u8 unkC;
    u8 unkD;
    u8 padE[0x10 - 0xE];
    u8 unk10;
    u8 unk11;
    u8 pad12[0x18 - 0x12];
} WarpPointState;


static inline int* Transporter_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern undefined8 FUN_80017ac8();
extern undefined4 ObjHits_SetTargetMask();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_AddContactObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern void Obj_FreeObject(int* obj);
extern undefined4 ObjMsg_AllocQueue();
extern int ObjList_ContainsObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80053c98();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern int fn_80174A80();
extern undefined4 fn_80174BFC();
extern undefined4 fn_8017510C();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
/*
 * --INFO--
 *
 * Function: pushable_setScale
 * EN v1.0 Address: 0x801755CC
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801758D4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* pushable_setScale: real v1.0 body defined at end of file (old v1.1 misimport removed). */


/*
 * --INFO--
 *
 * Function: pushable_render
 * EN v1.0 Address: 0x80175FB8
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x80176464
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* pushable_render: recovered v1.0 body defined at end of file. */


/*
 * --INFO--
 *
 * Function: FUN_80176920
 * EN v1.0 Address: 0x80176920
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80177470
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80176920(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , int param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;

    if (((*(char*)(*(int*)(param_9 + 0x4c) + 0x1d) != '\x02') &&
            (*(char*)(param_11 + 0x80) == '\x01')) &&
        (iVar1 = (int)*(char*)(*(int*)(param_9 + 0x4c) + 0x1a), -1 < iVar1))
    {
        FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar1, '\x01',
                     param_11, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_11 + 0x80) = 0;
    }
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_801778d0
 * EN v1.0 Address: 0x801778D0
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x801784F8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801778d0(int param_1)
{
    *(u8*)(*(int*)&((GameObject*)param_1)->extra + 0x10) = 1;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801778e0
 * EN v1.0 Address: 0x801778E0
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x80178508
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801778e0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             int param_10)
{
    float fVar1;
    short* psVar2;
    undefined4 uVar3;
    int iVar4;
    float* pfVar5;
    ushort local_28;
    short local_26;
    short local_24;
    float local_20;
    float local_1c;
    float local_18;
    float local_14;

    psVar2 = (short*)FUN_80017a90();
    local_1c = lbl_803E42B0;
    if ((*(char*)(param_10 + 0x10) == '\0') && (psVar2 != (short*)0x0))
    {
        *(float*)(param_9 + 0x24) = lbl_803E42B0;
        *(float*)(param_9 + 0x28) = local_1c;
        *(float*)(param_9 + 0x2c) = lbl_803E42B4;
        local_18 = local_1c;
        local_14 = local_1c;
        local_20 = lbl_803E42B8;
        local_24 = psVar2[2];
        local_26 = psVar2[1];
        iVar4 = FUN_801365ac((int)psVar2);
        local_28 = *psVar2 + (short)iVar4;
        FUN_80017748(&local_28, (float*)(param_9 + 0x24));
        if ((psVar2[0x58] & 0x800U) == 0)
        {
            pfVar5 = (float*)(psVar2 + 6);
        }
        else
        {
            pfVar5 = (float*)FUN_801365b8((int)psVar2);
        }
        fVar1 = lbl_803E42BC;
        *(float*)(param_10 + 4) = -(lbl_803E42BC * *(float*)(param_9 + 0x24) - *pfVar5);
        *(float*)(param_10 + 8) = -(fVar1 * *(float*)(param_9 + 0x28) - pfVar5[1]);
        *(float*)(param_10 + 0xc) = -(fVar1 * *(float*)(param_9 + 0x2c) - pfVar5[2]);
        if (*(char*)(param_10 + 0x11) == '\0')
        {
            ObjHits_ClearHitVolumes(param_9);
        }
        else
        {
            *(char*)(param_10 + 0x11) = *(char*)(param_10 + 0x11) + -1;
        }
        uVar3 = 1;
    }
    else
    {
        FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
        uVar3 = 0;
    }
    return uVar3;
}


/* Trivial 4b 0-arg blr leaves. */
void invhit_hitDetect(void)
{
}

void invhit_release(void)
{
}

void invhit_initialise(void)
{
}

void iceblast_free(void)
{
}

void iceblast_hitDetect(void)
{
}

void iceblast_release(void)
{
}

void iceblast_initialise(void)
{
}

extern unsigned long GameBit_Set(int eventId, int value);
extern int saveGame_saveObjectPos(int* obj);
extern int lbl_803DDAB8;
extern int lbl_803AC6E0[];

#pragma scheduling off
#pragma peephole off
void pushable_free(int* obj);

/* 8b "li r3, N; blr" returners. */
int WarpPoint_getExtraSize(void) { return 0x10; }
int WarpPoint_getObjectTypeId(void) { return 0x1; }
int invhit_getExtraSize(void) { return 0xc; }
int invhit_getObjectTypeId(void) { return 0x0; }
int iceblast_getExtraSize(void) { return 0x4; }
int iceblast_getObjectTypeId(void) { return 0x0; }
int flameblast_getExtraSize(void) { return 0x14; }

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern f32 lbl_803E3618;
extern f32 lbl_803E3620;
extern f32 lbl_803E3628;
extern f32 lbl_803E362C;
#pragma peephole on
void flameblast_render(int* obj)
{
    f32 vec[3];
    f32 f = lbl_803E362C * *(f32*)((GameObject*)obj)->extra + lbl_803E3628;
    vec[0] = lbl_803E3618;
    vec[1] = lbl_803E3620;
    vec[2] = lbl_803E3618;
    fn_80098B18((int)obj, f, 2, 0, 0, (int)vec);
}

/* 16b chained patterns. */
void objSetAnimSpeedTo1(int* obj)
{
    u8 v = 0x1;
    *((u8*)((int**)obj)[0xb8 / 4] + 0x10) = v;
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E35E8;
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 scale);
extern f32 lbl_803E3600;
void invhit_render(int* obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E35E8); }
void iceblast_render(int* obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3600); }

#pragma peephole off
void WarpPoint_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if (visible == 0) return;
    if (*(s8*)((char*)p + 0x1d) == 1) return;
}

void invhit_free(int obj)
{
    char* inner = ((GameObject*)obj)->extra;
    switch (((InvhitState*)inner)->unk8)
    {
    case 4:
        (*gExpgfxInterface)->freeSource2((u32)obj);
        break;
    }
}

#pragma peephole on
void iceblast_init(int obj, s16* p)
{
    *(f32*)((GameObject*)obj)->extra = (f32) * (s16*)((char*)p + 0x1a);
    ObjHits_SetTargetMask(obj, 1);
}

extern void warpToMap(int mapId, int flag);

#pragma peephole off
int WarpPoint_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if (*(s8*)((char*)p + 0x1d) != 2)
    {
        if (animUpdate->triggerCommand == 1)
        {
            int v = (s8) * (u8*)((char*)p + 0x1a);
            if (v > -1)
            {
                warpToMap(v, 1);
                animUpdate->triggerCommand = 0;
            }
        }
    }
    return 0;
}

extern f32 timeDelta;
extern f32 lbl_803E3630;
extern f32 lbl_803E3634;
extern int fn_8017805C(int* obj, f32* state);

void flameblast_update(int* obj)
{
    f32* state = ((GameObject*)obj)->extra;
    state[0] = state[0] + timeDelta;
    if (state[0] > lbl_803E3630)
    {
        state[0] = state[0] - lbl_803E3630;
        if (fn_8017805C(obj, state) == 0)
        {
            return;
        }
    }
    else
    {
        if (state[0] > lbl_803E3634)
        {
            if (((FlameblastState*)state)->unk11 == 0)
            {
                ObjHits_SetHitVolumeSlot(obj, 0x1a, 1, 0);
            }
        }
    }
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * state[0] + state[1];
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * state[0] + state[2];
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * state[0] + state[3];
}

extern f32 lbl_803E3604;
extern f32 lbl_803E3608;
extern f32 lbl_803E360C;
extern void* Obj_GetPlayerObject(void);
extern void vecRotateZXY(void* in, void* out);
extern f32 lbl_803E3638;

void flameblast_init(int* obj, u8* def)
{
    f32* state = ((GameObject*)obj)->extra;
    fn_8017805C(obj, state);
    state[0] = lbl_803E3638 * (f32)(s32) * (s16*)((char*)def + 0x1a);
    ((FlameblastState*)state)->unk11 = 2;
}

void WarpPoint_init(int* obj, u8* def)
{
    s16* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)WarpPoint_SeqFn;
    *(s16*)obj = (s16)((u32)def[0x18] << 8);
    state[0] = 0x1e;
    ((WarpPointState*)state)->unk8 = (f32)((s32) * (s8*)((char*)def + 0x1e) << 2);
    state[1] = ((WarpPointObjectDef*)def)->unk20;
    state[2] = (s16)(s32) * (s8*)((char*)def + 0x1b);
    if (*(s8*)((char*)def + 0x1c) != 0)
    {
        ((WarpPointState*)state)->unkC = 0;
    }
    else
    {
        ((WarpPointState*)state)->unkC = 1;
    }
    if (*(s8*)((char*)def + 0x1d) == 2)
    {
        state[0] = 0;
    }
    if (((ObjPlacement*)def)->mapId == 0x4B675 || ((ObjPlacement*)def)->mapId == 0x46882)
    {
        *(u8*)((char*)def + 0x1f) = 1;
    }
    else
    {
        *(u8*)((char*)def + 0x1f) = 0;
    }
}

void iceblast_update(int* obj)
{
    int* path;
    int* def;
    f32* state;
    int* player;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;
    player = (int*)Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    def = *(int**)&((GameObject*)obj)->anim.placementData;
    if (player != NULL && (path = ((GameObject*)player)->childObjs[0]) != NULL)
    {
        ((GameObject*)obj)->anim.rotZ = *(s16*)((char*)path + 4);
        ((GameObject*)obj)->anim.rotY = *(s16*)((char*)path + 2);
        *(s16*)obj = *(s16*)path;
    }
    else
    {
        return;
    }
    ObjHits_SetHitVolumeSlot(obj, 0x10, ((IceblastPlacement*)def)->unk19 != 0 ? 3 : 1, 0);
    state[0] = state[0] - timeDelta;
    if (state[0] <= lbl_803E3604)
    {
        f32 zero;
        state[0] = state[0] + lbl_803E3608;
        zero = lbl_803E3604;
        ((f32*)obj)[9] = zero;
        ((f32*)obj)[11] = zero;
        ((f32*)obj)[10] = lbl_803E360C;
        vec.pos[1] = zero;
        vec.pos[2] = zero;
        vec.pos[3] = zero;
        vec.pos[0] = lbl_803E3600;
        vec.dir[2] = *(s16*)((char*)path + 4);
        vec.dir[1] = *(s16*)((char*)path + 2);
        vec.dir[0] = *(s16*)path;
        vecRotateZXY(&vec, (f32*)((char*)obj + 0x24));
        ObjPath_GetPointWorldPosition((int)path, 0, &((GameObject*)obj)->anim.localPosX,
                                      &((GameObject*)obj)->anim.localPosY, &((GameObject*)obj)->anim.localPosZ, 0);
        ObjHits_EnableObject((u32)obj);
    }
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.
        localPosX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
        localPosY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.
        localPosZ;
}

extern s16* getTrickyObject(void);
extern int fn_80138F90(void);
extern f32* trickyGetQueuedPathParticlePos(s16 * tricky);
extern f32 lbl_803E361C;
extern f32 lbl_803E3624;

#pragma opt_common_subs off
int fn_8017805C(int* obj, f32* state)
{
    s16* tricky;
    f32* pf;
    f32 k;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;

    tricky = getTrickyObject();
    if (*(u8*)((char*)state + 0x10) != 0 || tricky == NULL)
    {
        Obj_FreeObject(obj);
        return 0;
    }
    {
        f32 f = lbl_803E3618;
        ((GameObject*)obj)->anim.velocityX = f;
        ((GameObject*)obj)->anim.velocityY = f;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E361C;
        vec.pos[1] = f;
        vec.pos[2] = f;
        vec.pos[3] = f;
        vec.pos[0] = lbl_803E3620;
    }
    vec.dir[2] = tricky[2];
    vec.dir[1] = tricky[1];
    vec.dir[0] = tricky[0] + fn_80138F90();
    vecRotateZXY(&vec, &((GameObject*)obj)->anim.velocityX);
    if ((((GameObject*)tricky)->objectFlags & 0x800) != 0)
    {
        pf = trickyGetQueuedPathParticlePos(tricky);
    }
    else
    {
        pf = &((GameObject*)tricky)->anim.localPosX;
    }
    k = lbl_803E3624;
    state[1] = -(k * ((GameObject*)obj)->anim.velocityX - pf[0]);
    state[2] = -(k * ((GameObject*)obj)->anim.velocityY - pf[1]);
    state[3] = -(k * ((GameObject*)obj)->anim.velocityZ - pf[2]);
    if (*(u8*)((char*)state + 0x11) != 0)
    {
        *(u8*)((char*)state + 0x11) -= 1;
    }
    else
    {
        ObjHits_ClearHitVolumes(obj);
    }
    return 1;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
typedef struct InvHitState
{
    f32 anchorX;
    f32 anchorZ;
    u8 mode;
} InvHitState;

void invhit_init(int* obj, u8* def)
{
    InvHitState* state = ((GameObject*)obj)->extra;
    char* sub;

    state->mode = def[0x1a];
    sub = *(char**)&((GameObject*)obj)->anim.hitReactState;
    ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags & ~1;
    switch (state->mode)
    {
    case 0:
        ((GameObject*)obj)->unkF8 = def[0x18];
        break;
    case 6:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = 0x23;
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 0x45;
        sub[0x6e] = 0xb;
        sub[0x6f] = 1;
        sub[0xae] = 0;
        sub[0xaf] = 0;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 3:
        ((GameObject*)obj)->unkF8 = def[0x18];
        ((GameObject*)obj)->unkF4 = 0;
        break;
    case 5:
        ((GameObject*)obj)->unkF8 = def[0x18];
        ((GameObject*)obj)->unkF4 = 0;
        break;
    case 7:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = def[0x18];
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 0x45;
        sub[0xae] = 0;
        sub[0x6e] = 0xa;
        sub[0x6f] = 0;
        sub[0xaf] = 0;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 1:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = def[0x18];
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 0x45;
        sub[0xae] = 0;
        sub[0x6e] = 0xb;
        sub[0x6f] = 1;
        sub[0xaf] = 0;
        sub[0x6e] = 0x11;
        sub[0x6f] = 1;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 2:
        ((ObjHitsPriorityState*)sub)->shapeFlags = def[0x19];
        ((ObjHitsPriorityState*)sub)->primaryRadius = def[0x18];
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 1;
        sub[0xae] = 0;
        sub[0xaf] = 0;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 4:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = 0xa;
        ((ObjHitsPriorityState*)sub)->flags = 3;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        ((GameObject*)obj)->unkF8 = 0x78;
        {
            char* anchorObj = *(char**)&((InvhitObjectDef*)def)->unk1C;
            if (anchorObj != NULL)
            {
                state->anchorX = ((GameObject*)anchorObj)->anim.localPosX;
                state->anchorZ = *(f32*)(*(char**)&((InvhitObjectDef*)def)->unk1C + 0x14);
            }
        }
        break;
    }
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x6000;
}
#pragma opt_common_subs reset

extern int playerIsDisguised(void* player);
extern u32 GameBit_Get(int eventId);
extern int fn_80295A04(void* player, int a);
extern void pushable_savePos(int* obj);
extern int fn_80174668(int* obj, PushableState* state);
extern void fn_80174438(int* obj, PushableState* state);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void Obj_RemoveFromUpdateList(int* obj);
extern f32 lbl_803E3528;
extern f64 lbl_803E3530;
extern f64 lbl_803E3538;

void pushable_update(int* obj);

extern f32 sqrtf(f32 x);
extern u32 fn_80296118(void);
extern f32 lbl_803AC780[];
extern u8 framesThisStep;
extern EffectInterface** gPartfxInterface;
extern s8 hitDetectFn_80065e50(int* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern f32 lbl_803E35EC;
extern f32 lbl_803E35F0;
extern f32 lbl_803E35F4;

void invhit_update(int* obj)
{
    InvHitState* state;
    int i;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
    switch (state->mode)
    {
    case 0:
        {
            char* victim = (char*)Obj_GetPlayerObject();
            while (victim != NULL)
            {
                f32 dx = ((GameObject*)obj)->anim.localPosX - ((PushableState*)victim)->cullDistance;
                f32 dy = ((GameObject*)obj)->anim.localPosY - ((PushableState*)victim)->scale;
                f32 dz = ((GameObject*)obj)->anim.localPosZ - ((PushableState*)victim)->timer_0x14;
                f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
                if (dist < (f32)((GameObject*)obj)->unkF8)
                {
                    u8* victimHits = *(u8**)&((GameObject*)victim)->anim.hitReactState;
                    victimHits[0x71] += 1;
                    ((ObjHitsPriorityState*)victimHits)->flags = ((ObjHitsPriorityState*)victimHits)->flags & ~1;
                    (*(u8**)&((GameObject*)obj)->anim.hitReactState)[0x71] += 1;
                }
                if (((GameObject*)victim)->anim.classId == 1)
                {
                    victim = (char*)getTrickyObject();
                }
                else
                {
                    victim = NULL;
                }
            }
            break;
        }
    case 3:
        if (Obj_GetPlayerObject() != NULL)
        {
            lbl_803AC780[0] = ((GameObject*)obj)->anim.worldPosX;
            lbl_803AC780[1] = ((GameObject*)obj)->anim.worldPosY;
            lbl_803AC780[2] = ((GameObject*)obj)->anim.worldPosZ;
        }
        break;
    case 5:
        {
            void* pl = Obj_GetPlayerObject();
            u32 v = fn_80296118();
            if (pl != NULL && v != 0)
            {
                lbl_803AC780[0] = ((GameObject*)obj)->anim.worldPosX;
                lbl_803AC780[1] = ((GameObject*)obj)->anim.worldPosY;
                lbl_803AC780[2] = ((GameObject*)obj)->anim.worldPosZ;
            }
            break;
        }
    case 1:
        ObjList_ContainsObject(((GameObject*)obj)->unkF4);
        break;
    case 7:
        {
            char* hitState = *(char**)&((GameObject*)obj)->anim.hitReactState;
            char* ownerHitState = *(char**)(((GameObject*)obj)->unkF4 + 0x54);
            char* ownerHitSlot = ownerHitState;

            i = 0;
            for (; i < *(s8*)(ownerHitState + 0x71); i++)
            {
                if (*(int**)(ownerHitSlot + 0x7c) == obj)
                {
                    *(s16*)(hitState + 0x60) = *(s16*)(hitState + 0x60) & ~1;
                    Obj_FreeObject(obj);
                }
                ownerHitSlot += 4;
            }
            break;
        }
    case 4:
        {
            char* hitState = *(char**)&((GameObject*)obj)->anim.hitReactState;
            char* targetObj;
            f32** hits[2];
            f32 reach;
            f32 dx2;
            f32 dz2;
            s8 cnt;
            f32 thr;

            ((GameObject*)obj)->unkF8 -= framesThisStep;
            if (*(void**)&((ObjHitsPriorityState*)hitState)->lastHitObject != NULL)
            {
                ((ObjHitsPriorityState*)hitState)->flags = 0;
            }
            targetObj = *(char**)&((GameObject*)obj)->unkF4;
            if (targetObj != NULL)
            {
                f32 dx;
                f32 dz;
                f32 k;
                f32 qt;
                f32 d;

                if (ObjList_ContainsObject(targetObj) == 0) break;
                dx = ((GameObject*)targetObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
                dz = ((GameObject*)targetObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
                k = lbl_803E35EC;
                qt = dx / k;
                ((GameObject*)obj)->anim.localPosX = qt * timeDelta + ((GameObject*)obj)->anim.localPosX;
                qt = dz / k;
                ((GameObject*)obj)->anim.localPosZ = qt * timeDelta + ((GameObject*)obj)->anim.localPosZ;
                dx = ((GameObject*)targetObj)->anim.localPosX - state->anchorX;
                dz = ((GameObject*)targetObj)->anim.localPosZ - state->anchorZ;
                reach = lbl_803E35F0 + sqrtf(dx * dx + dz * dz);
                dx2 = ((GameObject*)obj)->anim.localPosX - state->anchorX;
                dz2 = ((GameObject*)obj)->anim.localPosZ - state->anchorZ;
                d = sqrtf(dx2 * dx2 + dz2 * dz2);
                if (d > reach)
                {
                    f32 r = reach / d;
                    dx2 = dx2 * r;
                    dz2 = dz2 * r;
                    ((GameObject*)obj)->anim.localPosX = state->anchorX + dx2;
                    ((GameObject*)obj)->anim.localPosZ = state->anchorZ + dz2;
                }
                (*gPartfxInterface)->spawnObject(obj, 0x25, NULL, 0, -1,
                                                 NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x56, NULL, 0, -1,
                                                 NULL);
            }
            cnt = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                       ((GameObject*)obj)->anim.localPosZ, hits, 0, 0);
            thr = lbl_803E35F4;
            for (i = 0; i < cnt; i++)
            {
                f32 h = *hits[0][i];
                f32 oy = ((GameObject*)obj)->anim.localPosY;
                if (h < thr + oy && h > oy - thr)
                {
                    ((GameObject*)obj)->anim.localPosY = h;
                    i = cnt;
                }
            }
            break;
        }
    }
}

extern int getCurMapLayer(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern f32 lbl_803E35D8;
extern f32 lbl_803E35DC;

void WarpPoint_update(int* obj)
{
    char* def;
    s16* state;
    char* player;
    f32 dist;

    def = *(char**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    *state -= framesThisStep;
    if (*state < 0)
    {
        *state = 0;
    }
    if (*(u8*)(def + 0x1f) != 0 && ((WarpPointState*)state)->unkD == 0 && lbl_803DCEB8 > -1 &&
        lbl_803DCEB8 == *(s8*)(def + 0x19))
    {
        (*gMapEventInterface)->triggerEvent((int)(player + 0xc), *(s16*)player,
                                            0, getCurMapLayer());
        ((WarpPointState*)state)->unkD = 1;
    }
    switch (*(s8*)(def + 0x1d))
    {
    case 0:
        if (lbl_803DCEB8 > -1 || GameBit_Get(0xd53) != 0)
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (((WarpPointState*)state)->unkC == 0 && *(s8*)(def + 0x1c) != 0 &&
                dist < ((WarpPointState*)state)->unk8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                if (((GameObject*)obj)->anim.seqId == 0x27e)
                {
                    GameBit_Set(0xd53, 1);
                    (*gMapEventInterface)->triggerEvent(
                        (int)(player + 0xc), *(s16*)player, 0, getCurMapLayer());
                }
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                GameBit_Set(0xd53, 0);
                lbl_803DCDE0 = 2;
                ((WarpPointState*)state)->unkC = 1;
            }
        }
        if (*(s8*)(def + 0x1a) > -1)
        {
            f32 d2 = Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18));
            if (d2 < ((WarpPointState*)state)->unk8)
            {
                warpToMap(*(s8*)(def + 0x1a), 1);
            }
        }
        break;
    case 1:
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (lbl_803DCEB8 > -1 && *(s8*)(def + 0x1c) != 0 && dist < lbl_803E35D8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                lbl_803DCDE0 = 2;
            }
            if (*state == 0 && dist < (f32) * (s8*)(def + 0x1e) && *(s8*)(def + 0x1a) > -1 &&
                *(s8*)(def + 0x1a) > -1)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            }
            break;
        }
    case 2:
        if (lbl_803E35DC != (dist = ((WarpPointState*)state)->unk8))
        {
            f32 dx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((PushableState*)player)->probeLocal[0].y - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((PushableState*)player)->probeLocal[0].z - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (GameBit_Get(state[1]) != 0 && ((WarpPointState*)state)->unkC == 0 &&
            *(s8*)(def + 0x1c) != 0 && dist <= ((WarpPointState*)state)->unk8 &&
            *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            ((WarpPointState*)state)->unkC = 1;
        }
        else
        {
            if (((WarpPointState*)state)->unkC == 1 && GameBit_Get(state[1]) != 0 && *state == 0 &&
                dist <= ((WarpPointState*)state)->unk8 && *(s8*)(def + 0x1a) > -1)
            {
                GameBit_Set(state[1], 0);
                warpToMap(*(s8*)(def + 0x1a), 0);
            }
        }
        break;
    case 3:
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (GameBit_Get(state[1]) != 0 && ((WarpPointState*)state)->unkC == 0 &&
                *(s8*)(def + 0x1c) != 0 && dist < ((WarpPointState*)state)->unk8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                GameBit_Set(state[1], 0);
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                ((WarpPointState*)state)->unkC = 1;
            }
            break;
        }
    case 4:
        if (lbl_803E35DC != (dist = ((WarpPointState*)state)->unk8))
        {
            f32 dx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((PushableState*)player)->probeLocal[0].y - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((PushableState*)player)->probeLocal[0].z - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (lbl_803DCEB8 > -1 && ((WarpPointState*)state)->unkC == 0 && *(s8*)(def + 0x1c) != 0 &&
            dist < ((WarpPointState*)state)->unk8 &&
            *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            lbl_803DCDE0 = 2;
            ((WarpPointState*)state)->unkC = 1;
        }
        if (GameBit_Get(state[1]) != 0 && *state == 0 && dist <= ((WarpPointState*)state)->unk8 &&
            *(s8*)(def + 0x1a) > -1)
        {
            GameBit_Set(state[1], 0);
            warpToMap(*(s8*)(def + 0x1a), 1);
        }
        break;
    }
}

extern void objSetSlot(s16* obj, int slot);
extern int modelFileHeaderGetCullDistance(int hdr);
extern void Model_GetVertexPosition(int* model, int idx, f32* out);
extern void debugPrintf(char* fmt, ...);
extern char sPushPullObjectHitpointOverflow[];
extern void Matrix_TransformPoint(f32* matrix, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ);
extern int arrayIndexOf(int* array, int count, int value);
extern void fn_8007FE04(int* array, int* count, int value);
extern f32 lbl_803E358C;
extern f32 lbl_803E35CC;
extern f32 lbl_803E3558;
extern f32 lbl_803E3540;
extern f32 lbl_803E3588;

void pushable_init(s16* obj, char* def);


extern int lbl_802C2270[];
extern int fn_802969F0(void);
extern void setMatrixFromObjectPos(f32* mtx, void* vec);
extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void Obj_BuildTransformMatrices(int* obj);
extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int* obj);
extern void hitDetect_calcSweptSphereBounds(int* boundsOut, f32* startPoints, f32* endPoints, int* box, int count);
extern void hitDetectFn_800691c0(int* obj, int* bounds, int a, int b);
extern f32 lbl_803E35A8;
extern f32 lbl_803E35AC;
extern f32 lbl_803E35B0;
extern f32 lbl_803E35B4;
extern f32 lbl_803E35B8;
extern f32 lbl_803E35BC;
extern f32 lbl_803E35C0;
extern f32 lbl_803E35C4;
extern f32 lbl_803E35C8;

typedef struct
{
    int a, b, c, d;
} PushableBox16;

typedef struct
{
    u8 pad[0x24];
    f32 vx;
    u8 pad2[4];
    f32 vz;
} PushableObjPos;


extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int hitDetectFn_80067958(int a, f32* start, f32* end, int b, void* buf, int c);
extern int objBboxFn_800640cc(f32* start, f32* end, f32 radius, int a, int b, int* obj, int c, int d, int e, int f);
extern f32 lbl_803E3590;
extern f32 lbl_803E3594;
extern f32 lbl_803E359C;
extern f32 lbl_803E35A0;
extern f32 lbl_803E35A4;

typedef struct
{
    f32 r[4];
    s8 b10;
    u8 pad1[3];
    u8 b14;
    u8 pad2[0x17];
    s16 h2c;
    s16 pad3;
} SetScaleParams;


extern void fn_8003B5E0(int a, int b, int c, int d);

