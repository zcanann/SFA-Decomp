#include "main/dll_000A_expgfx.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/player_target.h"

typedef struct InvhitState
{
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 pad9[0xC - 0x9];
} InvhitState;

typedef struct InvhitObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void* unk1C;
} InvhitObjectDef;

extern undefined4 FUN_80017748();
extern int FUN_80017a90();
extern undefined8 FUN_80017ac8();
extern undefined4 ObjHits_ClearHitVolumes();
extern void Obj_FreeObject(int* obj);
extern int ObjList_ContainsObject();
extern undefined4 FUN_80053c98();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
extern f32 lbl_803E35E8;
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 scale);
extern f32 timeDelta;
extern void* Obj_GetPlayerObject(void);
extern s16* getTrickyObject(void);
extern f32 sqrtf(f32 x);
extern f32 lbl_803AC780[];
extern u8 framesThisStep;
extern s8 hitDetectFn_80065e50(int* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern f32 lbl_803E35EC;
extern f32 lbl_803E35F0;
extern f32 lbl_803E35F4;

static inline int* Transporter_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

undefined4
FUN_80176920(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;

    if (((*(char*)(*(int*)(param_9 + 0x4c) + 0x1d) != '\x02') &&
            (animUpdate->triggerCommand == 1)) &&
        (iVar1 = (int)*(char*)(*(int*)(param_9 + 0x4c) + 0x1a), -1 < iVar1))
    {
        FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar1, '\x01',
                     (int)animUpdate, param_12, param_13, param_14, param_15, param_16);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

void FUN_801778d0(int param_1)
{
    *(u8*)(*(int*)&((GameObject*)param_1)->extra + 0x10) = 1;
    return;
}

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

void invhit_hitDetect(void)
{
}

void invhit_release(void)
{
}

void invhit_initialise(void)
{
}

void iceblast_free(void);

int invhit_getExtraSize(void) { return 0xc; }
int invhit_getObjectTypeId(void) { return 0x0; }
int iceblast_getExtraSize(void);

void invhit_render(int* obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E35E8); }
void iceblast_render(int* obj, int a, int b, int c, int d);

#pragma scheduling off
#pragma peephole off
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

void iceblast_init(int obj, s16* p);

#pragma opt_common_subs off
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
            u32 v = Player_GetTargetObject((int)pl);
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
