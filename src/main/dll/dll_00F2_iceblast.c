#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/mapEventTypes.h"
#include "main/objhits.h"
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

extern undefined4 FUN_80017748();
extern int FUN_80017a90();
extern undefined8 FUN_80017ac8();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80053c98();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
extern unsigned long GameBit_Set(int eventId, int value);
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 scale);
extern f32 lbl_803E3600;
extern void warpToMap(int mapId, int flag);
extern f32 timeDelta;
extern f32 lbl_803E3604;
extern f32 lbl_803E3608;
extern f32 lbl_803E360C;
extern void* Obj_GetPlayerObject(void);
extern void vecRotateZXY(void* in, void* out);
extern s16* getTrickyObject(void);

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

void invhit_hitDetect(void);

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

int iceblast_getExtraSize(void) { return 0x4; }
int iceblast_getObjectTypeId(void) { return 0x0; }
int flameblast_getExtraSize(void);

void iceblast_render(int* obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3600); }

void WarpPoint_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

#pragma scheduling off
void iceblast_init(int obj, s16* p)
{
    *(f32*)((GameObject*)obj)->extra = (f32) * (s16*)((char*)p + 0x1a);
    ObjHits_SetTargetMask(obj, 1);
}

#pragma peephole off
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
    ObjHits_SetHitVolumeSlot((u32)obj, 0x10, ((IceblastPlacement*)def)->unk19 != 0 ? 3 : 1, 0);
    state[0] = state[0] - timeDelta;
    if (state[0] <= lbl_803E3604)
    {
        f32 zero;
        state[0] = state[0] + lbl_803E3608;
        zero = lbl_803E3604;
        ((f32*)(int)obj)[9] = zero;
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

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off

#pragma opt_common_subs reset
