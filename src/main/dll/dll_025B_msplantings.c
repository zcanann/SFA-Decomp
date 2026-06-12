#include "main/dll/DIM/dimlogfire.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct MoonSeedPlantingSpotPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
} MoonSeedPlantingSpotPlacement;

typedef struct MoonSeedPlantingSpotState
{
    u8 pad0[0x1 - 0x0];
    u8 flags;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 unk24;
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    u8 unk57;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x94 - 0x70];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xA0 - 0x9C];
} MoonSeedPlantingSpotState;

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803ad590;
extern undefined4 DAT_803ad598;
extern undefined4 DAT_803ad59c;
extern undefined4 DAT_803ad5a0;
extern undefined4 DAT_803ad5a4;
extern EffectInterface** gPartfxInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803DC074;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;

void FUN_801a8f88(void)
{
    int iVar1;
    uint uVar2;
    short* psVar3;

    iVar1 = FUN_80286840();
    psVar3 = *(short**)(iVar1 + 0xb8);
    if (((int)*psVar3 == 0xffffffff) || (uVar2 = GameBit_Get((int)*psVar3), uVar2 != 0))
    {
        *(float*)(psVar3 + 0x14) = *(float*)(psVar3 + 0x14) - lbl_803DC074;
        if (*(float*)(psVar3 + 0x14) < lbl_803E5248)
        {
            *(float*)(psVar3 + 0xc) = lbl_803E524C;
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[1], (uint)(ushort)psVar3[1]);
            *(float*)(psVar3 + 0xe) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[3], (uint)(ushort)psVar3[3]);
            *(float*)(psVar3 + 0x10) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[2], (uint)(ushort)psVar3[2]);
            *(float*)(psVar3 + 0x12) =
                (f32)(s32)(uVar2);
            FUN_80017748((ushort*)(psVar3 + 4), (float*)(psVar3 + 0xe));
            *(float*)(psVar3 + 0xe) = *(float*)(psVar3 + 0xe) + *(float*)(iVar1 + 0xc);
            *(float*)(psVar3 + 0x10) = *(float*)(psVar3 + 0x10) + *(float*)(iVar1 + 0x10);
            *(float*)(psVar3 + 0x12) = *(float*)(psVar3 + 0x12) + *(float*)(iVar1 + 0x14);
            uVar2 = randomGetRange(100, 200);
            *(float*)(psVar3 + 0x14) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(0x32, 100);
            *(float*)(psVar3 + 0x16) =
                (f32)(s32)(uVar2);
        }
        *(float*)(psVar3 + 0x16) = *(float*)(psVar3 + 0x16) - lbl_803DC074;
        if (lbl_803E5248 < *(float*)(psVar3 + 0x16))
        {
            (*gPartfxInterface)->spawnObject((void*)iVar1, 0x71f, psVar3 + 8, 0x200001, -1, NULL);
        }
        DAT_803ad598 = lbl_803E524C;
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[1], (uint)(ushort)psVar3[1]);
        DAT_803ad59c = (f32)(s32)(uVar2);
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[3], (uint)(ushort)psVar3[3]);
        DAT_803ad5a0 = (f32)(s32)(uVar2);
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[2], (uint)(ushort)psVar3[2]);
        DAT_803ad5a4 = (f32)(s32)(uVar2);
        FUN_80017748((ushort*)(psVar3 + 4), &DAT_803ad59c);
        DAT_803ad59c = DAT_803ad59c + *(float*)(iVar1 + 0xc);
        DAT_803ad5a0 = DAT_803ad5a0 + *(float*)(iVar1 + 0x10);
        DAT_803ad5a4 = DAT_803ad5a4 + *(float*)(iVar1 + 0x14);
        (*gPartfxInterface)->spawnObject((void*)iVar1, 0x720, &DAT_803ad590, 0x200001, -1, NULL);
    }
    FUN_8028688c();
    return;
}

undefined4
FUN_801a9408(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             ObjAnimUpdateState* animUpdate)
{
    byte bVar1;
    undefined2* puVar2;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int iVar3;
    int iVar4;
    undefined8 uVar5;

    for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1)
    {
        bVar1 = animUpdate->eventIds[iVar3];
        if (bVar1 == 2)
        {
            iVar4 = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (iVar4 != 0)
            {
                uVar5 = ObjLink_DetachChild(param_9, iVar4);
                param_1 = FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
            }
            *(undefined4*)(param_9 + 0xf8) = 0xffffffff;
        }
        else if ((bVar1 < 2) && (bVar1 != 0))
        {
            *(undefined4*)(param_9 + 0xf8) = 0x30b;
            iVar4 = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (iVar4 != 0)
            {
                uVar5 = ObjLink_DetachChild(param_9, iVar4);
                param_1 = FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
            }
            puVar2 = FUN_80017aa4(0x20, (short)*(undefined4*)(param_9 + 0xf8));
            iVar4 = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, puVar2, 4,
                                 ((GameObject*)param_9)->anim.mapEventSlot, 0xffffffff,
                                 *(uint**)&((GameObject*)param_9)->anim.parent,
                                 in_r8, in_r9, in_r10);
            param_1 = ObjLink_AttachChild(param_9, iVar4, 0);
        }
    }
    return 0;
}

void animsharpclaw_hitDetect(void);

void MoonSeedPlantingSpot_hitDetect(void)
{
}

void MoonSeedPlantingSpot_release(void)
{
}

void MoonSeedPlantingSpot_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void MoonSeedPlantingSpot_init(int* obj, u8* init)
{
    u8* sub;
    int mapId;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)MoonSeedPlantingSpot_SeqFn;
    *(s16*)obj = (s16)(init[0x1f] << 8);
    sub[0] = 0;
    ObjGroup_AddObject((int)obj, 0x2e);
    mapId = *(int*)(init + 0x14);
    switch (mapId)
    {
    case 0x41a5b:
        *(s16*)(sub + 8) = 0x866;
        *(s16*)(sub + 0xa) = 0x856;
        break;
    case 0x41a59:
        *(s16*)(sub + 8) = 0x867;
        *(s16*)(sub + 0xa) = 0x858;
        break;
    case 0x41a5c:
        *(s16*)(sub + 8) = 0x868;
        *(s16*)(sub + 0xa) = 0x85a;
        break;
    case 0x41a5d:
        *(s16*)(sub + 8) = 0x869;
        *(s16*)(sub + 0xa) = 0x864;
        break;
    case 0x43e04:
        *(s16*)(sub + 8) = 0x9a2;
        *(s16*)(sub + 0xa) = 0x99a;
        break;
    case 0x43e1f:
        *(s16*)(sub + 8) = 0x9a3;
        *(s16*)(sub + 0xa) = 0x99c;
        break;
    case 0x43e20:
        *(s16*)(sub + 8) = 0x9a4;
        *(s16*)(sub + 0xa) = 0x99e;
        break;
    case 0x43e21:
        *(s16*)(sub + 8) = 0x9a5;
        *(s16*)(sub + 0xa) = 0x9a0;
        break;
    case 0x476ae:
        *(s16*)(sub + 8) = 0x3d5;
        *(s16*)(sub + 0xa) = 0x3d2;
        break;
    case 0x4b26e:
        *(s16*)(sub + 8) = 0xd4d;
        *(s16*)(sub + 0xa) = 0xd4b;
        break;
    case 0x4bea3:
        *(s16*)(sub + 8) = 0xe21;
        *(s16*)(sub + 0xa) = 0xe10;
        break;
    }
    sub[1] = 0;
}
void ccgasvent_render(void);

int MoonSeedPlantingSpot_render2(void) { return 0x2; }
int MoonSeedPlantingSpot_modelMtxFn(void) { return 0x0; }
int MoonSeedPlantingSpot_func0B(void) { return 0x0; }
int MoonSeedPlantingSpot_getExtraSize(void) { return 0x18; }
int MoonSeedPlantingSpot_getObjectTypeId(void) { return 0x1; }
int ccgasvent_getExtraSize(void);

extern void objRenderFn_8003b8f4(f32);

void MoonSeedPlantingSpot_free(int x) { ObjGroup_RemoveObject(x, 0x2e); }
void ccgasvent_free(int x);

int MoonSeedPlantingSpot_SeqFn(int obj)
{
    obj = *(int*)&((GameObject*)obj)->extra;
    *(u8*)(obj + 1) = (u8)((uint) * (u8*)(obj + 1) | 1);
    return 0;
}

extern u8 CCGasVentControlFn_801a9fd0(int obj, int extra);

extern f32 timeDelta;
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int id);

extern f32 getXZDistance(f32 * a, f32 * b);

extern int getTrickyObject(void);
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern f32 lbl_803E45DC;
extern f32 lbl_803E45F0;
extern f32 lbl_803E45F4;
extern f32 lbl_803E45F8;
extern f32 lbl_803E45FC;
extern f32 lbl_803E4600;
extern f32 lbl_803E4604;
extern f32 lbl_803E4608;

void MoonSeedPlantingSpot_update(int obj)
{
    int ex = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((MoonSeedPlantingSpotState*)ex)->flags & 1)
    {
        *(u8*)ex = 2;
        GameBit_Set(*(s16*)((char*)ex + 8), 1);
        ((MoonSeedPlantingSpotState*)ex)->flags = ((MoonSeedPlantingSpotState*)ex)->flags & ~1;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) && !(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 8))
    {
        if (GameBit_Get(0x86a) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    ((MoonSeedPlantingSpotState*)ex)->flags |= 2;
    switch (*(u8*)ex)
    {
    case 0:
        *(u8*)ex = 1;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY - lbl_803E45F0;
        if (GameBit_Get(*(s16*)((char*)ex + 8)) != 0)
        {
            *(u8*)ex = 2;
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        if (GameBit_Get(*(s16*)((char*)ex + 0xa)) != 0)
        {
            int setup2;
            int ex2;
            ex2 = *(int*)&((GameObject*)obj)->extra;
            setup2 = *(int*)&((GameObject*)obj)->anim.placementData;
            if (GameBit_Get(*(s16*)((char*)ex2 + 8)) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(*(s16*)((char*)ex2 + 0xa), 1);
                *(u8*)ex2 = 4;
                ((GameObject*)obj)->anim.localPosY = ((MoonSeedPlantingSpotPlacement*)setup2)->unkC;
            }
        }
        break;
    case 1:
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) &&
            (*gGameUIInterface)->isEventReady(0x86a) != 0)
        {
            int cnt = GameBit_Get(0x86a);
            if (cnt != 0)
            {
                ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
                ((GameObject*)obj)->anim.alpha = 0;
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                GameBit_Set(0x86a, cnt - 1);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        break;
    case 2:
        {
            int tricky = getTrickyObject();
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            if (((MoonSeedPlantingSpotState*)ex)->flags & 2)
            {
                void* player;
                if (((MoonSeedPlantingSpotState*)ex)->flags & 4)
                {
                    ((GameObject*)obj)->anim.localPosY =
                        ((ObjPlacement*)setup)->posY + (f32)(int)
                    randomGetRange(-1, 1);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x70f, NULL, 2, -1, NULL);
                }
                ((MoonSeedPlantingSpotState*)ex)->unk14 = ((MoonSeedPlantingSpotState*)ex)->unk14 - timeDelta;
                if (((MoonSeedPlantingSpotState*)ex)->unk14 <= lbl_803E45F4)
                {
                    if ((int)randomGetRange(0, 1) != 0)
                    {
                        ((MoonSeedPlantingSpotState*)ex)->unk14 = lbl_803E45F8;
                        ((MoonSeedPlantingSpotState*)ex)->flags |= 4;
                        Sfx_PlayFromObject(obj, 0x438);
                    }
                    else
                    {
                        ((MoonSeedPlantingSpotState*)ex)->unk14 = (f32)(int)
                        randomGetRange(0x32, 200);
                        ((MoonSeedPlantingSpotState*)ex)->flags &= ~4;
                    }
                }
                player = (void*)Obj_GetPlayerObject();
                if (player != NULL && getXZDistance(&((GameObject*)player)->anim.worldPosX,
                                                    &((GameObject*)obj)->anim.worldPosX) <= lbl_803E45FC)
                {
                    objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 5, 1, 0x28, lbl_803E4600, 0, 0);
                    (*(void (*)(int, int, int, int))(*(int*)(*(int*)(*(int*)((char*)tricky + 0x68)) + 0x28)))(
                        tricky, obj, 1, 4);
                }
                else
                {
                    objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 6, 1, 0x28, lbl_803E4604, 0, 0);
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0x1a)
                {
                    *(u8*)ex = 3;
                    *(s16*)((char*)ex + 0xc) = 0;
                    ((MoonSeedPlantingSpotState*)ex)->unk10 = lbl_803E4608;
                }
            }
            break;
        }
    case 3:
        {
            int tricky = getTrickyObject();
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
            if (getXZDistance((f32*)(tricky + 0x18), &((GameObject*)obj)->anim.worldPosX) <= lbl_803E45FC)
            {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 5, 1, 0x28, lbl_803E4600, 0, 0);
            }
            else
            {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 6, 1, 0x28, lbl_803E4604, 0, 0);
            }
            if (((MoonSeedPlantingSpotState*)ex)->unk10 <= lbl_803E45F4 && GameBit_Get(*(s16*)((char*)ex + 8)) != 0 &&
                GameBit_Get(*(s16*)((char*)ex + 0xa)) == 0)
            {
                int setup2;
                int ex2;
                ex2 = *(int*)&((GameObject*)obj)->extra;
                setup2 = *(int*)&((GameObject*)obj)->anim.placementData;
                if (GameBit_Get(*(s16*)((char*)ex2 + 8)) != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                    GameBit_Set(*(s16*)((char*)ex2 + 0xa), 1);
                    *(u8*)ex2 = 4;
                    ((GameObject*)obj)->anim.localPosY = ((MoonSeedPlantingSpotPlacement*)setup2)->unkC;
                }
            }
            ((MoonSeedPlantingSpotState*)ex)->unk10 = ((MoonSeedPlantingSpotState*)ex)->unk10 - timeDelta;
            if (((MoonSeedPlantingSpotState*)ex)->unk10 < lbl_803E45F4)
            {
                ((MoonSeedPlantingSpotState*)ex)->unk10 = *(f32*)&lbl_803E45F4;
            }
            break;
        }
    }
}

extern int Obj_AllocObjectSetup(int size, int type);

int MoonSeedPlantingSpot_setScale(int* obj, int arg)
{
    int* sub;
    u8* inner;
    int ret;

    inner = ((GameObject*)obj)->extra;
    ret = 0;
    if (arg == 0)
    {
        if ((inner[1] & 2) != 0)
        {
            inner[0] = 3;
            *(s16*)(inner + 0xc) = 0;
        }
        ret = 1;
    }
    else if (arg == 1)
    {
        if (inner[0] == 3)
        {
            ret = 1;
            if (GameBit_Get(*(s16*)(inner + 8)) != 0 && GameBit_Get(*(s16*)(inner + 0xa)) == 0)
            {
                sub = *(int**)&((GameObject*)obj)->anim.placementData;
                inner = ((GameObject*)obj)->extra;
                if (GameBit_Get(*(s16*)(inner + 8)) != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                    GameBit_Set(*(s16*)(inner + 0xa), 1);
                    inner[0] = 4;
                    ((GameObject*)obj)->anim.localPosY = ((MoonSeedPlantingSpotState*)sub)->unkC;
                }
            }
        }
    }
    return ret;
}

extern f32 lbl_803E45D8;
extern f32 lbl_803E45E0;
extern f32 lbl_803E45E4;
extern f32 mathSinf(f32 x);
extern void fn_8003B608(int r, int g, int b);

void MoonSeedPlantingSpot_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* inner = ((GameObject*)p1)->extra;
    s32 v = visible;
    if (v != 0)
    {
        if (inner[0] == 2)
        {
            if ((inner[1] & 2) != 0)
            {
                f32 s;
                int iv;
                *(s16*)(inner + 0xc) += 0x1000;
                s = mathSinf(lbl_803E45E0 * (f32) * (s16*)(inner + 0xc) / lbl_803E45E4);
                iv = (int)(lbl_803E45D8 * (lbl_803E45DC + s));
                fn_8003B608((u8)(iv + 0x7f), 0xff, 0xff);
            }
        }
        else if (inner[0] == 3)
        {
            if (*(s16*)(inner + 0xc) < 0x7d00)
            {
                *(s16*)(inner + 0xc) += 0xff;
            }
            fn_8003B608((s16)(*(s16*)(inner + 0xc) >> 7), 0xff, 0xff);
        }
        else
        {
            fn_8003B608(0xff, 0xff, 0xff);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E45DC);
    }
}

extern void objSetSlot(void* obj, int slot);
