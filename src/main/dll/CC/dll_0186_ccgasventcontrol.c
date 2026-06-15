#include "main/dll/DIM/dimlogfire.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct CcgasventcontrolState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    s16 unkC;
    u8 padE[0x10 - 0xE];
} CcgasventcontrolState;

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803ad590;
extern undefined4 DAT_803ad598;
extern undefined4 DAT_803ad59c;
extern undefined4 DAT_803ad5a0;
extern undefined4 DAT_803ad5a4;
extern f32 lbl_803DC074;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;

#pragma scheduling on
#pragma peephole on
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4620;
extern void disableHeavyFog(void);
extern u8 CCGasVentControlFn_801a9fd0(int obj, int extra);
extern int* ObjGroup_GetObjects(int group, int* count);
extern f32 lbl_803E4618;
extern f32 timeDelta;
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int id);
extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, u8 mode);
extern f32 lbl_803E4624;
extern f32 lbl_803E4628;
extern f32 lbl_803E462C;
extern f32 lbl_803E4630;
extern f32 lbl_803E4634;
extern f32 lbl_803E4638;
extern f32 lbl_803E463C;
extern f32 lbl_803E4640;
extern f32 getXZDistance(f32 * a, f32 * b);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern void Sfx_SetObjectSfxVolume(int obj, int sound, int vol, f32 v);
extern f32 lbl_803E461C;

void FUN_801a8f88(void)
{
    int control;
    uint rnd;
    short* state;

    control = FUN_80286840();
    state = *(short**)(control + 0xb8);
    if (((int)*state == 0xffffffff) || (rnd = GameBit_Get((int)*state), rnd != 0))
    {
        *(float*)(state + 0x14) = *(float*)(state + 0x14) - lbl_803DC074;
        if (*(float*)(state + 0x14) < lbl_803E5248)
        {
            *(float*)(state + 0xc) = lbl_803E524C;
            rnd = randomGetRange(-(uint)(ushort)state[1], (uint)(ushort)state[1]);
            *(float*)(state + 0xe) =
                (f32)(s32)(rnd);
            rnd = randomGetRange(-(uint)(ushort)state[3], (uint)(ushort)state[3]);
            *(float*)(state + 0x10) =
                (f32)(s32)(rnd);
            rnd = randomGetRange(-(uint)(ushort)state[2], (uint)(ushort)state[2]);
            *(float*)(state + 0x12) =
                (f32)(s32)(rnd);
            FUN_80017748((ushort*)(state + 4), (float*)(state + 0xe));
            *(float*)(state + 0xe) = *(float*)(state + 0xe) + *(float*)(control + 0xc);
            *(float*)(state + 0x10) = *(float*)(state + 0x10) + *(float*)(control + 0x10);
            *(float*)(state + 0x12) = *(float*)(state + 0x12) + *(float*)(control + 0x14);
            rnd = randomGetRange(100, 200);
            *(float*)(state + 0x14) =
                (f32)(s32)(rnd);
            rnd = randomGetRange(0x32, 100);
            *(float*)(state + 0x16) =
                (f32)(s32)(rnd);
        }
        *(float*)(state + 0x16) = *(float*)(state + 0x16) - lbl_803DC074;
        if (lbl_803E5248 < *(float*)(state + 0x16))
        {
            (*gPartfxInterface)->spawnObject((void*)control, 0x71f, state + 8, 0x200001, -1, NULL);
        }
        DAT_803ad598 = lbl_803E524C;
        rnd = randomGetRange(-(uint)(ushort)state[1], (uint)(ushort)state[1]);
        DAT_803ad59c = (f32)(s32)(rnd);
        rnd = randomGetRange(-(uint)(ushort)state[3], (uint)(ushort)state[3]);
        DAT_803ad5a0 = (f32)(s32)(rnd);
        rnd = randomGetRange(-(uint)(ushort)state[2], (uint)(ushort)state[2]);
        DAT_803ad5a4 = (f32)(s32)(rnd);
        FUN_80017748((ushort*)(state + 4), &DAT_803ad59c);
        DAT_803ad59c = DAT_803ad59c + *(float*)(control + 0xc);
        DAT_803ad5a0 = DAT_803ad5a0 + *(float*)(control + 0x10);
        DAT_803ad5a4 = DAT_803ad5a4 + *(float*)(control + 0x14);
        (*gPartfxInterface)->spawnObject((void*)control, 0x720, &DAT_803ad590, 0x200001, -1, NULL);
    }
    FUN_8028688c();
    return;
}

undefined4
FUN_801a9408(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             ObjAnimUpdateState* animUpdate)
{
    byte eventType;
    undefined2* spawnDef;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int i;
    int child;
    undefined8 detached;

    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventType = animUpdate->eventIds[i];
        if (eventType == 2)
        {
            child = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (child != 0)
            {
                detached = ObjLink_DetachChild(param_9, child);
                param_1 = FUN_80017ac8(detached, param_2, param_3, param_4, param_5, param_6, param_7, param_8, child);
            }
            *(undefined4*)(param_9 + 0xf8) = 0xffffffff;
        }
        else if ((eventType < 2) && (eventType != 0))
        {
            *(undefined4*)(param_9 + 0xf8) = 0x30b;
            child = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (child != 0)
            {
                detached = ObjLink_DetachChild(param_9, child);
                param_1 = FUN_80017ac8(detached, param_2, param_3, param_4, param_5, param_6, param_7, param_8, child);
            }
            spawnDef = FUN_80017aa4(0x20, (short)*(undefined4*)(param_9 + 0xf8));
            child = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, spawnDef, 4,
                                 ((GameObject*)param_9)->anim.mapEventSlot, 0xffffffff,
                                 *(uint**)&((GameObject*)param_9)->anim.parent,
                                 in_r8, in_r9, in_r10);
            param_1 = ObjLink_AttachChild(param_9, child, 0);
        }
    }
    return 0;
}

void animsharpclaw_hitDetect(void);

int ccgasventcontrol_getExtraSize(void) { return 0x10; }
int ccqueen_getExtraSize(void);

#pragma peephole off
void ccgasventcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4620);
}

#pragma scheduling off
void ccgasventcontrol_free(int obj)
{
    char* inner = ((GameObject*)obj)->extra;
    u8 t = *(u8*)inner;
    if (t == 3 || t == 4)
    {
        disableHeavyFog();
    }
    (*gGameUIInterface)->airMeterSetShutdown();
}

void ccgasventcontrol_init(int obj, u8* p)
{
    char* inner = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)CCGasVentControl_SeqFn;
    *(s16*)obj = (s16)((u32)p[0x1a] << 8);
    if (GameBit_Get(0xa3) != 0)
    {
        *(u8*)inner = 7;
    }
}

#pragma peephole on
int CCGasVentControl_SeqFn(int obj)
{
    CCGasVentControlFn_801a9fd0(obj, *(int*)&((GameObject*)obj)->extra);
    return 0;
}

#pragma peephole off
void ccgasventcontrol_update(int obj)
{
    int ex = *(int*)&((GameObject*)obj)->extra;
    u8 b = CCGasVentControlFn_801a9fd0(obj, ex);
    switch (*(u8*)ex)
    {
    case 0:
        {
            int cnt;
            ObjGroup_GetObjects(0x3f, &cnt);
            if (cnt == 4)
            {
                *(u8*)ex = 1;
            }
            break;
        }
    case 1:
        if (GameBit_Get(0x3ec) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            *(u8*)ex = 2;
        }
        break;
    case 2:
        (*gGameUIInterface)->initAirMeter(6000, 0x603);
        ((CcgasventcontrolState*)ex)->unk4 = lbl_803E4624;
        *(u8*)ex = 3;
        *(u8*)((char*)ex + 0xc) = b;
        break;
    case 3:
        if (b != 0)
        {
            int player = Obj_GetPlayerObject();
            ((CcgasventcontrolState*)ex)->unk8 = ((CcgasventcontrolState*)ex)->unk8 + timeDelta / lbl_803E4618;
            if (((CcgasventcontrolState*)ex)->unk8 > lbl_803E4628)
            {
                ((CcgasventcontrolState*)ex)->unk8 = *(f32*)&lbl_803E4628;
            }
            if (((GameObject*)player)->anim.localPosY <= ((GameObject*)obj)->anim.localPosY + ((CcgasventcontrolState*)
                ex)->unk8)
            {
                ((CcgasventcontrolState*)ex)->unk4 = -(timeDelta * (f32)b - ((CcgasventcontrolState*)ex)->unk4);
            }
            else
            {
                ((CcgasventcontrolState*)ex)->unk4 = lbl_803E462C * timeDelta + ((CcgasventcontrolState*)ex)->unk4;
                if (((CcgasventcontrolState*)ex)->unk4 > lbl_803E4624)
                {
                    ((CcgasventcontrolState*)ex)->unk4 = *(f32*)&lbl_803E4624;
                }
            }
            enableHeavyFog(((GameObject*)obj)->anim.localPosY + ((CcgasventcontrolState*)ex)->unk8,
                           ((GameObject*)obj)->anim.localPosY - lbl_803E4630, lbl_803E4634, lbl_803E4638,
                           lbl_803E463C, 0);
            if (((CcgasventcontrolState*)ex)->unk4 >= lbl_803E4640)
            {
                (*gGameUIInterface)->runAirMeter((int)((CcgasventcontrolState*)ex)->unk4);
            }
            else
            {
                (*gGameUIInterface)->airMeterSetShutdown();
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)player)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)player)->anim.localPosY;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)player)->anim.localPosZ;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                *(u8*)ex = 4;
            }
            if (b != *(u8*)((char*)ex + 0xc))
            {
                Sfx_PlayFromObject(0, 0x409);
                *(u8*)((char*)ex + 0xc) = b;
            }
        }
        else
        {
            Sfx_PlayFromObject(0, 0x7e);
            (*gGameUIInterface)->airMeterSetShutdown();
            GameBit_Set(0xa3, 1);
            GameBit_Set(0x620, 0);
            *(u8*)ex = 5;
        }
        break;
    case 4:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case 5:
        {
            int player = Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint(player + 0xc, *(s16*)player, 1, 0);
            *(u8*)ex = 6;
            break;
        }
    case 6:
        if (GameBit_Get(0x1c0) == 0)
        {
            disableHeavyFog();
            *(u8*)ex = 7;
        }
        break;
    }
}

u8 CCGasVentControlFn_801a9fd0(int obj, int extra)
{
    u8 i;
    u8 count = 0;
    if (GameBit_Get(0x1c0) != 0)
    {
        int cnt;
        int* list = ObjGroup_GetObjects(0x3f, &cnt);
        f32 thr;
        i = 0;
        thr = lbl_803E4618;
        for (; i < 4; i++)
        {
            int other = ObjGroup_FindNearestObject(5, list[i], 0);
            if (getXZDistance((f32*)(list[i] + 0x18), (f32*)(other + 0x18)) > thr)
            {
                count = (u8)count + 1;
            }
        }
    }
    if (count != 0)
    {
        if (*(u8*)((char*)extra + 1) == 0)
        {
            Sfx_AddLoopedObjectSound(obj, 0x223);
            *(u8*)((char*)extra + 1) = 1;
        }
        Sfx_SetObjectSfxVolume(obj, 0x223, (u8)(count * 0xf + 0x28), lbl_803E461C);
    }
    else
    {
        if (*(u8*)((char*)extra + 1) != 0)
        {
            Sfx_RemoveLoopedObjectSound(obj, 0x223);
            *(u8*)((char*)extra + 1) = 0;
        }
    }
    return count;
}
