#include "main/dll/DIM/dimlogfire.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 ObjGroup_FindNearestObject();
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
extern f32 lbl_803DC074;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;

extern f32 lbl_803E4610;
extern f32 lbl_803E4614;

void FUN_801a8f88(void)
{
    int ctrl;
    uint rnd;
    short* vent;

    ctrl = FUN_80286840();
    vent = *(short**)(ctrl + 0xb8);
    if (((int)*vent == 0xffffffff) || (rnd = GameBit_Get((int)*vent), rnd != 0))
    {
        *(float*)(vent + 0x14) = *(float*)(vent + 0x14) - lbl_803DC074;
        if (*(float*)(vent + 0x14) < lbl_803E5248)
        {
            *(float*)(vent + 0xc) = lbl_803E524C;
            rnd = randomGetRange(-(uint)(ushort)vent[1], (uint)(ushort)vent[1]);
            *(float*)(vent + 0xe) =
                (f32)(s32)(rnd);
            rnd = randomGetRange(-(uint)(ushort)vent[3], (uint)(ushort)vent[3]);
            *(float*)(vent + 0x10) =
                (f32)(s32)(rnd);
            rnd = randomGetRange(-(uint)(ushort)vent[2], (uint)(ushort)vent[2]);
            *(float*)(vent + 0x12) =
                (f32)(s32)(rnd);
            FUN_80017748((ushort*)(vent + 4), (float*)(vent + 0xe));
            *(float*)(vent + 0xe) = *(float*)(vent + 0xe) + *(float*)(ctrl + 0xc);
            *(float*)(vent + 0x10) = *(float*)(vent + 0x10) + *(float*)(ctrl + 0x10);
            *(float*)(vent + 0x12) = *(float*)(vent + 0x12) + *(float*)(ctrl + 0x14);
            rnd = randomGetRange(100, 200);
            *(float*)(vent + 0x14) =
                (f32)(s32)(rnd);
            rnd = randomGetRange(0x32, 100);
            *(float*)(vent + 0x16) =
                (f32)(s32)(rnd);
        }
        *(float*)(vent + 0x16) = *(float*)(vent + 0x16) - lbl_803DC074;
        if (lbl_803E5248 < *(float*)(vent + 0x16))
        {
            (*gPartfxInterface)->spawnObject((void*)ctrl, 0x71f, vent + 8, 0x200001, -1, NULL);
        }
        DAT_803ad598 = lbl_803E524C;
        rnd = randomGetRange(-(uint)(ushort)vent[1], (uint)(ushort)vent[1]);
        DAT_803ad59c = (f32)(s32)(rnd);
        rnd = randomGetRange(-(uint)(ushort)vent[3], (uint)(ushort)vent[3]);
        DAT_803ad5a0 = (f32)(s32)(rnd);
        rnd = randomGetRange(-(uint)(ushort)vent[2], (uint)(ushort)vent[2]);
        DAT_803ad5a4 = (f32)(s32)(rnd);
        FUN_80017748((ushort*)(vent + 4), &DAT_803ad59c);
        DAT_803ad59c = DAT_803ad59c + *(float*)(ctrl + 0xc);
        DAT_803ad5a0 = DAT_803ad5a0 + *(float*)(ctrl + 0x10);
        DAT_803ad5a4 = DAT_803ad5a4 + *(float*)(ctrl + 0x14);
        (*gPartfxInterface)->spawnObject((void*)ctrl, 0x720, &DAT_803ad590, 0x200001, -1, NULL);
    }
    FUN_8028688c();
    return;
}

undefined4
FUN_801a9408(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj,
             ObjAnimUpdateState* animUpdate)
{
    byte eventId;
    undefined2* spawned;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int i;
    int child;
    undefined8 detached;

    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventId = animUpdate->eventIds[i];
        if (eventId == 2)
        {
            child = *(int*)&((GameObject*)obj)->childObjs[0];
            if (child != 0)
            {
                detached = ObjLink_DetachChild(obj, child);
                param_1 = FUN_80017ac8(detached, param_2, param_3, param_4, param_5, param_6, param_7, param_8, child);
            }
            *(undefined4*)(obj + 0xf8) = 0xffffffff;
        }
        else if ((eventId < 2) && (eventId != 0))
        {
            *(undefined4*)(obj + 0xf8) = 0x30b;
            child = *(int*)&((GameObject*)obj)->childObjs[0];
            if (child != 0)
            {
                detached = ObjLink_DetachChild(obj, child);
                param_1 = FUN_80017ac8(detached, param_2, param_3, param_4, param_5, param_6, param_7, param_8, child);
            }
            spawned = FUN_80017aa4(0x20, (short)*(undefined4*)(obj + 0xf8));
            child = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, spawned, 4,
                                 ((GameObject*)obj)->anim.mapEventSlot, 0xffffffff,
                                 *(uint**)&((GameObject*)obj)->anim.parent,
                                 in_r8, in_r9, in_r10);
            param_1 = ObjLink_AttachChild(obj, child, 0);
        }
    }
    return 0;
}

void animsharpclaw_hitDetect(void);

void ccgasvent_render(void)
{
}

int animsharpclaw_getExtraSize(void);
int ccgasvent_getExtraSize(void) { return 0x1; }
int ccgasventcontrol_getExtraSize(void);

#pragma scheduling off
void ccgasvent_free(int x) { ObjGroup_RemoveObject(x, 0x3f); }
#pragma scheduling reset

#pragma scheduling off
void ccgasvent_init(int x) { ObjGroup_AddObject(x, 0x3f); }
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ccgasvent_update(int* obj)
{
    f32 dist = lbl_803E4610;
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x1c0) != 0)
    {
        ObjGroup_FindNearestObject(5, (uint)obj, &dist);
        switch (state[0])
        {
        case 0:
            if (dist >= lbl_803E4614)
            {
                state[0] = 1;
            }
            break;
        case 1:
            if (dist < lbl_803E4614)
            {
                state[0] = 0;
            }
            else
            {
                (*gPartfxInterface)->spawnObject(obj, 0x3df, NULL, 0, -1, NULL);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
