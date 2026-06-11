#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/dll/creator1C6.h"

extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern int Obj_GetPlayerObject(void);
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern void ObjGroup_RemoveObject(int obj, int group);
extern void ModelLightStruct_free(int light);
extern void gameTimerStop(void);
extern void Music_Trigger(int id, int mode);
extern void GameBit_Set(int eventId, int value);
extern void unlockLevel(int param_1, int param_2, int param_3);
extern int mapGetDirIdx(int idx);
extern void lockLevel(int idx, int param_2);
extern void modelLightStruct_setEnabled(int light, int enabled, double scale);
extern void objRenderFn_8003b8f4(double scale, int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5);
extern void objParticleFn_80099d84(int obj, f32 scale, int kind, f32 fextra, int light);
extern void fn_80296518(int obj, int param_2, int param_3);
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803de848;
extern MapEventInterface** gMapEventInterface;
extern f64 DOUBLE_803e5d28;
extern f64 DOUBLE_803e5d68;
extern f32 lbl_803DC074;
extern f32 lbl_803E50D8;
extern f32 lbl_803E5CFC;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D1C;
extern f32 lbl_803E5D38;
extern f32 lbl_803E5D3C;
extern f32 lbl_803E5D40;
extern f32 lbl_803E5D44;
extern f32 lbl_803E5D50;
extern f32 lbl_803E5D54;
extern f32 lbl_803E5D58;
extern f32 lbl_803E5D5C;
extern f32 lbl_803E5D60;

/*
 * --INFO--
 *
 * Function: fn_801C8EBC
 * EN v1.0 Address: 0x801C8EBC
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801C8FE8
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_801C8EBC(int obj, undefined4 unused, ObjAnimUpdateState* animUpdate)
{
    struct Creator1C6Flag15
    {
        u8 b80 : 1;
        u8 rest : 7;
    };
    void** state;
    int player;
    int i;
    u32 event;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;

    for (i = 0; i < (s32)animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        if (event != 0)
        {
            switch (event)
            {
            case 3:
                ((struct Creator1C6Flag15*)((u8*)state + 0x15))->b80 = 1;
                break;
            case 7:
                fn_80296518(player, 2, 1);
                GameBit_Set(0x15f, 1);
                GameBit_Set(0xc6e, 1);
                (*gMapEventInterface)->setMode(0xb, 3);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            case 0xe:
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | 0x4000);
                if (state[0] != NULL)
                {
                    modelLightStruct_setEnabled((int)state[0], 0, (double)lbl_803E50D8);
                }
                break;
            case 0xf:
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~0x4000);
                if (state[0] != NULL)
                {
                    modelLightStruct_setEnabled((int)state[0], 0, (double)lbl_803E50D8);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }

    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9018
 * EN v1.0 Address: 0x801C9018
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C911C
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: dbsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C9040
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int dbsh_shrine_getExtraSize(void)
{
    return 0x18;
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C9048
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dbsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void dbsh_shrine_free(int obj)
{
    void** state;

    state = ((GameObject*)obj)->extra;
    if (state[0] != NULL)
    {
        ModelLightStruct_free((int)state[0]);
        state[0] = NULL;
    }
    gameTimerStop();
    ObjGroup_RemoveObject(obj, 0xb);
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(8, 0);
    Music_Trigger(0xe, 0);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
}

void dbsh_shrine_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, s8 visible)
{
    void** state;

    state = ((GameObject*)obj)->extra;
    if (visible == 0)
    {
        if (state[0] != NULL)
        {
            modelLightStruct_setEnabled((int)state[0], 0, (double)lbl_803E50D8);
        }
    }
    else
    {
        if (state[0] != NULL)
        {
            modelLightStruct_setEnabled((int)state[0], 1, (double)lbl_803E50D8);
        }
        ((void (*)(int, undefined4, undefined4, undefined4, undefined4, f32))objRenderFn_8003b8f4)(
            obj, p2, p3, p4, p5, lbl_803E50D8);
        objParticleFn_80099d84(obj, lbl_803E50D8, 7, *(f32*)&lbl_803E50D8, (int)state[0]);
    }
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C91AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_shrine_hitDetect(void)
{
}
