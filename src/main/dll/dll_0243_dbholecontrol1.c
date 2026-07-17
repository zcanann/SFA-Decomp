/* DLL 0x243 - DBHoleControl1 [801FE118-801FEB30) */
#include "main/game_object.h"
#include "main/object_update_list.h"
#include "main/obj_group.h"
#include "main/object_render_legacy.h"
#include "main/object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/audio/sfx_ids.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/obj_message.h"
#include "main/object_api.h"
#include "main/dll/dll_0242_dbstealerworm.h"
#include "main/dll/dll_0243_dbholecontrol1.h"
#include "string.h"

__declspec(section ".sdata2") f32 lbl_803E6390 = 1.0f;

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

#define DBHOLECONTROL1_OBJGROUP  0x1e
#define DBEGG_OBJGROUP           0x24
#define DBHOLECONTROL1_CHILD_OBJ 1337

extern f32 lbl_803E6390;
int lbl_803DDCE0;

extern void* mapRomListFindItem(int, int, int, int, int);

void DBstealerwo_setFuncPtrs_80203c78(void)
{
    gDBStealerWormStateHandlersA[0] = (int)dbstealerworm_stateHandlerA00;
    gDBStealerWormStateHandlersA[1] = (int)dbstealerworm_stateHandlerA01;
    gDBStealerWormStateHandlersA[2] = (int)dbstealerworm_stateHandlerA02;
    gDBStealerWormStateHandlersA[3] = (int)dbstealerworm_stateHandlerA03;
    gDBStealerWormStateHandlersA[4] = (int)dbstealerworm_stateHandlerA04;
    gDBStealerWormStateHandlersA[5] = (int)dbstealerworm_stateHandlerA05;
    gDBStealerWormStateHandlersA[6] = (int)dbstealerworm_stateHandlerA06;
    gDBStealerWormStateHandlersA[7] = (int)dbstealerworm_stateHandlerA07;
    gDBStealerWormStateHandlersA[8] = (int)dbstealerworm_stateHandlerA08;
    gDBStealerWormStateHandlersA[9] = (int)dbstealerworm_stateHandlerA09;
    gDBStealerWormStateHandlersA[10] = (int)dbstealerworm_stateHandlerA0A;
    gDBStealerWormStateHandlersA[11] = (int)dbstealerworm_stateHandlerA0B;
    gDBStealerWormStateHandlersA[12] = (int)dbstealerworm_stateHandlerA0C;
    gDBStealerWormStateHandlersA[13] = (int)dbstealerworm_stateHandlerA0D;
    gDBStealerWormStateHandlersA[14] = (int)dbstealerworm_stateHandlerA0E;
    gDBStealerWormStateHandlersA[15] = (int)dbstealerworm_stateHandlerA0F;
    gDBStealerWormStateHandlersB[0] = (int)dbstealerworm_stateHandlerB00;
    gDBStealerWormStateHandlersB[1] = (int)dbstealerworm_stateHandlerB01;
    gDBStealerWormStateHandlersB[2] = (int)dbstealerworm_stateHandlerB02;
    gDBStealerWormStateHandlersB[3] = (int)dbstealerworm_stateHandlerB03;
    gDBStealerWormStateHandlersB[4] = (int)dbstealerworm_stateHandlerB04;
    gDBStealerWormStateHandlersB[5] = (int)dbstealerworm_stateHandlerB05;
    gDBStealerWormStateHandlersB[6] = (int)dbstealerworm_stateHandlerB06;
}

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int newObj;
    void* res;
    int* objs;
    int count;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (mainGetBit((s32)(s8) * (u8*)(data + 0x19) + 2601) != 0)
                continue;
            if (Obj_IsLoadingLocked() == 0)
                continue;
            res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
            if (res == NULL)
                continue;
            newObj = (int)Obj_AllocObjectSetup(56, DBHOLECONTROL1_CHILD_OBJ);
            memcpy((void*)newObj, res, 56);
            ((GameObject*)newObj)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)newObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)newObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            *(int*)&((GameObject*)newObj)->anim.localPosZ = -1;
            *(s16*)(newObj + 26) = 149;
            loadObjectAtObject((GameObject*)obj, (ObjPlacement*)newObj);
            break;
        }
    }

    if (mainGetBit(((Dbholecontrol1Placement*)data)->hideGameBit) != 0 || lbl_803DDCE0 != 0)
    {
        objs = (int*)ObjGroup_GetObjects(DBEGG_OBJGROUP, &count);
        ObjMsg_SendToObjects(0, 3, (void*)obj, 17, 0);
        while (count-- != 0)
        {
            ObjGroup_RemoveObject(*objs++, DBEGG_OBJGROUP);
        }
        return 4;
    }
    return 0;
}

int dbholecontrol1_getExtraSize(void)
{
    return 0xc;
}
int dbholecontrol1_getObjectTypeId(void)
{
    return 0x0;
}

void dbholecontrol1_free(int obj)
{
    ObjGroup_RemoveObject(obj, DBHOLECONTROL1_OBJGROUP);
}

void dbholecontrol1_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 enabled = visible;
    if (enabled != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6390);
}

void dbholecontrol1_hitDetect(void)
{
}

void dbholecontrol1_update(int* obj)
{

    u8* def;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (mainGetBit(((Dbholecontrol1Placement*)def)->hideGameBit) != 0)
    {
        Obj_RemoveFromUpdateList((u8*)obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }
    else if (mainGetBit(((Dbholecontrol1Placement*)def)->triggerGameBit) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(((Dbholecontrol1Placement*)def)->triggerSeqId, obj, -1);
    }
}

void dbholecontrol1_init(int* obj, u8* params)
{
    DbHoleControl1State* state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject((int)obj, DBHOLECONTROL1_OBJGROUP);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = dbholecontrol1_SeqFn;
    state->gameBitA = ((Dbholecontrol1Placement*)params)->gameBitA;
    state->gameBitB = ((Dbholecontrol1Placement*)params)->gameBitB;
}

void dbholecontrol1_release(void)
{
}

void dbholecontrol1_initialise(void)
{
}
