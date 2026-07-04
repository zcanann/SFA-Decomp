/* DLL 0x243 - DBHoleControl1 [801FE118-801FEB30) */
#include "main/game_object.h"
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
extern void objRenderFn_8003b8f4(f32);

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */

#include "main/audio/sfx_ids.h"
#include "main/dll/anim.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/objhits.h"
#include "main/dll/fx_800944A0_shared.h"

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

/* chuka extra block (extraSize 0xC). */

typedef struct Dbholecontrol1Placement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;
    s16 unk18;
    s16 gameBitA; /* copied into DbHoleControl1State.gameBitA */
    s16 gameBitB; /* copied into DbHoleControl1State.gameBitB */
    s16 hideGameBit;
    s16 triggerGameBit;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} Dbholecontrol1Placement;

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);


int dbstealerworm_stateHandlerB04(int obj, int p);

int dbstealerworm_stateHandlerB02(int obj, int p);

extern void Obj_RemoveFromUpdateList(int* obj);
extern f32 lbl_803E6390;
extern int gDBStealerWormStateHandlersA[];
extern int gDBStealerWormStateHandlersB[];
extern int dbstealerworm_stateHandlerB06();
extern int dbstealerworm_stateHandlerB05();
extern int dbstealerworm_stateHandlerA0E();
extern int dbstealerworm_stateHandlerA0D();
extern int dbstealerworm_stateHandlerA0A();
extern int dbstealerworm_stateHandlerA04();
extern int dbstealerworm_stateHandlerA02();

int dbstealerworm_stateHandlerA09(int obj, int p);

int dbstealerworm_stateHandlerA06(int obj, int p2);

int dbstealerworm_stateHandlerA05(int obj, int p);

int dbstealerworm_stateHandlerA03(int obj, int p);

int dbstealerworm_stateHandlerA01(int obj, int p);

void dbholecontrol1_hitDetect(void)
{
}

void dbholecontrol1_release(void)
{
}

void dbholecontrol1_initialise(void)
{
}

void dbholecontrol1_update(int* obj)
{

    u8* def;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((Dbholecontrol1Placement*)def)->hideGameBit) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }
    else if (GameBit_Get(((Dbholecontrol1Placement*)def)->triggerGameBit) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(*(s8*)(def + 0x19), obj, -1);
    }
}

void dbholecontrol1_init(int* obj, u8* params)
{
    extern u32 ObjGroup_AddObject();
    DbHoleControl1State* sub = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 0x1e);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = dbholecontrol1_SeqFn;
    sub->gameBitA = ((Dbholecontrol1Placement*)params)->gameBitA;
    sub->gameBitB = ((Dbholecontrol1Placement*)params)->gameBitB;
}

int dbholecontrol1_getExtraSize(void) { return 0xc; }
int dbholecontrol1_getObjectTypeId(void) { return 0x0; }

void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E6390);
}

void dbholecontrol1_free(int x) { extern u64 ObjGroup_RemoveObject(); ObjGroup_RemoveObject(x, 0x1e); }

int dbstealerworm_stateHandlerB00(int p1, int p2);

int dbstealerworm_stateHandlerB03(int p1, int p2);

int dbstealerworm_stateHandlerB01(int p1, int p2);

int dbstealerworm_stateHandlerA00(int obj, int p2);

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{

    extern void*mapRomListFindItem(int, int, int, int, int);
    extern int Obj_AllocObjectSetup(int, int);
    extern void memcpy(int, void*, int);
    extern void loadObjectAtObject(int, int);
    extern int*ObjGroup_GetObjects(int, int*);
    extern void ObjMsg_SendToObjects(int, int, int, int, int);
    extern int lbl_803DDCE0;
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
            if (GameBit_Get((s32)(s8) * (u8*)(data + 0x19) + 2601) != 0) continue;
            if (Obj_IsLoadingLocked() == 0) continue;
            res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
            if (res == NULL) continue;
            newObj = Obj_AllocObjectSetup(56, 1337);
            memcpy(newObj, res, 56);
            ((GameObject*)newObj)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)newObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)newObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            *(int*)&((GameObject*)newObj)->anim.localPosZ = -1;
            *(s16*)(newObj + 26) = 149;
            loadObjectAtObject(obj, newObj);
            break;
        }
    }

    if (GameBit_Get(((Dbholecontrol1Placement*)data)->hideGameBit) != 0 || lbl_803DDCE0 != 0)
    {
        objs = ObjGroup_GetObjects(36, &count);
        ObjMsg_SendToObjects(0, 3, obj, 17, 0);
        while (count-- != 0)
        {
            ObjGroup_RemoveObject(*objs++, 36);
        }
        return 4;
    }
    return 0;
}


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

int dbstealerworm_stateHandlerA04(int obj, int param2);

int dbstealerworm_stateHandlerA0E(int obj, int param2);

int dbstealerworm_stateHandlerA02(int obj, int p2);

int dbstealerworm_stateHandlerA0D(int obj, int p2);

int dbstealerworm_stateHandlerB05(int obj, int p2);

int dbstealerworm_stateHandlerB06(int obj, int p2);

int dbstealerworm_stateHandlerA0A(int obj, int p2);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408). */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
