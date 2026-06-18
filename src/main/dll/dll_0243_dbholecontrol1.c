/*
 * DLL 0x243 - DBHoleControl1 [801FE118-801FEB30)
 *
 * Spawn/cleanup controller for a dbhole. update() removes the object
 * (and hides its anim) once its disable game bit is set, otherwise runs
 * the placement trigger sequence when its trigger game bit is set. SeqFn
 * services the placement's animation sequence events: event 1 spawns a
 * follow-up object (rom-list item 0x4658A, type 1337) inheriting this
 * object's position when loading is locked and the per-place bit is
 * clear; once the disable bit (or lbl_803DDCE0) is set it broadcasts a
 * teardown message to ObjGroup 36 and removes every member.
 *
 * Also carries DBstealerwo_setFuncPtrs (the dbstealerworm state-handler
 * dispatch-table init) which links into this object's section.
 */
#include "main/game_object.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/anim.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern void objRenderFn_8003b8f4(f32);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

typedef struct Dbholecontrol1Placement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    s8 unk18;
    s8 unk19;
    u8 pad1A[0x1C - 0x1A];
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} Dbholecontrol1Placement;

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int dbstealerworm_stateHandlerB04(int obj, int p);

int dbstealerworm_stateHandlerB02(int obj, int p);

extern void Obj_RemoveFromUpdateList(int* obj);
extern f32 lbl_803E6390;
extern int gDBStealerWormStateHandlersA[];
extern int gDBStealerWormStateHandlersB[];

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
    if (GameBit_Get(((Dbholecontrol1Placement*)def)->unk1E) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }
    else if (GameBit_Get(((Dbholecontrol1Placement*)def)->unk20) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(((Dbholecontrol1Placement*)def)->unk19, obj, -1);
    }
}

void dbholecontrol1_init(int* obj, u8* params)
{
    extern undefined4 ObjGroup_AddObject(); /* #57 */
    DbHoleControl1State* sub = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 0x1e);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dbholecontrol1_SeqFn;
    sub->gameBitA = *(s16*)(params + 0x1a);
    sub->gameBitB = *(s16*)(params + 0x1c);
}

int dbholecontrol1_getExtraSize(void) { return 0xc; }
int dbholecontrol1_getObjectTypeId(void) { return 0x0; }

void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(lbl_803E6390);
}

void dbholecontrol1_free(int x) { extern undefined8 ObjGroup_RemoveObject(); /* #57 */ ObjGroup_RemoveObject(x, 0x1e); }

int dbstealerworm_stateHandlerB00(int p1, int p2);

int dbstealerworm_stateHandlerB03(int p1, int p2);

int dbstealerworm_stateHandlerB01(int p1, int p2);

int dbstealerworm_stateHandlerA00(int obj, int p2);

int dbstealerworm_stateHandlerA02(int obj, int p2);

int dbstealerworm_stateHandlerA04(int obj, int param2);

int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA0A(int obj, int p2);

int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA0D(int obj, int p2);

int dbstealerworm_stateHandlerA0E(int obj, int param2);

int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerB05(int obj, int p2);

int dbstealerworm_stateHandlerB06(int obj, int p2);

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern void*mapRomListFindItem(int, int, int, int, int);
    extern int Obj_AllocObjectSetup(int, int);
    extern void memcpy(int, void*, int);
    extern void loadObjectAtObject(int, int);
    extern int*ObjGroup_GetObjects(int, int*);
    extern void ObjGroup_RemoveObject(int, int);
    extern void ObjMsg_SendToObjects(int, int, int, int, int);
    extern int lbl_803DDCE0;
    int newObj;
    void* res;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (GameBit_Get((s32)((Dbholecontrol1Placement*)data)->unk19 + 2601) != 0) continue;
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

    if (GameBit_Get(((Dbholecontrol1Placement*)data)->unk1E) != 0 || lbl_803DDCE0 != 0)
    {
        int count;
        int* objs = ObjGroup_GetObjects(36, &count);
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
