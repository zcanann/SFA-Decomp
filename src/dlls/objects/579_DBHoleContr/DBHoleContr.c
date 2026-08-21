/* DBHoleContr (DLL 0x243) */
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/object_update_list.h"
#include "main/objtype.h"
#include "string.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "sys/objects.h"
#include "main/dll/dll_0243_dbholecontrol1.h"
#include "main/dll/baddie_state.h"
#include "main/lightmap.h"

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

#define DBEGG_OBJGROUP           0x24
#define DBHOLECONTROL1_CHILD_OBJ        1337
#define DBHOLECONTROL1_CHILD_SETUP_SIZE 56

int lbl_803DDCE0;

int dbholecontrol1_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    GroundBaddiePlacement* childPlacement;
    void* res;
    GameObject** objs;
    int count;
    Dbholecontrol1Placement* data = (Dbholecontrol1Placement*)obj->anim.placementData;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (mainGetBit((s32)data->triggerSeqId + 2601) != 0)
                continue;
            if (Obj_CanSetupObject() == 0)
                continue;
            res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
            if (res == NULL)
                continue;
            childPlacement = (GroundBaddiePlacement*)Obj_AllocObjectSetup(DBHOLECONTROL1_CHILD_SETUP_SIZE, DBHOLECONTROL1_CHILD_OBJ);
            memcpy(childPlacement, res, DBHOLECONTROL1_CHILD_SETUP_SIZE);
            childPlacement->base.posX = obj->anim.localPosX;
            childPlacement->base.posY = obj->anim.localPosY;
            childPlacement->base.posZ = obj->anim.localPosZ;
            childPlacement->base.ident = -1;
            childPlacement->gameBitC = 149;
            loadObjectAtObject(obj, &childPlacement->base);
            break;
        }
    }

    if (mainGetBit(data->hideGameBit) != 0 || lbl_803DDCE0 != 0)
    {
        objs = objGetAllOfType(DBEGG_OBJGROUP, &count);
        ObjMsg_SendToObjects(0, 3, obj, 17, 0);
        while (count-- != 0)
        {
            objFreeObjectType(*objs++, DBEGG_OBJGROUP);
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

void dbholecontrol1_free(GameObject* obj)
{
    objFreeObjectType(obj, DBHOLE_CONTROL1_OBJECT_GROUP);
}

void dbholecontrol1_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 enabled = visible;
    if (enabled != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (1.0f));
}

void dbholecontrol1_hitDetect(void)
{
}

void dbholecontrol1_update(GameObject* obj)
{

    Dbholecontrol1Placement* def;
    def = (Dbholecontrol1Placement*)obj->anim.placementData;
    if (mainGetBit(def->hideGameBit) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
    }
    else if (mainGetBit(def->triggerGameBit) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(def->triggerSeqId, obj, -1);
    }
}

void dbholecontrol1_init(GameObject* obj, u8* params)
{
    DbHoleControl1State* state = obj->extra;
    objAddObjectType(obj, DBHOLE_CONTROL1_OBJECT_GROUP);
    obj->anim.rotX = (s16)(((Dbholecontrol1Placement*)params)->rotXByte << 8);
    obj->animEventCallback = dbholecontrol1_SeqFn;
    state->gameBitA = ((Dbholecontrol1Placement*)params)->gameBitA;
    state->gameBitB = ((Dbholecontrol1Placement*)params)->gameBitB;
}

void dbholecontrol1_release(void)
{
}

void dbholecontrol1_initialise(void)
{
}

ObjectDescriptor gDBHoleControl1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dbholecontrol1_initialise,
    (ObjectDescriptorCallback)dbholecontrol1_release,
    0,
    (ObjectDescriptorCallback)dbholecontrol1_init,
    (ObjectDescriptorCallback)dbholecontrol1_update,
    (ObjectDescriptorCallback)dbholecontrol1_hitDetect,
    (ObjectDescriptorCallback)dbholecontrol1_render,
    (ObjectDescriptorCallback)dbholecontrol1_free,
    (ObjectDescriptorCallback)dbholecontrol1_getObjectTypeId,
    dbholecontrol1_getExtraSize,
};
