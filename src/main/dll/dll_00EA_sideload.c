/*
 * sideload (DLL 0x00EA) [0x80171BAC-0x80171C78).
 *
 * The only function this object contributes is sideload_update: a deferred
 * spawner placed in a map. Each tick, once the level has finished loading
 * (Obj_IsLoadingLocked), the player object exists, Tricky is absent, and the
 * placement's arming game bit (placement+0x18) is set, it allocates an object
 * setup (type 0x24), copies the spawner's position into it, hands it to
 * Obj_SetupObject, and seeds the new object's first field from placement
 * field yawByte (<< 8).
 *
 * Foreign ObjectDescriptor tables are not present in this translation unit;
 * each descriptor is defined by its own DLL.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/gamebits.h"
#include "main/dll/dll_00EA_sideload.h"

/* object id sideload_update defers into existence once its arming game bit is set */
#define SIDELOAD_CHILD_OBJ 0x24

void sideload_update(int self)
{
    int state;
    void* obj;
    short* p;

    state = *(int*)&((GameObject*)self)->anim.placementData;
    if ((Obj_IsLoadingLocked() != 0) && (Obj_GetPlayerObject() != 0) && (getTrickyObject() == 0) &&
        (mainGetBit((int)((SideloadPlacement*)state)->armGameBit) != 0))
    {
        obj = Obj_AllocObjectSetup(0x18, SIDELOAD_CHILD_OBJ);
        *(u8*)((char*)obj + 4) = 2;
        *(u8*)((char*)obj + 5) = 4;
        *(u8*)((char*)obj + 7) = 0xff;
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)self)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)self)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)self)->anim.localPosZ;
        p = (short*)Obj_SetupObject((ObjPlacement*)obj, 5, -1, -1, NULL);
        *p = (short)((u8)((SideloadPlacement*)state)->yawByte << 8);
    }
}
