/*
 * DLL 0xEB - SideRepel [80171C78-80171D10)
 *
 * The DLL's own canonical code is the three siderepel callbacks
 * (getExtraSize/free/init): a repel-volume object that registers into
 * object group 0x40 and sizes its hit sphere from the placement radius.
 *
 * Foreign ObjectDescriptor tables are not present in this translation unit;
 * each descriptor is defined by its own DLL.
 */
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_placement.h"
#include "main/dll/dll_00EB_siderepel.h"

/* object group: side-repel object */
#define SIDEREPEL_OBJGROUP 0x40

int siderepel_getExtraSize(void)
{
    return sizeof(SideRepelState);
}

void siderepel_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, SIDEREPEL_OBJGROUP);
}

void siderepel_init(GameObject* obj, SideRepelPlacement* placement)
{
    obj->objectFlags =
        obj->objectFlags |
        (OBJECT_OBJFLAG_UPDATE_DISABLED | OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    ObjGroup_AddObject((int)obj, SIDEREPEL_OBJGROUP);
    if (obj->anim.hitReactState != NULL)
    {
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, (s16)(placement->radius >> 3));
    }
}
