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
#include "main/objlib.h"
#include "main/obj_placement.h"
#include "main/dll/dll_00EB_siderepel.h"

/* object group: side-repel object */
#define SIDEREPEL_OBJGROUP 0x40

#define SIDEREPEL_OBJFLAG_UPDATE_DISABLED    0x8000
#define SIDEREPEL_OBJFLAG_HIDDEN             0x4000
#define SIDEREPEL_OBJFLAG_HITDETECT_DISABLED 0x2000

int siderepel_getExtraSize(void)
{
    return 0x1;
}

void siderepel_free(int obj)
{
    ObjGroup_RemoveObject(obj, SIDEREPEL_OBJGROUP);
}

void siderepel_init(int obj, int placement)
{
    ((GameObject*)obj)->objectFlags =
        ((GameObject*)obj)->objectFlags |
        (SIDEREPEL_OBJFLAG_UPDATE_DISABLED | SIDEREPEL_OBJFLAG_HIDDEN | SIDEREPEL_OBJFLAG_HITDETECT_DISABLED);
    ObjGroup_AddObject(obj, SIDEREPEL_OBJGROUP);
    if (((GameObject*)obj)->anim.hitReactState != NULL)
    {
        ObjHitbox_SetSphereRadius(obj, (s16)(((SideRepelPlacement*)placement)->radius >> 3));
    }
}
