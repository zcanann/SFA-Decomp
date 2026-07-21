/*
 * staypoint (DLL 0x0102) - a "stay here" marker that drives the player's
 * Tricky (the fox companion) to hold position at this object.
 *
 * StayPoint_init marks the object with the 0x4000 object flag.
 *
 * StayPoint_update arms the disable bit each frame, then - while the
 * placement's required game bit is satisfied (-1 = always) - tests whether
 * this is the stay point Tricky is currently assigned to (trickyGetStayPoint).
 * If it is and Tricky is within range (squared distance < lbl_803E38A8) it
 * sets the placement's active game bit and bails. Otherwise it clears the
 * active bit, sets the hit-volume priority from whether a menu item is
 * selected, clears the disable bit, re-runs the object render hook, and -
 * if the player is within range - issues the stay command to Tricky
 * through Tricky's object interface.
 *
 * The descriptor follows the implementation below.
 */
#include "main/game_object.h"
#include "main/objprint_render_api.h"
#include "main/object.h"
#include "main/gamebits.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/dll_0102_staypoint.h"
#include "main/vecmath_distance_api.h"

typedef void (*StayPointCommandCallback)(GameObject* tricky, GameObject* stayPoint, int enabled, int mode);

typedef struct StayPointTrickyInterface
{
    void* callbacks[10];
    StayPointCommandCallback commandStay;
} StayPointTrickyInterface;

STATIC_ASSERT(offsetof(StayPointTrickyInterface, commandStay) == 0x28);

/* hit-volume priority when a cMenu item is / isn't selected. */
#define STAYPOINT_PRIORITY_MENU 0x10

extern f32 lbl_803E38A8; /* stay-point engage radius, squared */

void StayPoint_update(GameObject* obj)
{
    StayPointPlacement* placement;
    GameObject* tricky;
    int isCurrentStayPoint;

    placement = (StayPointPlacement*)obj->anim.placementData;
    tricky = getTrickyObject();
    *(u8*)&obj->anim.resetHitboxMode =
        (u8)(*(u8*)&obj->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    if (tricky != NULL)
    {
        isCurrentStayPoint = ((int)obj - (int)trickyGetStayPoint(tricky) == 0);
        if (isCurrentStayPoint == 0 && placement->activeGameBit != -1)
        {
            mainSetBits(placement->activeGameBit, 0);
        }
        if (placement->requiredGameBit == -1 || mainGetBit(placement->requiredGameBit) != 0)
        {
            if (isCurrentStayPoint != 0 &&
                vec3f_distanceSquared(&obj->anim.worldPosX, &tricky->anim.worldPosX) < lbl_803E38A8)
            {
                if (placement->activeGameBit != -1)
                {
                    mainSetBits(placement->activeGameBit, 1);
                }
                return;
            }
            if (cMenuGetSelectedItem() == -1)
            {
                obj->anim.modelInstance->hitVolumes[0].priority = 0;
            }
            else
            {
                obj->anim.modelInstance->hitVolumes[0].priority = STAYPOINT_PRIORITY_MENU;
            }
            *(u8*)&obj->anim.resetHitboxMode =
                (u8)(*(u8*)&obj->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
            if (((obj->anim.modelInstance->flags & 1) != 0) && obj->anim.hitVolumeTransforms != NULL)
            {
                objRenderFn_80041018(obj);
            }
            if ((*(u8*)&obj->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                ((StayPointTrickyInterface*)*tricky->anim.dll)->commandStay(tricky, obj, 1, 3);
            }
        }
    }
}

void StayPoint_init(GameObject* obj)
{
    u32 flags;
    flags = obj->objectFlags;
    flags |= OBJECT_OBJFLAG_HIDDEN;
    obj->objectFlags = flags;
}

ObjectDescriptor gStayPointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};
