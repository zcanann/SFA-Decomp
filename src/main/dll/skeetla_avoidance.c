#include "main/dll/skeetla.h"
#include "main/game_object.h"
#include "main/obj_list.h"
#include "main/obj_group.h"
#include "main/objhits.h"
#include "main/objHitReact.h"
#include "main/object_api.h"

extern const f32 lbl_803E2484;

/* group owned by another DLL, queried here */
#define SIDEREPEL_OBJGROUP 0x40 /* DLL 0xEB siderepel */

void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint)
{
    int count;
    int startIndex;
    int objectCount;
    int i;
    void** objects;
    u8* obj;
    u8* def;
    ObjHitsPriorityState* hitState;
    u16 minRadius;

    objects = (void**)ObjGroup_GetObjects(SIDEREPEL_OBJGROUP, &count);
    for (i = 0; i < count; i++)
    {
        obj = objects[i];
        def = *(u8**)&((GameObject*)obj)->anim.placementData;
        trickyAdjustStepAroundPoint(start, end, guardPoint, &((GameObject*)obj)->anim.worldPosX,
                                    lbl_803E2484 * (f32)(u32) * (u16*)(def + 0x18),
                                    lbl_803E2484 * (f32)(u32) * (u16*)(def + 0x1a));
    }

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    for (i = startIndex; i < objectCount; i++)
    {
        obj = objects[i];
        def = *(u8**)&((GameObject*)obj)->anim.modelInstance;
        minRadius = *(u16*)(def + 0x84);
        if (minRadius != 0)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if ((hitState != NULL) && ((*(s16*)&hitState->flags & 1) != 0))
            {
                trickyAdjustStepAroundPoint(start, end, guardPoint, &((GameObject*)obj)->anim.worldPosX,
                                            lbl_803E2484 * (f32)(u32)minRadius,
                                            lbl_803E2484 * (f32)(u32) * (u16*)(def + 0x86));
            }
        }
    }
}
