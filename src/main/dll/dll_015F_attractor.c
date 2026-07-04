/*
 * attractor (DLL 0x15F) - a placement-driven object that joins object
 * group 0x1e and, on demand, reports either itself or a heading toward
 * the player. Its placement record carries a setup byte (0x18, copied
 * <<8 into anim.rotX at init), a mode byte (0x19) and a scale halfword
 * (0x1a).
 *
 * attractor_func0B is the queried accessor: mode 1 returns the object;
 * mode 2 additionally faces the object at the player (atan2 of the
 * player-relative xz delta, biased by 0x8000) before returning it;
 * other modes report nothing.
 *
 * attractor_setScale exposes the placement scale halfword when the
 * mode byte is set. The object has no per-frame think/hit work
 * (update/hitDetect are empty) and renders through objRenderFn_8003b8f4
 * at a fixed scale (lbl_803E43D0).
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"

#define ATTRACTOR_OBJ_GROUP 0x1e

/* placement mode byte (0x19) - selects what attractor_func0B reports */
#define ATTRACTOR_MODE_NONE        0 /* report nothing */
#define ATTRACTOR_MODE_RETURN_SELF 1 /* return the object */
#define ATTRACTOR_MODE_FACE_PLAYER 2 /* face player, then return the object */

typedef struct AttractorMapData
{
    ObjPlacement base;
    s8 setupByte; /* 0x18: -> anim.rotX << 8 */
    s8 mode;      /* 0x19 */
    s16 scale;    /* 0x1a */
} AttractorMapData;

STATIC_ASSERT(offsetof(AttractorMapData, setupByte) == 0x18);
STATIC_ASSERT(offsetof(AttractorMapData, mode) == 0x19);
STATIC_ASSERT(offsetof(AttractorMapData, scale) == 0x1a);

extern f32 lbl_803E43D0;

void attractor_hitDetect(void)
{
}

void attractor_update(void)
{
}

void attractor_release(void)
{
}

void attractor_initialise(void)
{
}

int attractor_getExtraSize(void) { return 0x0; }
int attractor_getObjectTypeId(void) { return 0x0; }

void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderFn_8003b8f4(lbl_803E43D0);
}

void attractor_free(int obj) { ObjGroup_RemoveObject(obj, ATTRACTOR_OBJ_GROUP); }

int attractor_setScale(int* obj)
{
    AttractorMapData* p = (AttractorMapData*)((int**)obj)[0x4c / 4];
    if (p->mode != ATTRACTOR_MODE_NONE)
    {
        return p->scale;
    }
    return 0;
}

void attractor_init(GameObject* obj, AttractorMapData* data)
{
    ObjGroup_AddObject((u32)obj, ATTRACTOR_OBJ_GROUP);
    {
        s8 setup = data->setupByte;
        s16 rotX = setup << 8;
        obj->anim.rotX = rotX;
    }
}

void attractor_func0B(GameObject* obj, void** out)
{
    void* result = NULL;
    s8 mode = ((AttractorMapData*)obj->anim.placementData)->mode;
    switch (mode)
    {
    case ATTRACTOR_MODE_NONE:
        break;
    case ATTRACTOR_MODE_RETURN_SELF:
        result = obj;
        break;
    case ATTRACTOR_MODE_FACE_PLAYER:
    {
        GameObject* player = (GameObject*)Obj_GetPlayerObject();
        int angle = atan2i(
            (int)(player->anim.localPosX - obj->anim.localPosX),
            (int)(player->anim.localPosZ - obj->anim.localPosZ));
        obj->anim.rotX = (s16)(angle + 0x8000);
        result = obj;
        break;
    }
    }
    *out = result;
}
