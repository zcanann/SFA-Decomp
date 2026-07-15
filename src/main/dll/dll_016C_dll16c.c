/*
 * dll_16C - map-event boulder proxy object (object type id 0x3, extra size 0x24).
 *
 * Drives a "boulder" GameObject that mirrors a separately-spawned map-event
 * sub-object: on update it relinks to a member of object group 10 chosen by
 * seqId (364 normally, 367 for seqId 368), advances its 0x100 move, and fades
 * its render opacity by the player's distance to the linked object. Render is
 * gated by GameBit 0x3A2 / seqId 883 and suppressed when GameBit 110 is set
 * unless GameBit 898 is also set. The sequence callback (dll_16C_SeqFn) spawns
 * /frees a child object from a small id table keyed by
 * subObjIndex, and forwards trigger commands (1/2/3) to the linked object's
 * vtable.
 */
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/object_render_legacy.h"
#include "main/rcp_dolphin_api.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/shader_api.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/dll/dll_016C_dll16c.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/object_descriptor.h"

typedef struct Dll16CPlacement
{
    u8 pad00[0x27];
    s8 subObjIndex;
} Dll16CPlacement;

/*
 * Per-object extra state for the dll_16C map-event boulder proxy
 * (dll_16C_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

/* seqId variant whose render is gated by GameBit 0x3A2 (docblock: "Render is gated by GameBit 0x3A2 / seqId 883") */
#define DLL16C_RENDER_GATE_SEQID 883

typedef struct Dll16CChildObjectIdTable
{
    s16 ids[5];
} Dll16CChildObjectIdTable;

STATIC_ASSERT(sizeof(Dll16CChildObjectIdTable) == 0xA);

const Dll16CChildObjectIdTable lbl_802C2308 = {{0x23, 0x69, 0x33, 0x64, 0x1D}};
extern f32 lbl_803E4748;
extern f32 lbl_803E474C;
extern f32 lbl_803E4758;
extern f32 lbl_803E475C;
extern f32 lbl_803E4760;
extern f32 lbl_803E4764;

void dll_16C_release(void)
{
}

void dll_16C_initialise(void)
{
}

int dll_16C_getExtraSize(void)
{
    return 0x24;
}
int dll_16C_getObjectTypeId(void)
{
    return 0x3;
}

void dll_16C_free(GameObject* obj)
{
    GameObject* child = obj->childObjs[0];
    if (child != NULL)
        Obj_FreeObject(child);
}

#pragma scheduling off
#pragma peephole off
void dll_16C_hitDetect(GameObject* obj)
{
    Dll16CState* extra = (obj)->extra;
    GameObject* p = extra->linkedObj;
    if (p != NULL)
    {
        if ((*(int (**)(void*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
        {
            dll_16C_syncSubObjectTransform(obj, extra->linkedObj, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}

void dll_16C_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    Dll16CState* extra;
    GameObject* linkedObj;
    int hit;

    if (obj->anim.seqId != DLL16C_RENDER_GATE_SEQID)
    {
        if (mainGetBit(GAMEBIT_IM_TrickyRelated006E) != 0)
        {
            if (mainGetBit(GAMEBIT_IM_HutRelated0382) == 0)
                return;
        }
        extra = obj->extra;
        linkedObj = extra->linkedObj;
        hit = 0;
        if (linkedObj != NULL)
        {
            if ((*(int (**)(GameObject*))(**(int**)((char*)linkedObj + 0x68) + 0x38))(linkedObj) == 2)
            {
                hit = 1;
            }
        }
        if (hit != 0)
        {
            obj->anim.flags |= 8;
            visible = objUpdateOpacity(linkedObj);
            dll_16C_syncSubObjectTransform(obj, linkedObj, p1, p2, p3, p4, visible, extra->opacity, 1);
        }
        else
        {
            obj->anim.flags &= ~8;
        }
        if (visible != 0 && extra->opacity != 0)
        {
            u8 saved = *(u8*)((char*)obj + 0x37);
            if (hit != 0)
            {
                *(u8*)((char*)obj + 0x37) = extra->opacity;
            }
            ((void (*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4,
                                                                                        lbl_803E4758);
            ObjPath_GetPointWorldPosition(obj, 1, &extra->pathPointX, &extra->pathPointY, &extra->pathPointZ, 0);
            *(u8*)((char*)obj + 0x37) = saved;
        }
    }
    else
    {
        ((void (*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4,
                                                                                    lbl_803E4758);
    }
}

void dll_16C_init(GameObject* obj, void* placement)
{
    Dll16CState* extra;
    obj->animEventCallback = dll_16C_SeqFn;
    if (obj->anim.modelState != NULL)
    {
        obj->anim.modelState->flags |= 0x4000;
        obj->anim.modelState->shadowTintA = 100;
        obj->anim.modelState->shadowTintB = 150;
    }
    extra = obj->extra;
    extra->linkedObj = NULL;
    extra->subObjIndex = ((Dll16CPlacement*)placement)->subObjIndex;
    extra->opacity = 0xff;
}

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
int dll_16C_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GameObject* linkedObj;
    Dll16CState* extra = obj->extra;
    Dll16CChildObjectIdTable childObjectIds;

    extra->opacity = 0xff;
    linkedObj = extra->linkedObj;
    if (animUpdate->triggerCommand == 3)
    {
        extra->subObjIndex = -1;
        animUpdate->triggerCommand = 0;
    }
    childObjectIds = lbl_802C2308;

    if (extra->subObjIndex != extra->subObjIndexApplied)
    {
        if (obj->childObjs[0] != NULL)
        {
            Obj_FreeObject((GameObject*)obj->childObjs[0]);
            *(int*)&obj->childObjs[0] = 0;
            obj->childCount = 0;
        }
        if (Obj_IsLoadingLocked())
        {
            s8 idx = extra->subObjIndex;
            if (idx > 0)
            {
                *(int*)&obj->childObjs[0] =
                    (int)Obj_SetupObject(Obj_AllocObjectSetup(24, childObjectIds.ids[idx - 1]), 4, -1, -1, obj->anim.parent);
                obj->childCount = 1;
            }
            extra->subObjIndexApplied = extra->subObjIndex;
        }
        else
        {
            extra->subObjIndexApplied = 0;
        }
    }

    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;

    if (linkedObj != NULL && animUpdate->triggerCommand == 2)
    {
        extra->unk04 = lbl_803E4758;
        extra->snapX = extra->pathPointX;
        extra->snapY = extra->pathPointY;
        extra->snapZ = extra->pathPointZ;
        (*(void (**)(GameObject*, int))(**(int**)((char*)linkedObj + 0x68) + 0x3c))(linkedObj, 2);
        ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 1);
        if (obj->anim.modelState != NULL)
        {
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        animUpdate->hitVolumePair &= ~4;
        animUpdate->triggerCommand = 0;
    }
    else if (linkedObj != NULL && animUpdate->triggerCommand == 1)
    {
        (*(void (**)(GameObject*, int))(**(int**)((char*)linkedObj + 0x68) + 0x3c))(linkedObj, 0);
        animUpdate->triggerCommand = 0;
    }

    if (linkedObj != NULL)
    {
        if ((*(int (**)(GameObject*))(**(int**)((char*)linkedObj + 0x68) + 0x38))(linkedObj) == 2)
        {
            animUpdate->hitVolumePair &= ~3;
        }
    }
    return 0;
}

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
void dll_16C_syncSubObjectTransform(GameObject* dst, GameObject* src, int p1, int p2, int p3, int p4, int visible,
                                    int opacity, int reissueMove)
{
    if (reissueMove != 0 && (s8)visible != 0 && opacity > 0)
    {
        u8 saved = *(u8*)((char*)src + 0x37);
        *(u8*)((char*)src + 0x37) = opacity;
        (*(void (**)(GameObject*, int, int, int, int, int))(**(int**)&src->anim.dll + 0x10))(src, p1, p2, p3, p4, -1);
        *(u8*)((char*)src + 0x37) = saved;
    }
    dst->anim.previousWorldPosX = dst->anim.worldPosX;
    dst->anim.previousWorldPosY = dst->anim.worldPosY;
    dst->anim.previousWorldPosZ = dst->anim.worldPosZ;
    dst->anim.previousLocalPosX = dst->anim.localPosX;
    dst->anim.previousLocalPosY = dst->anim.localPosY;
    dst->anim.previousLocalPosZ = dst->anim.localPosZ;
    {
        f32 x, y, z;
        (*(void (**)(GameObject*, f32*, f32*, f32*))(**(int**)&src->anim.dll + 0x28))(src, &x, &y, &z);
        dst->anim.localPosX = x;
        dst->anim.localPosY = y;
        dst->anim.localPosZ = z;
    }
    dst->anim.rotX = src->anim.rotX;
    dst->anim.rotY = src->anim.rotY;
    dst->anim.rotZ = src->anim.rotZ;
    dst->anim.worldPosX = dst->anim.localPosX;
    dst->anim.worldPosY = dst->anim.localPosY;
    dst->anim.worldPosZ = dst->anim.localPosZ;
    dst->anim.velocityX = src->anim.velocityX;
    dst->anim.velocityY = src->anim.velocityY;
    dst->anim.velocityZ = src->anim.velocityZ;
}

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
void dll_16C_update(GameObject* obj)
{
    Dll16CState* extra = obj->extra;
    Dll16CChildObjectIdTable childObjectIds;

    childObjectIds = lbl_802C2308;
    if (extra->subObjIndex != extra->subObjIndexApplied)
    {
        if (obj->childObjs[0] != NULL)
        {
            Obj_FreeObject((GameObject*)obj->childObjs[0]);
            *(int*)&obj->childObjs[0] = 0;
            obj->childCount = 0;
        }
        if (Obj_IsLoadingLocked())
        {
            s8 idx = extra->subObjIndex;
            if (idx > 0)
            {
                *(int*)&obj->childObjs[0] =
                    (int)Obj_SetupObject(Obj_AllocObjectSetup(24, childObjectIds.ids[idx - 1]), 4, -1, -1, obj->anim.parent);
                obj->childCount = 1;
            }
            extra->subObjIndexApplied = extra->subObjIndex;
        }
        else
        {
            extra->subObjIndexApplied = 0;
        }
    }

    if (extra->linkedObj == NULL)
    {
        GameObject** objs;
        int count;
        int i;
        int sel;
        objs = (GameObject**)ObjGroup_GetObjects(10, &count);
        switch (obj->anim.seqId)
        {
        case 365:
        case 883:
        default:
            sel = 364;
            break;
        case 368:
            sel = 367;
            break;
        }
        for (i = 0; i < count; i++)
        {
            if (sel == objs[i]->anim.seqId)
            {
                extra->linkedObj = objs[i];
                i = count;
            }
        }
    }

    if (obj->anim.seqId == DLL16C_RENDER_GATE_SEQID || mainGetBit(GAMEBIT_IM_BikeRelated03A2) != 0)
    {
        GameObject* sub = extra->linkedObj;
        f32 b;
        f32 blend;
        f32 a;
        if (obj->anim.currentMove != 0x100)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 0);
        }
        (*(void (**)(GameObject*, f32*))(**(int**)((char*)sub + 0x68) + 0x44))(sub, &blend);
        blend = lbl_803E474C;
        (*(void (**)(GameObject*, f32*, f32*))(**(int**)((char*)sub + 0x68) + 0x40))(sub, &a, &b);
        ObjAnim_AdvanceCurrentMove((int)obj, blend, (f32)(u32)framesThisStep, NULL);
        if (extra->linkedObj != NULL)
        {
            f32 fade;
            GameObject* player = Obj_GetPlayerObject();
            fade = Vec_distance(&extra->linkedObj->anim.worldPosX, &player->anim.worldPosX);
            fade = (fade - lbl_803E475C) / lbl_803E4760;
            if (fade < lbl_803E4748)
            {
                fade = lbl_803E4748;
            }
            else if (fade > lbl_803E4758)
            {
                fade = lbl_803E4758;
            }
            fade = lbl_803E4758 - fade;
            extra->opacity = lbl_803E4764 * fade;
            if (obj->anim.modelState != NULL)
            {
                obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
        else
        {
            extra->opacity = 0xff;
            if (obj->anim.modelState != NULL)
            {
                obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
    }
}

ObjectDescriptor lbl_80323740 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_16C_initialise,
    (ObjectDescriptorCallback)dll_16C_release,
    0,
    (ObjectDescriptorCallback)dll_16C_init,
    (ObjectDescriptorCallback)dll_16C_update,
    (ObjectDescriptorCallback)dll_16C_hitDetect,
    (ObjectDescriptorCallback)dll_16C_render,
    (ObjectDescriptorCallback)dll_16C_free,
    (ObjectDescriptorCallback)dll_16C_getObjectTypeId,
    dll_16C_getExtraSize,
};
