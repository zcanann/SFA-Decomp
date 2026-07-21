/*
 * effectbox (DLL 0x00EE) - an oriented box trigger volume placed in a
 * level. Each frame EffectBox_update transforms a candidate object's
 * position into the box's local space (yaw/pitch from the placement) and,
 * if it lies inside the box extents, fires an action on that object.
 *
 * The placement's targetMode selects the candidate set: 0 = the player,
 * 1 = Tricky, 2 = every object in object group 5. The action depends on
 * the same mode (the player gets fn_80295918 with actionArg; group members get
 * their action callback). A non-negative placement game bit gates the
 * box: it only runs while the bit's value differs from gameBitValue.
 */
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/object.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/obj_group.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/dll/dll_00EE_effectbox.h"

#define EFFECTBOX_TARGET_OBJGROUP 5

#define EFFECTBOX_RENDER_SCALE 1.0f
#define EFFECTBOX_PI           3.1415927f
#define EFFECTBOX_ANGLE_SCALE  32768.0f
#define EFFECTBOX_ZERO         0.0f

typedef void (*EffectBoxActionCallback)(GameObject* obj, int actionArg);

typedef struct EffectBoxTargetInterface
{
    void* callbacks[10];
    EffectBoxActionCallback applyAction;
} EffectBoxTargetInterface;

STATIC_ASSERT(offsetof(EffectBoxTargetInterface, applyAction) == 0x28);

int EffectBox_getExtraSize(void)
{
    return 0x0;
}
int EffectBox_getObjectTypeId(void)
{
    return 0x0;
}

void EffectBox_free(GameObject* obj)
{
    fn_8002B758(obj);
}

void EffectBox_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, EFFECTBOX_RENDER_SCALE);
}

void EffectBox_hitDetect(void)
{
}

void EffectBox_update(GameObject* obj)
{
    GameObject** list;
    EffectboxPlacement* placement;
    GameObject* single;
    int count;
    int i;
    GameObject* other;
    f32 cosY;
    f32 sinY;
    f32 cosX;
    f32 sinX;
    f32 negExtX;
    f32 negExtZ;
    f32 extX;
    f32 extY;
    f32 extZ;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 proj;
    int gateGameBit;

    placement = (EffectboxPlacement*)obj->anim.placementData;
    gateGameBit = obj->userData2;
    if ((gateGameBit <= -1) || (placement->gameBitValue != mainGetBit(gateGameBit)))
    {
        cosY = mathCosf((EFFECTBOX_PI * (f32) - (placement->rotYaw << 8)) / EFFECTBOX_ANGLE_SCALE);
        sinY = mathSinf((EFFECTBOX_PI * (f32) - (placement->rotYaw << 8)) / EFFECTBOX_ANGLE_SCALE);
        cosX = mathCosf((EFFECTBOX_PI * (f32) - (placement->rotPitch << 8)) / EFFECTBOX_ANGLE_SCALE);
        sinX = mathSinf((EFFECTBOX_PI * (f32) - (placement->rotPitch << 8)) / EFFECTBOX_ANGLE_SCALE);
        extX = (f32)placement->extentX;
        extY = (f32)(placement->extentY << 1);
        extZ = (f32)placement->extentZ;
        switch (placement->targetMode)
        {
        case EFFECTBOX_TARGET_PLAYER:
            single = Obj_GetPlayerObject();
            if (single == NULL)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case EFFECTBOX_TARGET_TRICKY:
            single = getTrickyObject();
            if (single == NULL)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case EFFECTBOX_TARGET_GROUP:
            list = (GameObject**)ObjGroup_GetObjects(EFFECTBOX_TARGET_OBJGROUP, &count);
            if (list == NULL)
            {
                return;
            }
            break;
        }
        i = 0;
        negExtX = -extX;
        negExtZ = -extZ;
        for (; i < count; i++)
        {
            other = *list;
            dx = other->anim.localPosX;
            dy = other->anim.localPosY;
            dz = other->anim.localPosZ;
            dx = dx - obj->anim.localPosX;
            dy = dy - obj->anim.localPosY;
            dz = dz - obj->anim.localPosZ;
            proj = dx * cosY + dz * sinY;
            if ((proj > negExtX) && (proj < extX))
            {
                proj = (-dx) * sinY + dz * cosY;
                proj = (-dy) * sinX + proj * cosX;
                if ((proj > negExtZ) && (proj < extZ))
                {
                    proj = dy * cosX + proj * sinX;
                    if ((proj >= EFFECTBOX_ZERO) && (proj < extY))
                    {
                        switch (placement->targetMode)
                        {
                        case EFFECTBOX_TARGET_TRICKY:
                            break;
                        case EFFECTBOX_TARGET_PLAYER:
                            fn_80295918(other, 1, (f32)placement->actionArg);
                            break;
                        case EFFECTBOX_TARGET_GROUP:
                            ((EffectBoxTargetInterface*)*other->anim.dll)->applyAction(
                                other, placement->actionArg);
                            break;
                        }
                    }
                }
            }
            list++;
        }
    }
}

void EffectBox_init(GameObject* obj, EffectboxPlacement* placement)
{
    s16 gateGameBit;
    u32 flags;
    if (obj->userData1 == 0)
    {
        fn_8002B860(obj);
    }
    obj->userData1 = 1;
    gateGameBit = placement->gameBitIndex;
    if (gateGameBit > -1)
    {
        obj->userData2 = gateGameBit;
    }
    else
    {
        obj->userData2 = -1;
    }
    flags = (u32)obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = flags;
}

void EffectBox_release(void)
{
}

void EffectBox_initialise(void)
{
}

ObjectDescriptor gEffectBoxObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)EffectBox_initialise,
    (ObjectDescriptorCallback)EffectBox_release,
    0,
    (ObjectDescriptorCallback)EffectBox_init,
    (ObjectDescriptorCallback)EffectBox_update,
    (ObjectDescriptorCallback)EffectBox_hitDetect,
    (ObjectDescriptorCallback)EffectBox_render,
    (ObjectDescriptorCallback)EffectBox_free,
    (ObjectDescriptorCallback)EffectBox_getObjectTypeId,
    EffectBox_getExtraSize,
};
