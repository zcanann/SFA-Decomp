/* DLL 0x1DA - rolling-rock object (DIM2 / SnowHorn region). One placed
 * instance per object: render draws the rock model; init seeds the floor
 * height into extra[0] and lifts the rock up by a fixed amount; hitDetect
 * reacts to priority hit type 0xE (a fire/torch volume) by kicking the
 * rock's XZ velocity from the hit normal and playing the put-out-fire sfx;
 * update runs the rolling physics each frame (velocity damping that depends
 * on whether the rock is grounded, geometry-normal bounce, gravity fall,
 * landing on a contact object, and a floor clamp), then persists the
 * object's position. Re-split from a former multi-object TU. */
#include "main/audio/sfx_ids.h"
#include "main/object_render.h"
#include "main/dll/savegame_object_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/object_descriptor.h"

typedef struct Dll1DAState
{
    f32 floorHeight; /* 0x00: clamp floor, seeded at init */
    u8 grounded;     /* 0x04: rock is resting on a contact object */
    u8 unk5;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} Dll1DAState;

typedef struct
{
    int hit[7];
    f32 nx;
    f32 ny;
    f32 nz;
    int pad[8];
} RockHitInfo;


int dll_1DA_getExtraSize(void)
{
    return 0x8;
}
int dll_1DA_getObjectTypeId(void)
{
    return 0x0;
}

void dll_1DA_free(void)
{
}

void dll_1DA_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_1DA_hitDetect(GameObject* obj)
{

    void* hi;
    void* player;
    f32 k;
    int hit = ObjHits_GetPriorityHit(obj, (int*)&hi, NULL, NULL);
    if (hit == 0xE)
    {
        player = Obj_GetPlayerObject();
        (void)Vec_distance((float*)&(obj)->anim.worldPosX, (float*)((int)player + 0x18));
        (obj)->anim.velocityX = ((GameObject*)hi)->anim.velocityX * (k = 0.5f);
        (obj)->anim.velocityZ = ((GameObject*)hi)->anim.velocityZ * k;
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_birdymornin11_1f9);
    }
}

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */
void dll_1DA_update(int obj)
{
    int state;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 len;
    f32 k;
    f32 damping;
    f32 reflect;
    int hitCount;
    TrackGroundHit** floorList;
    int i;
    RockHitInfo out;

    state = *(int*)&((GameObject*)obj)->extra;
    if (((Dll1DAState*)state)->grounded != 0)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = 0.85f);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = 0.9f);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
    }
    if (((GameObject*)obj)->anim.velocityX < 0.1f && ((GameObject*)obj)->anim.velocityX > -0.1f &&
        ((GameObject*)obj)->anim.velocityZ < 0.1f &&
        ((GameObject*)obj)->anim.velocityZ > -0.1f)
    {
        ((GameObject*)obj)->anim.velocityX = (k = 0.0f);
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta, 0.0f,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    hitCount = objBboxFn_800640cc(&((GameObject*)obj)->anim.previousLocalPosX, (f32*)(obj + 0xc), 6.5f, 1,
                                  (TrackBBoxHit*)out.hit, (GameObject*)obj, 8, -1, 0xff, 0);
    if (hitCount != 0)
    {
        vx = -((GameObject*)obj)->anim.velocityX;
        vy = -((GameObject*)obj)->anim.velocityY;
        vz = -((GameObject*)obj)->anim.velocityZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (0.0f != len)
        {
            f32 s = 1.0f / len;
            vx = vx * s;
            vy = vy * s;
            vz = vz * s;
        }
        reflect = 2.0f * (vz * out.nz + (vx * out.nx + vy * out.ny));
        ((GameObject*)obj)->anim.velocityX = out.nx * reflect;
        ((GameObject*)obj)->anim.velocityY = out.ny * reflect;
        ((GameObject*)obj)->anim.velocityZ = out.nz * reflect;
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - vx;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - vy;
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - vz;
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (damping = 0.8f * len);
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (0.5f * len);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * damping;
    }
    ((GameObject*)obj)->anim.localPosY = -(0.2f * timeDelta - ((GameObject*)obj)->anim.localPosY);
    hitCount = hitDetectFn_80065e50((GameObject*)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ, &floorList, 0, 0x11);
    ((Dll1DAState*)state)->grounded = 0;
    i = 0;
    for (; hitCount > 0; hitCount--)
    {
        if (((GameObject*)obj)->anim.localPosY < 5.0f + floorList[i]->height)
        {
            ((GameObject*)obj)->anim.localPosY = floorList[i]->height;
            ObjHits_AddContactObject(floorList[i]->object, (GameObject*)obj);
            ((Dll1DAState*)state)->grounded = 1;
            break;
        }
        i++;
    }
    if (((GameObject*)obj)->anim.localPosY < *(f32*)state)
    {
        ((GameObject*)obj)->anim.localPosY = *(f32*)state;
    }
    saveGame_saveObjectPos((GameObject*)obj);
}

void dll_1DA_init(GameObject* obj)
{
    *(*(f32**)&obj->extra) = obj->anim.localPosY;
    obj->anim.localPosY += 1.0f;
}

void dll_1DA_release(void)
{
}

void dll_1DA_initialise(void)
{
}

ObjectDescriptor dll_1DA = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1DA_initialise,
    (ObjectDescriptorCallback)dll_1DA_release,
    0,
    (ObjectDescriptorCallback)dll_1DA_init,
    (ObjectDescriptorCallback)dll_1DA_update,
    (ObjectDescriptorCallback)dll_1DA_hitDetect,
    (ObjectDescriptorCallback)dll_1DA_render,
    (ObjectDescriptorCallback)dll_1DA_free,
    (ObjectDescriptorCallback)dll_1DA_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_1DA_getExtraSize,
};
