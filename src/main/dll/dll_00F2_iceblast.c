/*
 * iceblast (DLL 0xF2) - a path-following ice projectile in the
 * pushable/transporter object family (shares the dll_00EF pushable
 * descriptor; sibling of flameblast/invhit/warppoint).
 *
 * The blast rides the player's first child path object: iceblast_update
 * copies that path object's heading into the blast's rotation, runs a
 * per-frame countdown timer and, each time the timer expires, re-seeds
 * the launch position from the rotated heading and the path's world
 * point, then integrates localPos by velocity*timeDelta every frame.
 * The placement's useAltHitVolume byte selects the hit-volume slot (3 when set,
 * else 1). The 4-byte extra holds only the countdown timer.
 */
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/dll/vecrotatezxyarg_struct.h"

typedef struct IceblastPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 useAltHitVolume;
    s16 initialTimer;
    u8 pad1C[4];
} IceblastPlacement;

extern void vecRotateZXY(void* in, void* out);
extern f32 timeDelta;

int iceblast_getExtraSize(void)
{
    return 0x4;
}

int iceblast_getObjectTypeId(void)
{
    return 0x0;
}

void iceblast_free(void)
{
}

void iceblast_render(int* obj, int p1, int p2, int p3, int p4)
{
    objRenderFn_8003b8f4((int)obj, p1, p2, p3, p4, 1.0f);
}

void iceblast_hitDetect(void)
{
}

void iceblast_update(GameObject* obj)
{
    GameObject* path;
    GameObject* player = Obj_GetPlayerObject();
    f32* timer = obj->extra;
    IceblastPlacement* def = (IceblastPlacement*)obj->anim.placementData;
    VecRotateZXYArg vec;
    if (player != NULL && (path = player->childObjs[0]) != NULL)
    {
        obj->anim.rotZ = path->anim.rotZ;
        obj->anim.rotY = path->anim.rotY;
        obj->anim.rotX = path->anim.rotX;
    }
    else
    {
        return;
    }
    ObjHits_SetHitVolumeSlot((u32)obj, 0x10, def->useAltHitVolume != 0 ? 3 : 1, 0);

    timer[0] -= timeDelta;
    if (timer[0] <= 0.0f)
    {
        timer[0] += 24.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityZ = 0.0f;
        obj->anim.velocityY = -3.0f;
        vec.pos[1] = 0.0f;
        vec.pos[2] = 0.0f;
        vec.pos[3] = 0.0f;
        vec.pos[0] = 1.0f;
        vec.dir[2] = path->anim.rotZ;
        vec.dir[1] = path->anim.rotY;
        vec.dir[0] = path->anim.rotX;
        vecRotateZXY(&vec, &obj->anim.velocityX);
        ObjPath_GetPointWorldPosition((int)path, 0, &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ,
                                      0);
        ObjHits_EnableObject((u32)obj);
    }
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
    obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
}

void iceblast_init(GameObject* obj, IceblastPlacement* def)
{
    *(f32*)obj->extra = def->initialTimer;
    ObjHits_SetTargetMask((int)obj, 1);
}

void iceblast_release(void)
{
}

void iceblast_initialise(void)
{
}
