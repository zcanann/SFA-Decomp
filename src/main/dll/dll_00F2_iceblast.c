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
 * else 1). The extra block is an IceblastState (just the countdown timer).
 */
#include "main/dll/dll_00F2_iceblast.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/frame_timing.h"
#include "main/dll/vecrotatezxy.h"

STATIC_ASSERT(offsetof(IceblastPlacement, useAltHitVolume) == 0x19);
STATIC_ASSERT(offsetof(IceblastPlacement, initialTimer) == 0x1a);
STATIC_ASSERT(sizeof(IceblastState) == 0x4);

int iceblast_getExtraSize(void)
{
    return sizeof(IceblastState);
}

int iceblast_getObjectTypeId(void)
{
    return 0x0;
}

void iceblast_free(void)
{
}

void iceblast_render(GameObject* obj, int p1, int p2, int p3, int p4)
{
    objRenderModelAndHitVolumes((int)obj, p1, p2, p3, p4, 1.0f);
}

void iceblast_hitDetect(void)
{
}

void iceblast_update(GameObject* obj)
{
    GameObject* path;
    GameObject* player = Obj_GetPlayerObject();
    IceblastState* state = obj->extra;
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

    state->timer -= timeDelta;
    if (state->timer <= 0.0f)
    {
        state->timer += 24.0f;
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
    IceblastState* state = obj->extra;
    state->timer = def->initialTimer;
    ObjHits_SetTargetMask((int)obj, 1);
}

void iceblast_release(void)
{
}

void iceblast_initialise(void)
{
}
