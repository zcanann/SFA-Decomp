#include "main/dll/dll_B6.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"

extern void *Obj_GetPlayerObject(void);
extern int objAnimFn_80296328(void);
extern int fn_80295C24(void *player);
extern void voxmaps_worldToGrid(f32 *world, int *grid);
extern u8 voxmaps_traceLine(int *from, int *to, int *out, u8 *occOut, int e);
extern f32 PSVECMag(void *vec);
extern float sqrtf(float x);

extern f32 lbl_803E1644;
extern f32 lbl_803E1648;
extern f32 lbl_803E1658;

CamcontrolTargetObject *camcontrol_findBestTarget(CamcontrolCameraState *cameraState, ObjAnimComponent *focus)
{
    int objIndex;
    int objCount;
    u8 out2[4];
    f32 v1[3];
    f32 v2[3];
    int g1[3];
    int g2[3];
    int out1[3];
    GameObject *targets[8];
    f32 dist[8];
    GameObject **ptr;
    int bestPri;
    GameObject *obj;
    int idx;
    int count;
    GameObject *player;
    u8 canTarget;
    ObjHitVolumeRuntimeBounds *data;
    ObjHitVolumeRuntimeBounds *entry;
    ObjDefHitVolume *row;
    ObjHitVolumeRuntimeTransform *src;
    ObjHitVolumeRuntimeTransform *transform;
    GameObject *best;
    int i;
    int k;
    int ok;
    f32 dx, dz, dy, distsq, range;
    f32 *pd;
    GameObject **pa;

    (void)cameraState;
    bestPri = -1;
    count = 0;
    player = Obj_GetPlayerObject();
    if (player == NULL || focus == NULL || gCamcontrolActiveActionId == 0x44 ||
        objAnimFn_80296328() == 0) {
        return NULL;
    }
    ptr = (GameObject **)ObjList_GetObjects(&objIndex, &objCount);
    idx = objIndex;
    ptr += idx;
    for (; idx < objCount; ptr++, idx++) {
        obj = *ptr;
        data = obj->anim.hitVolumeBounds;
        if (data == NULL
           || obj->anim.alpha != 0xff
           || (*(u8 *)&obj->anim.resetHitboxMode & 0x28)
           || (!(obj->objectFlags & 0x800) && !(obj->anim.modelInstance->flags & 1))
           || (obj->anim.flags & OBJANIM_FLAG_HIDDEN)
           || (obj->objectFlags & 0x40)
           || (gCamcontrolTargetClassMask & ((ok = 1) << (data[obj->unkE4].flags & 0xf))) == 0) {
            ok = 0;
        }
        if (ok == 0) {
            continue;
        }
        if ((int)obj->anim.modelInstance->hitVolumes[obj->unkE4].priority < bestPri) {
            continue;
        }
        transform = &obj->anim.hitVolumeTransforms[obj->unkE4];
        if ((*(u8 *)&obj->anim.resetHitboxMode & 0x80) || (data[obj->unkE4].flags & 0x80)) {
            dy = gCamcontrolNormalizedMin;
        } else {
            dy = focus->worldPosY - transform->centerY;
        }
        if (dy <= lbl_803E1644) {
            continue;
        }
        if (dy >= lbl_803E1648) {
            continue;
        }
        dx = focus->worldPosX - transform->centerX;
        dz = focus->worldPosZ - transform->centerZ;
        distsq = dz * dz + dx * dx;
        entry = &data[obj->unkE4];
        range = (f32)(int)(entry->bounds[2] << 2);
        if (distsq >= range * range) {
            continue;
        }
        canTarget = 1;
        if ((entry->flags & 0xf) == 2 && fn_80295C24(player) != 0) {
            canTarget = 0;
        }
        if (canTarget == 0) {
            continue;
        }
        bestPri = obj->anim.modelInstance->hitVolumes[obj->unkE4].priority;
        i = 0;
        pa = targets;
        while (i < count
            && (int)(*pa)->anim.modelInstance->hitVolumes[(*pa)->unkE4].priority > bestPri) {
            pa++;
            i++;
        }
        pd = dist + i;
        pa = targets + i;
        while (i < count && *pd < distsq
            && bestPri == (int)(*pa)->anim.modelInstance->hitVolumes[(*pa)->unkE4].priority) {
            pd++;
            pa++;
            i++;
        }
        for (k = count; k > i; k--) {
            dist[k] = dist[k - 1];
            targets[k] = targets[k - 1];
        }
        dist[i] = distsq;
        targets[i] = obj;
        count++;
        if (count == 8) {
            break;
        }
    }
    if (count > 0) {
        best = targets[0];
        row = &best->anim.modelInstance->hitVolumes[best->unkE4];
        if (row->flags & 0x20) {
            v1[0] = focus->worldPosX;
            v1[1] = lbl_803E1648 + focus->worldPosY;
            v1[2] = focus->worldPosZ;
            src = &best->anim.hitVolumeTransforms[best->unkE4];
            v2[0] = src->jointX;
            v2[1] = src->jointY;
            v2[2] = src->jointZ;
            voxmaps_worldToGrid(v1, g1);
            voxmaps_worldToGrid(v2, g2);
            if (voxmaps_traceLine(g1, g2, out1, out2, 0) == 0 && out2[0] != 1) {
                return NULL;
            }
        }
        return (CamcontrolTargetObject *)targets[0];
    }
    return NULL;
}

void camcontrol_updateMoveAverage(CamcontrolCameraState *cameraState, ObjAnimComponent *focus) {
    f32 mag;
    f32 minMove;
    cameraState->focusMoveHistory[0] = cameraState->focusMoveHistory[1];
    cameraState->focusMoveHistory[1] = cameraState->focusMoveHistory[2];
    cameraState->focusMoveHistory[2] = cameraState->focusMoveHistory[3];
    cameraState->focusMoveHistory[3] = cameraState->focusMoveHistory[4];
    mag = PSVECMag(&focus->velocityX);
    if (mag > gCamcontrolNormalizedMin) {
        mag = sqrtf(mag);
    }
    cameraState->focusMoveHistory[4] = mag;
    minMove = gCamcontrolNormalizedMin;
    cameraState->focusMoveAverage = minMove;
    cameraState->focusMoveAverage += cameraState->focusMoveHistory[0];
    cameraState->focusMoveAverage += cameraState->focusMoveHistory[1];
    cameraState->focusMoveAverage += cameraState->focusMoveHistory[2];
    cameraState->focusMoveAverage += cameraState->focusMoveHistory[3];
    cameraState->focusMoveAverage += cameraState->focusMoveHistory[4];
    cameraState->focusMoveAverage *= lbl_803E1658;
    if (cameraState->focusMoveAverage < minMove) {
        cameraState->focusMoveAverage = -cameraState->focusMoveAverage;
    }
}
