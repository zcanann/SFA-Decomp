/*
 * dll_b6 - camera-control lock-on target selection helpers.
 *
 * Companion code to the CAM camcontrol DLL (dll_0001_camcontrol): the two
 * functions here are called from there.
 *
 * camcontrol_findBestTarget scans the live object list for the best lock-on
 * target relative to the camera focus: it rejects hidden/invisible/flagged
 * objects, keeps only hit volumes whose class is enabled in
 * gCamcontrolTargetClassMask, filters by a vertical band and a squared planar
 * range derived from the volume's bounds, then inserts survivors into a
 * priority/distance-sorted list (highest priority first, nearest first within a
 * priority). The chosen target's line of sight is optionally validated against
 * the voxel map (voxmaps_traceLine).
 *
 * camcontrol_updateMoveAverage maintains a 5-frame rolling average of the focus
 * object's speed, used to damp camera follow.
 */
#include "main/dll/dll_B6.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/gameplay_runtime.h"

#define DLLB6_OBJFLAG_RENDERED 0x800
#define DLLB6_OBJFLAG_FREED 0x40
extern int objAnimFn_80296328(void);
extern int fn_80295C24(void *player);
/* voxel map line-of-sight (engine); int-pointer spellings are required for this TU's match
   (canonical engine_shared.h uses s16/VoxPos pointers and u8 - do not narrow these here) */
extern void voxmaps_worldToGrid(f32 *world, int *grid);
extern u8 voxmaps_traceLine(int *from, int *to, int *out, u8 *occOut, int e);
extern f32 PSVECMag(void *vec);
extern float sqrtf(float x);
extern f32 lbl_803E1644; /* vertical band lower bound */
extern f32 lbl_803E1648; /* vertical band upper bound; also reused as the camera height offset for the LOS ray origin */
extern f32 lbl_803E1658; /* 1/5 move-average weight */

static inline int camcontrol_isTargetCandidate(GameObject *obj, ObjHitVolumeRuntimeBounds *data)
{
    int accept;
    if (data != NULL
       && obj->anim.alpha == 0xff
       && !(*(u8 *)&obj->anim.resetHitboxMode & 0x28)
       && ((obj->objectFlags & DLLB6_OBJFLAG_RENDERED) || (obj->anim.modelInstance->flags & 1))
       && !(obj->anim.flags & OBJANIM_FLAG_HIDDEN)
       && !(obj->objectFlags & DLLB6_OBJFLAG_FREED)
       && (gCamcontrolTargetClassMask & ((accept = 1) << (data[obj->hitVolumeIndex].flags & CAMCONTROL_TARGET_KIND_MASK))))
    {
        return accept;
    }
    return 0;
}

CamcontrolTargetObject *camcontrol_findBestTarget(CamcontrolCameraState *cameraState, ObjAnimComponent *focus)
{
    int objIndex;
    int objCount;
    u8 occOut[4];
    f32 worldFrom[3];
    f32 worldTo[3];
    int gridFrom[3];
    int gridTo[3];
    int traceOut[3];
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
    GameObject *best;
    int i;
    int k;
    int accept;
    f32 dx, dz, dy, distsq, range;
    f32 *pDist;
    GameObject **pTarget;

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
        accept = camcontrol_isTargetCandidate(obj, data);
        if (accept == 0) {
            continue;
        }
        if ((int)*(u8 *)&obj->anim.modelInstance->hitVolumes[obj->hitVolumeIndex].priority < bestPri) {
            continue;
        }
        if ((*(u8 *)&obj->anim.resetHitboxMode & 0x80) || (data[obj->hitVolumeIndex].flags & 0x80)) {
            dy = gCamcontrolNormalizedMin;
        } else {
            dy = focus->worldPosY - obj->anim.hitVolumeTransforms[obj->hitVolumeIndex].centerY;
        }
        if (!(dy > lbl_803E1644)) {
            continue;
        }
        if (!(dy < lbl_803E1648)) {
            continue;
        }
        dx = focus->worldPosX - obj->anim.hitVolumeTransforms[obj->hitVolumeIndex].centerX;
        dz = focus->worldPosZ - obj->anim.hitVolumeTransforms[obj->hitVolumeIndex].centerZ;
        distsq = dx * dx + dz * dz;
        entry = &data[obj->hitVolumeIndex];
        range = (f32)(int)(entry->bounds[2] << 2);
        if (!(distsq < range * range)) {
            continue;
        }
        canTarget = 1;
        if ((entry->flags & CAMCONTROL_TARGET_KIND_MASK) == CAMCONTROL_TARGET_KIND_A_BUTTON_HINT &&
            fn_80295C24(player) != 0) {
            canTarget = 0;
        }
        if (canTarget == 0) {
            continue;
        }
        bestPri = *(u8 *)&obj->anim.modelInstance->hitVolumes[obj->hitVolumeIndex].priority;
        i = 0;
        while (i < count
            && (int)*(u8 *)&targets[i]->anim.modelInstance->hitVolumes[targets[i]->hitVolumeIndex].priority > bestPri) {
            i++;
        }
        while (i < count && dist[i] < distsq
            && bestPri == (int)*(u8 *)&targets[i]->anim.modelInstance->hitVolumes[targets[i]->hitVolumeIndex].priority) {
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
        row = best->anim.modelInstance->hitVolumes;
        row += best->hitVolumeIndex;
        if (row->flags & 0x20) {
            worldFrom[0] = focus->worldPosX;
            worldFrom[1] = lbl_803E1648 + focus->worldPosY;
            worldFrom[2] = focus->worldPosZ;
            worldTo[0] = best->anim.hitVolumeTransforms[best->hitVolumeIndex].jointX;
            worldTo[1] = best->anim.hitVolumeTransforms[best->hitVolumeIndex].jointY;
            worldTo[2] = best->anim.hitVolumeTransforms[best->hitVolumeIndex].jointZ;
            voxmaps_worldToGrid(worldFrom, gridFrom);
            voxmaps_worldToGrid(worldTo, gridTo);
            if (voxmaps_traceLine(gridFrom, gridTo, traceOut, occOut, 0) == 0 && occOut[0] != 1) {
                return NULL;
            }
        }
        return (CamcontrolTargetObject *)targets[0];
    }
    return NULL;
}

void camcontrol_updateMoveAverage(CamcontrolCameraState *cameraState, ObjAnimComponent *focus)
{
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
