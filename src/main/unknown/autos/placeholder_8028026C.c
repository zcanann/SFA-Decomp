#include "ghidra_import.h"

typedef struct S3DEmitterCtrl {
    u8 controller;
    u8 pad01;
    u16 value;
} S3DEmitterCtrl;

typedef struct S3DEmitterCtrlList {
    u8 count;
    u8 pad01[3];
    S3DEmitterCtrl *entries;
} S3DEmitterCtrlList;

typedef struct SndSpatialEntryLite {
    u8 pad00[0x1c];
    s8 assignedVoice;
} SndSpatialEntryLite;

typedef struct Snd3DEmitterLite {
    u8 pad00[0x08];
    SndSpatialEntryLite *entry;
    S3DEmitterCtrlList *ctrlList;
    u32 flags;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 refX;
    f32 refY;
    f32 refZ;
    f32 maxDistance;
    f32 maxVolume;
    f32 minVolume;
    f32 distanceCurve;
    u32 handle;
    u32 groupKey;
    u16 fxId;
    u8 studio;
    u8 maxVoices;
    u16 retryCounter;
    u8 pad4a[0x4c - 0x4a];
    f32 age;
} Snd3DEmitterLite;

typedef struct SndSpatialListenerLite {
    struct SndSpatialListenerLite *next;
    u8 pad04[8];
    u32 flags;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 time;
    f32 refX;
    f32 refY;
    f32 refZ;
    f32 velX;
    f32 velY;
    f32 velZ;
    u8 pad38[0x50 - 0x38];
    f32 matrix[12];
    f32 rearRange;
    f32 frontRange;
    f32 panScale;
    f32 volumeScale;
} SndSpatialListenerLite;

typedef struct S3DActiveNode {
    struct S3DActiveNode *next;
    f32 distance;
    f32 arg1;
    f32 arg2;
    f32 arg3;
    f32 arg4;
    Snd3DEmitterLite *emitter;
} S3DActiveNode;

typedef struct S3DSortedNode {
    struct S3DSortedNode *next;
    f32 distance;
    Snd3DEmitterLite *emitter;
} S3DSortedNode;

typedef struct S3DMixGroup {
    u32 key;
    S3DActiveNode *activeHead;
    S3DSortedNode *sortedHead;
    u16 sortedCount;
    u8 pad0e[2];
} S3DMixGroup;

extern u8 lbl_803CC8C0[];
extern u8 lbl_803DE36B;
extern u8 lbl_803DE36C;
extern u8 lbl_803DE36D;
extern u8 lbl_803DE36A;
extern SndSpatialListenerLite *s3dListenerRoot;
extern f32 lbl_803E7880;
extern f64 lbl_803E7888;
extern f32 lbl_803E7890;
extern f64 lbl_803E7898;
extern f32 lbl_803E78A0;
extern f32 lbl_803E78A4;
extern f64 lbl_803E78A8;
extern f32 lbl_803E78B0;
extern f32 lbl_803E78B4;
extern f32 lbl_803E78B8;
extern f32 lbl_803E78BC;
extern f32 lbl_803E78C0;

extern double __frsqrte(double x);
extern void salApplyMatrix(f32 *matrix, f32 *vec, f32 *out);
extern void salNormalizeVector(f32 *v);
extern u32 synthFXStart(u32 fxId, u8 volume, u8 pan, u8 studio, u8 studioAux);
extern u32 synthFXSetCtrl(u32 handle, u8 controller, u8 value);
extern u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value);

#define S3D_MAX_GROUPS 0x40
#define S3D_MAX_ACTIVE_NODES 0x40
#define S3D_EMITTER_FLAG_RESTART_ON_STOP 0x00000002
#define S3D_EMITTER_FLAG_USE_AUX_STUDIO 0x00000010
#define S3D_EMITTER_FLAG_SKIP_FADE_IN 0x00000020
#define S3D_EMITTER_FLAG_PLAYING 0x00020000
#define S3D_EMITTER_FLAG_REMOVE 0x00040000
#define S3D_EMITTER_FLAG_AGE_OUT 0x00100000
#define S3D_CTRL_VOLUME 0x07
#define S3D_CTRL_PAN 0x0a
#define S3D_CTRL_SPATIAL_AZIMUTH 0x83
#define S3D_CTRL_SPATIAL_PITCH 0x84
#define S3D_CTRL_14BIT_LIMIT 0x3fff
#define S3D_GROUP_KEY_STEREO_LIMIT 0x80000000
#define S3D_INVALID_FX_HANDLE 0xffffffff
#define S3D_MIX_GROUPS ((S3DMixGroup *)(lbl_803CC8C0 + 0x50))
#define S3D_ACTIVE_NODES ((S3DActiveNode *)(lbl_803CC8C0 + 0x450))
#define S3D_SORTED_NODES ((S3DSortedNode *)(lbl_803CC8C0 + 0xb50))

#define S3D_CLAMP_7BIT(value) (((value) & 0xff) > 0x7f ? 0x7f : (value))

#pragma fp_contract off
#pragma dont_inline on
void fn_802800C0(Snd3DEmitterLite *emitter, f32 *distanceOut, f32 *panOut, f32 *azimuthOut,
                 f32 *pitchOut, f32 *frontBackOut)
{
    SndSpatialListenerLite *listener;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 listenerDistance;
    f32 ratio;
    f32 curve;
    f32 listenerVelocityDistance;
    f32 projectedDistance;
    f32 transformed[3];
    f32 azimuthSum;
    f32 pitchSum;
    f32 frontBackSum;
    u32 listenerCount;
    f64 invSqrt;
    f64 countFloat;

    listenerCount = 0;
    *distanceOut = lbl_803E7880;
    *panOut = lbl_803E78A4;
    azimuthSum = lbl_803E7880;
    pitchSum = lbl_803E7880;
    frontBackSum = lbl_803E7880;

    for (listener = s3dListenerRoot; listener != (SndSpatialListenerLite *)0x0;
         listener = listener->next) {
        dx = emitter->posX - (listener->posX + listener->velX * listener->time);
        dy = emitter->posY - (listener->posY + listener->velY * listener->time);
        dz = emitter->posZ - (listener->posZ + listener->velZ * listener->time);
        listenerDistance = dx * dx + dy * dy + dz * dz;
        if (listenerDistance > lbl_803E7880) {
            invSqrt = __frsqrte((f64)listenerDistance);
            invSqrt = lbl_803E7898 * invSqrt *
                      (lbl_803E78A8 - (f64)listenerDistance * invSqrt * invSqrt);
            invSqrt = lbl_803E7898 * invSqrt *
                      (lbl_803E78A8 - (f64)listenerDistance * invSqrt * invSqrt);
            invSqrt = lbl_803E7898 * invSqrt *
                      (lbl_803E78A8 - (f64)listenerDistance * invSqrt * invSqrt);
            *(volatile f32 *)&listenerDistance = (f32)((f64)listenerDistance * invSqrt);
        }

        if (listenerDistance <= emitter->maxDistance) {
            ratio = listenerDistance / emitter->maxDistance;
            if (listener->time >= lbl_803E7880) {
                curve = lbl_803E78A4 -
                        (((lbl_803E78A4 + listener->time) * ratio) -
                         (listener->time *
                          (lbl_803E78A4 -
                           ((lbl_803E78A4 - ratio) * (lbl_803E78A4 - ratio)))));
            } else {
                curve = lbl_803E78A4 -
                        (((lbl_803E78A4 - listener->time) * ratio) +
                         (ratio * (listener->time * ratio)));
            }
            *distanceOut += listener->volumeScale *
                            (emitter->minVolume +
                             (emitter->maxVolume - emitter->minVolume) * curve);

            if ((emitter->flags & 0x00080000) == 0) {
                if (((emitter->flags & 0x00000008) != 0) || ((listener->flags & 1) != 0)) {
                    dx = listener->refX - emitter->refX;
                    dy = listener->refY - emitter->refY;
                    dz = listener->refZ - emitter->refZ;
                    listenerVelocityDistance = dx * dx + dy * dy + dz * dz;
                    if (listenerVelocityDistance > lbl_803E7880) {
                        invSqrt = __frsqrte((f64)listenerVelocityDistance);
                        invSqrt = lbl_803E7898 * invSqrt *
                                  (lbl_803E78A8 -
                                   (f64)listenerVelocityDistance * invSqrt * invSqrt);
                        invSqrt = lbl_803E7898 * invSqrt *
                                  (lbl_803E78A8 -
                                   (f64)listenerVelocityDistance * invSqrt * invSqrt);
                        invSqrt = lbl_803E7898 * invSqrt *
                                  (lbl_803E78A8 -
                                   (f64)listenerVelocityDistance * invSqrt * invSqrt);
                        *(volatile f32 *)&listenerVelocityDistance =
                            (f32)((f64)listenerVelocityDistance * invSqrt);
                    }

                    if (listenerVelocityDistance > lbl_803E7880) {
                        dx = (emitter->posX + emitter->refX * lbl_803E78B0) -
                             (listener->posX + listener->refX * lbl_803E78B0);
                        dy = (emitter->posY + emitter->refY * lbl_803E78B0) -
                             (listener->posY + listener->refY * lbl_803E78B0);
                        dz = (emitter->posZ + emitter->refZ * lbl_803E78B0) -
                             (listener->posZ + listener->refZ * lbl_803E78B0);
                        projectedDistance = dx * dx + dy * dy + dz * dz;
                        if (projectedDistance > lbl_803E7880) {
                            invSqrt = __frsqrte((f64)projectedDistance);
                            invSqrt = lbl_803E7898 * invSqrt *
                                      (lbl_803E78A8 -
                                       (f64)projectedDistance * invSqrt * invSqrt);
                            invSqrt = lbl_803E7898 * invSqrt *
                                      (lbl_803E78A8 -
                                       (f64)projectedDistance * invSqrt * invSqrt);
                            invSqrt = lbl_803E7898 * invSqrt *
                                      (lbl_803E78A8 -
                                       (f64)projectedDistance * invSqrt * invSqrt);
                            *(volatile f32 *)&projectedDistance =
                                (f32)((f64)projectedDistance * invSqrt);
                        }
                        if (listenerDistance <= projectedDistance) {
                            *panOut = listener->panScale /
                                      (listener->panScale + listenerVelocityDistance);
                        } else {
                            *panOut = listener->panScale /
                                      (listener->panScale - listenerVelocityDistance);
                        }
                    }
                }

                if (listenerDistance != lbl_803E7880) {
                    salApplyMatrix(listener->matrix, &emitter->posX, transformed);
                    if (transformed[2] <= lbl_803E7880) {
                        if (-listener->rearRange < transformed[2]) {
                            frontBackSum += -transformed[2] / listener->rearRange;
                        } else {
                            frontBackSum += lbl_803E78A4;
                        }
                    } else {
                        if (transformed[2] < listener->frontRange) {
                            frontBackSum += -transformed[2] / listener->frontRange;
                        } else {
                            frontBackSum += lbl_803E7890;
                        }
                    }

                    if (((transformed[0] != lbl_803E7880) ||
                         (transformed[1] != lbl_803E7880)) ||
                        (transformed[2] != lbl_803E7880)) {
                        salNormalizeVector(transformed);
                    }
                    azimuthSum += transformed[0];
                    pitchSum -= transformed[1];
                }
            }
        }
        listenerCount++;
    }

    if (listenerCount != 0) {
        countFloat = (f64)listenerCount;
        *azimuthOut = azimuthSum / (f32)countFloat;
        *pitchOut = pitchSum / (f32)countFloat;
        *frontBackOut = frontBackSum / (f32)countFloat;
    }
}
#pragma dont_inline reset
#pragma fp_contract reset

#pragma dont_inline on
void fn_802805A4(Snd3DEmitterLite *emitter, f32 distance, f32 pan, f32 unused, f32 azimuth,
                 f32 pitch)
{
    S3DEmitterCtrlList *ctrlList;
    S3DEmitterCtrl *ctrl;
    u32 handle;
    u32 value;
    u16 value14;
    u8 i;
    u8 controller;
    f32 scaledPitch;

    (void)unused;
    handle = emitter->handle;
    if ((emitter->flags & S3D_EMITTER_FLAG_AGE_OUT) == 0) {
        value = (u32)(lbl_803E78A0 * distance);
        value = S3D_CLAMP_7BIT(value);
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME, value);
    } else {
        value = (u32)(lbl_803E78A0 * (emitter->age * distance));
        value = S3D_CLAMP_7BIT(value);
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME, value);
    }

    value = (u32)(lbl_803E78B4 * (lbl_803E78A4 + pan));
    value = S3D_CLAMP_7BIT(value);
    synthFXSetCtrl(handle, S3D_CTRL_PAN, value);

    value = (u32)(lbl_803E78B4 * (lbl_803E78A4 - azimuth));
    value = S3D_CLAMP_7BIT(value);
    synthFXSetCtrl(handle, S3D_CTRL_SPATIAL_AZIMUTH, value);

    scaledPitch = lbl_803E78B8 * pitch;
    value = (u32)scaledPitch;
    if (value < S3D_CTRL_14BIT_LIMIT + 1) {
        value14 = (u16)(u32)scaledPitch;
    } else {
        value14 = S3D_CTRL_14BIT_LIMIT;
    }
    synthFXSetCtrl14(handle, S3D_CTRL_SPATIAL_PITCH, value14);

    ctrlList = emitter->ctrlList;
    if (ctrlList != (S3DEmitterCtrlList *)0x0) {
        ctrl = ctrlList->entries;
        for (i = 0; i < ctrlList->count; i++) {
            controller = ctrl->controller;
            if (((controller < 0x40) || (controller == 0x80)) ||
                (controller == S3D_CTRL_SPATIAL_PITCH)) {
                synthFXSetCtrl14(handle, controller, ctrl->value);
            } else {
                synthFXSetCtrl(handle, controller, ctrl->value);
            }
            ctrl++;
        }
    }
}
#pragma dont_inline reset

/*
 * fn_802807C4 - distance-sorted voice node insert.
 */
#pragma dont_inline on
void fn_802807C4(Snd3DEmitterLite *emitter, f32 distance)
{
    S3DMixGroup *groups;
    S3DMixGroup *group;
    S3DSortedNode *node;
    S3DSortedNode *prev;
    S3DSortedNode *newNode;
    u32 groupIndex;
    u32 groupCount;

    groups = S3D_MIX_GROUPS;
    group = groups;
    groupCount = lbl_803DE36B;
    groupIndex = 0;
    while ((groupIndex < groupCount) && (emitter->groupKey != group->key)) {
        group++;
        groupIndex++;
    }

    if (groupIndex == groupCount) {
        group->activeHead = (S3DActiveNode *)0x0;
        group->sortedHead = (S3DSortedNode *)0x0;
        group->sortedCount = 0;
        group->key = emitter->groupKey;
        lbl_803DE36B++;
    }

    group->sortedCount++;
    node = group->sortedHead;
    prev = (S3DSortedNode *)0x0;
    while ((node != (S3DSortedNode *)0x0) && (node->distance <= distance)) {
        prev = node;
        node = node->next;
    }

    newNode = &S3D_SORTED_NODES[lbl_803DE36D];
    if (prev == (S3DSortedNode *)0x0) {
        group->sortedHead = newNode;
    } else {
        prev->next = newNode;
    }
    newNode->next = node;
    newNode->emitter = emitter;
    newNode->distance = distance;
    lbl_803DE36D++;
}
#pragma dont_inline reset

/*
 * fn_802808D8 - active spatial voice node insert.
 */
#pragma dont_inline on
int fn_802808D8(Snd3DEmitterLite *emitter, f32 distance, f32 arg1, f32 arg2, f32 arg3, f32 arg4)
{
    S3DMixGroup *groups;
    S3DMixGroup *group;
    S3DActiveNode *scan;
    S3DActiveNode *next;
    S3DActiveNode *newNode;
    u32 groupIndex;
    u32 groupCount;
    u32 remaining;
    u32 activeIndex;

    groups = S3D_MIX_GROUPS;
    group = groups;
    groupCount = lbl_803DE36B;
    remaining = groupCount;
    groupIndex = 0;
    while ((remaining != 0) && (emitter->groupKey != group->key)) {
        group++;
        groupIndex++;
        remaining--;
    }

    if (groupIndex == groupCount) {
        if (groupCount == S3D_MAX_GROUPS) {
            return 0;
        }
        group->activeHead = (S3DActiveNode *)0x0;
        group->sortedHead = (S3DSortedNode *)0x0;
        group->sortedCount = 0;
        group->key = emitter->groupKey;
        lbl_803DE36B++;
    }

    activeIndex = lbl_803DE36C;
    if (activeIndex == S3D_MAX_ACTIVE_NODES) {
        return 0;
    }

    scan = group->activeHead;
    if (scan == (S3DActiveNode *)0x0) {
        newNode = &S3D_ACTIVE_NODES[activeIndex];
        newNode->next = (S3DActiveNode *)0x0;
        group->activeHead = newNode;
    } else {
        do {
            next = scan->next;
            if (next == (S3DActiveNode *)0x0) {
                break;
            }
            if (next->distance < distance) {
                break;
            }
            scan = next;
        } while (true);
        newNode = &S3D_ACTIVE_NODES[activeIndex];
        newNode->next = next;
        scan->next = newNode;
    }

    newNode->emitter = emitter;
    newNode->arg4 = arg4;
    newNode->arg1 = arg1;
    newNode->arg2 = arg2;
    newNode->arg3 = arg3;
    lbl_803DE36C++;
    newNode->distance = distance;
    return 1;
}
#pragma dont_inline reset

#pragma dont_inline on
void audioFn_80280a08(void)
{
    S3DMixGroup *group;
    S3DActiveNode *node;
    Snd3DEmitterLite *emitter;
    SndSpatialEntryLite *entry;
    u32 groupIndex;
    u32 handle;
    u8 studio;
    f32 lowerWindow;
    f32 upperWindow;
    f32 zero;
    f32 one;
    f32 distanceDelta;

    group = S3D_MIX_GROUPS;
    groupIndex = 0;
    zero = lbl_803E7880;
    one = lbl_803E78A4;
    upperWindow = lbl_803E78C0;
    lowerWindow = lbl_803E78BC;

    while (groupIndex < lbl_803DE36B) {
        node = group->activeHead;
        while (node != (S3DActiveNode *)0x0) {
            if (group->sortedHead == (S3DSortedNode *)0x0) {
                goto start_voice;
            }
            if ((lbl_803DE36A != 0) && ((group->key & S3D_GROUP_KEY_STEREO_LIMIT) != 0) &&
                (group->sortedCount < group->activeHead->emitter->maxVoices)) {
                goto start_voice;
            }

            distanceDelta = node->distance - group->sortedHead->distance;
            if (distanceDelta > lowerWindow) {
                if (distanceDelta <= upperWindow) {
                    emitter = node->emitter;
                    emitter->retryCounter++;
                    if (emitter->retryCounter < 0x14) {
                        goto next_node;
                    }
                } else {
                    node->emitter->retryCounter = 0;
                }

start_voice:
                emitter = node->emitter;
                entry = emitter->entry;
                if ((entry == (SndSpatialEntryLite *)0x0) || (entry->assignedVoice != -1)) {
                    if (entry == (SndSpatialEntryLite *)0x0) {
                        studio = emitter->studio;
                    } else {
                        studio = entry->assignedVoice;
                    }

                    handle = synthFXStart(emitter->fxId, 0x7f, 0x40, studio,
                                          (emitter->flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0);
                    emitter->handle = handle;
                    if (handle != S3D_INVALID_FX_HANDLE) {
                        if ((emitter->flags & S3D_EMITTER_FLAG_SKIP_FADE_IN) == 0) {
                            emitter->flags |= S3D_EMITTER_FLAG_AGE_OUT;
                            emitter->age = zero;
                        } else {
                            emitter->age = one;
                        }
                        fn_802805A4(emitter, node->distance, node->arg1, node->arg2, node->arg3,
                                     node->arg4);
                        emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                        group->sortedCount++;
                        if (group->sortedHead != (S3DSortedNode *)0x0) {
                            group->sortedHead = group->sortedHead->next;
                        }
                        goto next_node;
                    }
                }

                if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) == 0) {
                    emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
            }

next_node:
            node = node->next;
        }
        group++;
        groupIndex++;
    }
}
#pragma dont_inline reset
