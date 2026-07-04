#include "main/audio/snd3d_calc.h"

typedef struct S3DActiveNode
{
    struct S3DActiveNode* next;
    f32 distance;
    f32 arg1;
    f32 arg2;
    f32 arg3;
    f32 arg4;
    Snd3DEmitter* emitter;
} S3DActiveNode;

typedef struct S3DSortedNode
{
    struct S3DSortedNode* next;
    f32 distance;
    Snd3DEmitter* emitter;
} S3DSortedNode;

typedef struct S3DMixGroup
{
    u32 key;
    S3DActiveNode* activeHead;
    S3DSortedNode* sortedHead;
    u16 sortedCount;
    u8 pad0e[2];
} S3DMixGroup;

extern u8 lbl_803CC8C0[];
extern S3DMixGroup lbl_803CC910[];
extern u8 lbl_803DE36B;
extern u8 lbl_803DE36C;
extern u8 lbl_803DE36D;
extern u8 lbl_803DE36A;
extern SndSpatialListener* s3dListenerRoot;
extern f32 lbl_803E7880;
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
extern int synthFXStart(u32 fxId, u8 volume, u8 pan, u8 studio, u32 studioAux);
extern u32 synthFXSetCtrl(u32 handle, u8 controller, int value);
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

#define S3D_CLAMP_7BIT(value) (((value) & 0xff) > 0x7f ? 0x7f : (value))

#pragma fp_contract off
void s3dCalcEmitter(Snd3DEmitter* emitter, f32* distanceOut, f32* panOut, f32* azimuthOut,
                    f32* pitchOut, f32* frontBackOut)
{
    SndSpatialListener* listener;
    f64 k1;
    f64 k3;
    f32 half;
    f32 one;
    f32 zero;
    f32 frontBackSum;
    f32 pitchSum;
    f32 azimuthSum;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 listenerDistance;
    f32 ratio;
    f32 curveParam;
    f32 listenerVelocityDistance;
    f32 projectedDistance;
    f32 transformed[3];
    volatile f32 tmp1;
    volatile f32 tmp2;
    volatile f32 tmp3;
    u32 listenerCount;
    f64 invSqrt;

    listenerCount = 0;
    zero = lbl_803E7880;
    *distanceOut = zero;
    frontBackSum = zero;
    one = lbl_803E78A4;
    *panOut = one;
    pitchSum = frontBackSum;
    azimuthSum = pitchSum;
    half = lbl_803E78B0;
    k3 = lbl_803E7898;
    k1 = lbl_803E78A8;

    for (listener = s3dListenerRoot; listener != (SndSpatialListener*)0x0;
         listener = listener->next)
    {
        dx = emitter->posX - (listener->posX + listener->velX * listener->time);
        dy = emitter->posY - (listener->posY + listener->velY * listener->time);
        dz = emitter->posZ - (listener->posZ + listener->velZ * listener->time);
        listenerDistance = dx * dx + dy * dy + dz * dz;
        if (listenerDistance > zero)
        {
            invSqrt = __frsqrte((f64)listenerDistance);
            invSqrt = k3 * invSqrt *
                (k1 - listenerDistance * (invSqrt * invSqrt));
            invSqrt = k3 * invSqrt *
                (k1 - listenerDistance * (invSqrt * invSqrt));
            invSqrt = k3 * invSqrt *
                (k1 - listenerDistance * (invSqrt * invSqrt));
            tmp1 = (f32)((f64)listenerDistance * invSqrt);
            listenerDistance = tmp1;
        }

        if (emitter->maxDistance >= listenerDistance)
        {
            ratio = listenerDistance / emitter->maxDistance;
            curveParam = emitter->distanceCurve;
            if (curveParam >= zero)
            {
                *distanceOut += listener->volumeScale *
                (emitter->minVolume +
                    (emitter->maxVolume - emitter->minVolume) *
                    (one - ((one - curveParam) * ratio +
                        ratio * (curveParam * ratio))));
            }
            else
            {
                *distanceOut += listener->volumeScale *
                (emitter->minVolume +
                    (emitter->maxVolume - emitter->minVolume) *
                    (one - ((one + curveParam) * ratio -
                        curveParam *
                        (one - (one - ratio) * (one - ratio)))));
            }

            if ((emitter->flags & S3D_EMITTER_FLAG_WAITING_FOR_ROOM) == 0)
            {
                if (((emitter->flags & 0x00000008) != 0) || ((listener->flags & 1) != 0))
                {
                    dx = listener->refX - emitter->refX;
                    dy = listener->refY - emitter->refY;
                    dz = listener->refZ - emitter->refZ;
                    listenerVelocityDistance = dx * dx + dy * dy + dz * dz;
                    if (listenerVelocityDistance > zero)
                    {
                        invSqrt = __frsqrte((f64)listenerVelocityDistance);
                        invSqrt = k3 * invSqrt *
                        (k1 -
                            listenerVelocityDistance * (invSqrt * invSqrt));
                        invSqrt = k3 * invSqrt *
                        (k1 -
                            listenerVelocityDistance * (invSqrt * invSqrt));
                        invSqrt = k3 * invSqrt *
                        (k1 -
                            listenerVelocityDistance * (invSqrt * invSqrt));
                        tmp2 = (f32)((f64)listenerVelocityDistance * invSqrt);
                        listenerVelocityDistance = tmp2;
                    }

                    if (listenerVelocityDistance > zero)
                    {
                        dx = (emitter->posX + emitter->refX * half) -
                            (listener->posX + listener->refX * half);
                        dy = (emitter->posY + emitter->refY * half) -
                            (listener->posY + listener->refY * half);
                        dz = (emitter->posZ + emitter->refZ * half) -
                            (listener->posZ + listener->refZ * half);
                        projectedDistance = dx * dx + dy * dy + dz * dz;
                        if (projectedDistance > zero)
                        {
                            invSqrt = __frsqrte((f64)projectedDistance);
                            invSqrt = k3 * invSqrt *
                            (k1 -
                                projectedDistance * (invSqrt * invSqrt));
                            invSqrt = k3 * invSqrt *
                            (k1 -
                                projectedDistance * (invSqrt * invSqrt));
                            invSqrt = k3 * invSqrt *
                            (k1 -
                                projectedDistance * (invSqrt * invSqrt));
                            tmp3 = (f32)((f64)projectedDistance * invSqrt);
                            projectedDistance = tmp3;
                        }
                        if (projectedDistance < listenerDistance)
                        {
                            *panOut = listener->panScale /
                                (listener->panScale - listenerVelocityDistance);
                        }
                        else
                        {
                            *panOut = listener->panScale /
                                (listener->panScale + listenerVelocityDistance);
                        }
                    }
                }

                if (zero != listenerDistance)
                {
                    salApplyMatrix(listener->matrix, &emitter->posX, transformed);
                    if (transformed[2] <= zero)
                    {
                        frontBackSum += -listener->rearRange < transformed[2]
                            ? -transformed[2] / listener->rearRange
                            : lbl_803E78A4;
                    }
                    else
                    {
                        frontBackSum += listener->frontRange > transformed[2]
                            ? -transformed[2] / listener->frontRange
                            : lbl_803E7890;
                    }

                    if (((zero != transformed[0]) ||
                            (zero != transformed[1])) ||
                        (zero != transformed[2]))
                    {
                        salNormalizeVector(transformed);
                    }
                    azimuthSum += transformed[0];
                    pitchSum -= transformed[1];
                }
            }
        }
        listenerCount++;
    }

    if (listenerCount != 0)
    {
        *azimuthOut = azimuthSum / listenerCount;
        *pitchOut = pitchSum / listenerCount;
        *frontBackOut = frontBackSum / listenerCount;
    }
}
#pragma fp_contract reset

void s3dApplyEmitterControls(Snd3DEmitter* emitter, f32 distance, f32 pan, f32 unused,
                             f32 azimuth, f32 pitch)
{
    u32 handle;
    u16 value14;
    u8 i;
    S3DEmitterCtrl* ctrl;
    u8 controller;

    (void)unused;
    handle = emitter->handle;
    if ((emitter->flags & S3D_EMITTER_FLAG_AGE_OUT) != 0)
    {
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME,
                       S3D_CLAMP_7BIT((u32)(int)(lbl_803E78A0 * (emitter->age * distance))));
    }
    else
    {
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME,
                       S3D_CLAMP_7BIT((u32)(int)(lbl_803E78A0 * distance)));
    }

    synthFXSetCtrl(handle, S3D_CTRL_PAN,
                   S3D_CLAMP_7BIT((u32)(int)(lbl_803E78B4 * (lbl_803E78A4 + pan))));

    synthFXSetCtrl(handle, S3D_CTRL_SPATIAL_AZIMUTH,
                   S3D_CLAMP_7BIT((u32)(int)(lbl_803E78B4 * (lbl_803E78A4 - azimuth))));

    pitch = lbl_803E78B8 * pitch;
    if ((u32)pitch > S3D_CTRL_14BIT_LIMIT)
    {
        value14 = S3D_CTRL_14BIT_LIMIT;
    }
    else
    {
        value14 = (u16)(u32)
        pitch;
    }
    synthFXSetCtrl14(handle, S3D_CTRL_SPATIAL_PITCH, value14);

    if (emitter->ctrlList != (S3DEmitterCtrlList*)0x0)
    {
        ctrl = emitter->ctrlList->entries;
        for (i = 0; i < emitter->ctrlList->count; i++)
        {
            if (((ctrl->controller < 0x40) || (ctrl->controller == 0x80)) ||
                (ctrl->controller == S3D_CTRL_SPATIAL_PITCH))
            {
                synthFXSetCtrl14(handle, ctrl->controller, ctrl->value);
            }
            else
            {
                synthFXSetCtrl(handle, ctrl->controller, *(u8*)&ctrl->value);
            }
            ctrl++;
        }
    }
}

/*
 * s3dInsertSortedEmitter - distance-sorted voice node insert.
 */
void s3dInsertSortedEmitter(Snd3DEmitter* emitter, f32 distance)
{
    S3DMixGroup* group;
    S3DSortedNode* node;
    S3DSortedNode* prev;
    u8* base;
    int groupCount;
    int groupIndex;
    int gi;

    base = lbl_803CC8C0;
    group = (S3DMixGroup*)(base + 0x50);
    groupCount = lbl_803DE36B;
    for (groupIndex = 0; groupIndex < groupCount; groupIndex++)
    {
        if (emitter->groupKey == group->key)
        {
            break;
        }
        group++;
    }

    if (groupIndex == groupCount)
    {
        ((S3DMixGroup*)(base + 0x50))[groupIndex].activeHead = (S3DActiveNode*)0x0;
        ((S3DMixGroup*)(base + 0x50))[groupIndex].sortedHead = (S3DSortedNode*)0x0;
        ((S3DMixGroup*)(base + 0x50))[groupIndex].sortedCount = 0;
        ((S3DMixGroup*)(base + 0x50))[groupIndex].key = emitter->groupKey;
        lbl_803DE36B++;
    }

    ((S3DMixGroup*)(base + 0x50))[gi = groupIndex].sortedCount++;
    node = ((S3DMixGroup*)(base + 0x50))[gi].sortedHead;
    prev = (S3DSortedNode*)0x0;
    while (node != (S3DSortedNode*)0x0)
    {
        if (node->distance > distance)
        {
            break;
        }
        prev = node;
        node = node->next;
    }

    if (prev == (S3DSortedNode*)0x0)
    {
        ((S3DMixGroup*)(base + 0x50))[gi].sortedHead = &((S3DSortedNode*)(base + 0xb50))[lbl_803DE36D];
    }
    else
    {
        prev->next = &((S3DSortedNode*)(base + 0xb50))[lbl_803DE36D];
    }
    {
        S3DSortedNode* newNode = &((S3DSortedNode*)(base + 0xb50))[lbl_803DE36D];
        newNode->next = node;
        newNode->emitter = emitter;
    }
    ((S3DSortedNode*)(base + 0xb50))[lbl_803DE36D++].distance = distance;
}

/*
 * s3dInsertActiveEmitter - active spatial voice node insert.
 */
int s3dInsertActiveEmitter(Snd3DEmitter* emitter, f32 distance, f32 arg1, f32 arg2, f32 arg3,
                           f32 arg4)
{
    S3DMixGroup* group;
    S3DActiveNode* scan;
    S3DActiveNode* next;
    u8* base;
    S3DActiveNode** pp;
    int groupCount;
    int groupIndex;
    u32 activeIndex;

    base = lbl_803CC8C0;
    group = (S3DMixGroup*)(base + 0x50);
    groupCount = lbl_803DE36B;
    for (groupIndex = 0; groupIndex < groupCount; groupIndex++)
    {
        if (emitter->groupKey == group->key)
        {
            break;
        }
        group++;
    }

    if (groupIndex == groupCount)
    {
        if ((u32)groupCount == S3D_MAX_GROUPS)
        {
            return 0;
        }
        ((S3DMixGroup*)(base + 0x50))[groupIndex].activeHead = (S3DActiveNode*)0x0;
        ((S3DMixGroup*)(base + 0x50))[groupIndex].sortedHead = (S3DSortedNode*)0x0;
        ((S3DMixGroup*)(base + 0x50))[groupIndex].sortedCount = 0;
        ((S3DMixGroup*)(base + 0x50))[groupIndex].key = emitter->groupKey;
        lbl_803DE36B++;
    }

    activeIndex = lbl_803DE36C;
    if (activeIndex == S3D_MAX_ACTIVE_NODES)
    {
        return 0;
    }

    next = ((S3DMixGroup*)(base + 0x50))[groupIndex].activeHead;
    pp = &((S3DMixGroup*)(base + 0x50))[groupIndex].activeHead;
    if ((scan = next) != (S3DActiveNode*)0x0)
    {
        while ((next = scan->next) != (S3DActiveNode*)0x0)
        {
            if (scan->distance < distance)
            {
                break;
            }
            scan = next;
        }
        ((S3DActiveNode*)(base + 0x450))[activeIndex].next = next;
        scan->next = &((S3DActiveNode*)(base + 0x450))[activeIndex];
    }
    else
    {
        ((S3DActiveNode*)(base + 0x450))[activeIndex].next = next;
        *pp = &((S3DActiveNode*)(base + 0x450))[activeIndex];
    }

    {
        S3DActiveNode* newNode = &((S3DActiveNode*)(base + 0x450))[lbl_803DE36C];
        newNode->emitter = emitter;
        newNode->arg4 = arg4;
        newNode->arg1 = arg1;
        newNode->arg2 = arg2;
        newNode->arg3 = arg3;
    }
    ((S3DActiveNode*)(base + 0x450))[lbl_803DE36C++].distance = distance;
    return 1;
}


void s3dStartQueuedEmitters(void)
{
    int groupIndex;
    S3DActiveNode* node;
    Snd3DEmitter* emitter;
    u32 handle;
    u8 studio;
    f32 one;
    f32 zero;
    f32 upperWindow;
    f32 lowerWindow;
    f32 distanceDelta;

    zero = lbl_803E7880;
    one = lbl_803E78A4;
    upperWindow = lbl_803E78C0;
    lowerWindow = lbl_803E78BC;

    for (groupIndex = 0; groupIndex < lbl_803DE36B; groupIndex++)
    {
        node = lbl_803CC910[groupIndex].activeHead;
        while (node != (S3DActiveNode*)0x0)
        {
            if (lbl_803CC910[groupIndex].sortedHead == (S3DSortedNode*)0x0)
            {
                goto start_voice;
            }
            if ((lbl_803DE36A != 0) && ((lbl_803CC910[groupIndex].key & S3D_GROUP_KEY_STEREO_LIMIT) != 0) &&
                (lbl_803CC910[groupIndex].sortedCount < lbl_803CC910[groupIndex].activeHead->emitter->maxVoices))
            {
                goto start_voice;
            }

            distanceDelta = node->distance - lbl_803CC910[groupIndex].sortedHead->distance;
            if (distanceDelta <= lowerWindow)
            {
                goto next_node;
            }
            if (distanceDelta <= upperWindow)
            {
                emitter = node->emitter;
                if (++emitter->retryCounter < 0x14)
                {
                    goto next_node;
                }
            }
            else
            {
                node->emitter->retryCounter = 0;
            }

        start_voice:
            emitter = node->emitter;
            if ((emitter->entry != (SndSpatialEntry*)0x0) && (emitter->entry->assignedVoice == 0xff))
            {
                goto stop_voice;
            }

            if (emitter->entry != (SndSpatialEntry*)0x0)
            {
                studio = emitter->entry->assignedVoice;
            }
            else
            {
                studio = emitter->studio;
            }

            handle = synthFXStart(emitter->fxId, 0x7f, 0x40, studio,
                                  (emitter->flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0);
            emitter->handle = handle;
            if (handle != S3D_INVALID_FX_HANDLE)
            {
                goto started;
            }

        stop_voice:
            if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) == 0)
            {
                emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
            }
            goto next_node;

        started:
            if ((emitter->flags & S3D_EMITTER_FLAG_SKIP_FADE_IN) == 0)
            {
                emitter->flags |= S3D_EMITTER_FLAG_AGE_OUT;
                emitter->age = zero;
            }
            else
            {
                emitter->age = one;
            }
            s3dApplyEmitterControls(emitter, node->distance, node->arg1,
                                    node->arg2, node->arg3, node->arg4);
            emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
            lbl_803CC910[groupIndex].sortedCount++;
            if (lbl_803CC910[groupIndex].sortedHead != (S3DSortedNode*)0x0)
            {
                lbl_803CC910[groupIndex].sortedHead = lbl_803CC910[groupIndex].sortedHead->next;
            }

        next_node:
            node = node->next;
        }
    }
}
