#include "main/audio/snd3d_calc.h"
#include "main/audio/synth_voice.h"

#pragma exceptions on

typedef struct S3DActiveNode
{
    struct S3DActiveNode* next;
    f32 distance;
    f32 pan;
    f32 frontBack;
    f32 azimuth;
    f32 pitch;
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
extern u32 synthFXSetCtrl(u32 handle, u8 controller, int value);
extern u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value);

typedef struct SndFVector
{
    f32 x;
    f32 y;
    f32 z;
} SndFVector;

#define S3D_MAX_GROUPS                   0x40
#define S3D_MAX_ACTIVE_NODES             0x40
#define S3D_EMITTER_FLAG_RESTART_ON_STOP 0x00000002
#define S3D_EMITTER_FLAG_USE_AUX_STUDIO  0x00000010
#define S3D_EMITTER_FLAG_SKIP_FADE_IN    0x00000020
#define S3D_EMITTER_FLAG_PLAYING         0x00020000
#define S3D_EMITTER_FLAG_REMOVE          0x00040000
#define S3D_EMITTER_FLAG_AGE_OUT         0x00100000
#define S3D_CTRL_VOLUME                  0x07
#define S3D_CTRL_PAN                     0x0a
#define S3D_CTRL_PITCH_BEND              0x80
#define S3D_CTRL_SPATIAL_AZIMUTH         0x83
#define S3D_CTRL_SPATIAL_PITCH           0x84
#define S3D_CTRL_14BIT_LIMIT             0x3fff
#define S3D_GROUP_KEY_STEREO_LIMIT       0x80000000
#define S3D_INVALID_FX_HANDLE            0xffffffff

#define S3D_CLAMP_7BIT(value) (((value) & 0xff) > 0x7f ? 0x7f : (value))

#pragma fp_contract off
extern inline f32 sqrtf(f32 x)
{
    volatile f32 y;

    if (x > 0.0f)
    {
        f64 guess = __frsqrte((f64)x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        y = (f32)((f64)x * guess);
        return y;
    }
    return x;
}

void s3dCalcEmitter(Snd3DEmitter* emitter, f32* distanceOut, f32* panOut, f32* azimuthOut, f32* pitchOut,
                    f32* frontBackOut)
{
    SndSpatialListener* listener;
    SndFVector d;
    SndFVector v;
    SndFVector p;
    f32 relativeSpeed;
    f32 distance;
    f32 newDistance;
    f32 frameTime;
    f32 distanceRatio;
    SndFVector pan;
    u32 listenerCount;

    frameTime = 1.0f / 60.0f;
    *distanceOut = 0.0f;
    *panOut = 1.0f;
    pan.x = pan.y = pan.z = 0.0f;

    for (listenerCount = 0, listener = s3dListenerRoot; listener != NULL;
         listener = listener->next, listenerCount++)
    {
        d.x = emitter->posX - (listener->posX + listener->velX * listener->time);
        d.y = emitter->posY - (listener->posY + listener->velY * listener->time);
        d.z = emitter->posZ - (listener->posZ + listener->velZ * listener->time);
        distance = sqrtf(d.x * d.x + d.y * d.y + d.z * d.z);

        if (emitter->maxDistance >= distance)
        {
            distanceRatio = distance / emitter->maxDistance;
            if (emitter->distanceCurve >= 0.0f)
            {
                *distanceOut += listener->volumeScale *
                                (emitter->minVolume +
                                 (emitter->maxVolume - emitter->minVolume) *
                                     (1.0f -
                                      ((1.0f - emitter->distanceCurve) * distanceRatio +
                                       emitter->distanceCurve * distanceRatio * distanceRatio)));
            }
            else
            {
                *distanceOut += listener->volumeScale *
                                (emitter->minVolume +
                                 (emitter->maxVolume - emitter->minVolume) *
                                     (1.0f -
                                      ((emitter->distanceCurve + 1.0f) * distanceRatio -
                                       emitter->distanceCurve *
                                           (1.0f - (1.0f - distanceRatio) * (1.0f - distanceRatio)))));
            }

            if (!(emitter->flags & S3D_EMITTER_FLAG_WAITING_FOR_ROOM))
            {
                if ((emitter->flags & 0x00000008) || (listener->flags & 1))
                {
                    v.x = listener->refX - emitter->refX;
                    v.y = listener->refY - emitter->refY;
                    v.z = listener->refZ - emitter->refZ;
                    relativeSpeed = sqrtf(v.x * v.x + v.y * v.y + v.z * v.z);

                    if (relativeSpeed > 0.0f)
                    {
                        d.x = (emitter->posX + emitter->refX * frameTime) -
                              (listener->posX + listener->refX * frameTime);
                        d.y = (emitter->posY + emitter->refY * frameTime) -
                              (listener->posY + listener->refY * frameTime);
                        d.z = (emitter->posZ + emitter->refZ * frameTime) -
                              (listener->posZ + listener->refZ * frameTime);
                        newDistance = sqrtf(d.x * d.x + d.y * d.y + d.z * d.z);

                        if (newDistance < distance)
                        {
                            *panOut = listener->panScale / (listener->panScale - relativeSpeed);
                        }
                        else
                        {
                            *panOut = listener->panScale / (listener->panScale + relativeSpeed);
                        }
                    }
                }

                if (distance != 0.0f)
                {
                    salApplyMatrix(listener->matrix, &emitter->posX, &p.x);
                    if (p.z <= 0.0f)
                    {
                        pan.z += -listener->rearRange < p.z ? -p.z / listener->rearRange : 1.0f;
                    }
                    else
                    {
                        pan.z += listener->frontRange > p.z ? -p.z / listener->frontRange : -1.0f;
                    }

                    if (p.x != 0.0f || p.y != 0.0f || p.z != 0.0f)
                    {
                        salNormalizeVector(&p.x);
                    }
                    pan.x += p.x;
                    pan.y -= p.y;
                }
            }
        }
    }

    if (listenerCount != 0)
    {
        *azimuthOut = pan.x / listenerCount;
        *pitchOut = pan.y / listenerCount;
        *frontBackOut = pan.z / listenerCount;
    }
}
#pragma fp_contract reset

void s3dApplyEmitterControls(Snd3DEmitter* emitter, f32 distance, f32 pan, f32 unused, f32 azimuth, f32 pitch)
{
    u32 handle;
    u16 value14;
    u8 i;
    S3DEmitterCtrl* ctrl;
    (void)unused;
    handle = emitter->handle;
    if ((emitter->flags & S3D_EMITTER_FLAG_AGE_OUT) != 0)
    {
        {
            u32 v = (u32)(int)(lbl_803E78A0 * (emitter->age * distance));
            if ((v & 0xff) > 0x7f)
            {
                v = 0x7f;
            }
            synthFXSetCtrl(handle, S3D_CTRL_VOLUME, v);
        }
    }
    else
    {
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME, S3D_CLAMP_7BIT((u32)(int)(lbl_803E78A0 * distance)));
    }

    synthFXSetCtrl(handle, S3D_CTRL_PAN, S3D_CLAMP_7BIT((u32)(int)(lbl_803E78B4 * (lbl_803E78A4 + pan))));

    synthFXSetCtrl(handle, S3D_CTRL_SPATIAL_AZIMUTH,
                   S3D_CLAMP_7BIT((u32)(int)(lbl_803E78B4 * (lbl_803E78A4 - azimuth))));

    pitch = lbl_803E78B8 * pitch;
    if ((u32)pitch > S3D_CTRL_14BIT_LIMIT)
    {
        value14 = S3D_CTRL_14BIT_LIMIT;
    }
    else
    {
        value14 = (u16)(u32)pitch;
    }
    synthFXSetCtrl14(handle, S3D_CTRL_SPATIAL_PITCH, value14);

    if (emitter->ctrlList != (S3DEmitterCtrlList*)0x0)
    {
        ctrl = emitter->ctrlList->entries;
        for (i = 0; i < emitter->ctrlList->count; i++)
        {
            if (((ctrl->controller < 0x40) || (ctrl->controller == S3D_CTRL_PITCH_BEND)) ||
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
#pragma opt_lifetimes off
int s3dInsertActiveEmitter(Snd3DEmitter* emitter, f32 distance, f32 pan, f32 frontBack, f32 azimuth, f32 pitch)
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
        newNode->pitch = pitch;
        newNode->pan = pan;
        newNode->frontBack = frontBack;
        newNode->azimuth = azimuth;
    }
    ((S3DActiveNode*)(base + 0x450))[lbl_803DE36C++].distance = distance;
    return 1;
}
#pragma opt_lifetimes reset

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
            s3dApplyEmitterControls(emitter, node->distance, node->pan, node->frontBack, node->azimuth, node->pitch);
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

S3DMixGroup lbl_803CC910[0xE5];
u8 lbl_803CC8C0[0x50];
