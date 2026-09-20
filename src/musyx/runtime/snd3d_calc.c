#include "musyx/snd3d_calc.h"
#include "musyx/snd_core.h"
#include "musyx/synth_voice.h"
#include "musyx/synth_delay.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "musyx/snd3d.h"

typedef struct START_LIST
{
    struct START_LIST* next;
    f32 vol;
    f32 xPan;
    f32 yPan;
    f32 zPan;
    f32 pitch;
    SND_EMITTER* em;
} START_LIST;

typedef struct RUN_LIST
{
    struct RUN_LIST* next;
    f32 vol;
    SND_EMITTER* em;
} RUN_LIST;

typedef struct START_GROUP
{
    u32 id;
    START_LIST* list;
    RUN_LIST* running;
    u16 numRunning;
    u8 pad0e[2];
} START_GROUP;

static u8 lbl_803CC8C0[0x50];
static START_GROUP startGroup[64];
static START_LIST startListNum[64];
static RUN_LIST runList[64];
static u8 lbl_803CD710[0x50];

#define S3D_MAX_GROUPS                   0x40
#define S3D_MAX_ACTIVE_NODES             0x40
#define S3D_EMITTER_FLAG_SKIP_FADE_IN    0x00000020
#define S3D_CTRL_VOLUME                  0x07
#define S3D_CTRL_PAN                     0x0a
#define S3D_CTRL_PITCH_BEND              0x80
#define S3D_CTRL_SPATIAL_AZIMUTH         0x83
#define S3D_CTRL_SPATIAL_PITCH           0x84
#define S3D_CTRL_14BIT_LIMIT             0x3fff
#define S3D_GROUP_KEY_STEREO_LIMIT       0x80000000

extern inline f32 sqrtf(f32 x)
{
    volatile f32 y;

    if (x > 0.0f)
    {
        f64 guess = __frsqrte((f64)x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        y = (f32)(x * guess);
        return y;
    }
    return x;
}

static inline u8 clip127(u8 value)
{
    if (value > 0x7f)
    {
        return 0x7f;
    }
    return value;
}

static void CalcEmitter(SND_EMITTER* emitter, f32* vol, f32* doppler, f32* xPan,
                           f32* yPan, f32* zPan)
{
    SND_LISTENER* listener;
    SND_FVECTOR d;
    SND_FVECTOR v;
    SND_FVECTOR p;
    f32 relativeSpeed;
    f32 distance;
    f32 newDistance;
    f32 frameTime;
    f32 distanceRatio;
    SND_FVECTOR pan;
    u32 listenerCount;

    frameTime = 1.0f / 60.0f;
    *vol = 0.0f;
    *doppler = 1.0f;
    pan.x = pan.y = pan.z = 0.0f;

    for (listenerCount = 0, listener = s3dListenerRoot; listener != NULL;
         listener = listener->next, listenerCount++)
    {
        d.x = emitter->pos.x - (listener->pos.x + listener->heading.x * listener->volPosOff);
        d.y = emitter->pos.y - (listener->pos.y + listener->heading.y * listener->volPosOff);
        d.z = emitter->pos.z - (listener->pos.z + listener->heading.z * listener->volPosOff);
        distance = sqrtf(d.x * d.x + d.y * d.y + d.z * d.z);

        if (emitter->maxDis >= distance)
        {
            distanceRatio = distance / emitter->maxDis;
            if (emitter->volPush >= 0.0f)
            {
                *vol += listener->vol *
                                (emitter->minVol +
                                 (emitter->maxVol - emitter->minVol) *
                                     (1.0f -
                                      ((1.0f - emitter->volPush) * distanceRatio +
                                       emitter->volPush * distanceRatio * distanceRatio)));
            }
            else
            {
                *vol += listener->vol *
                                (emitter->minVol +
                                 (emitter->maxVol - emitter->minVol) *
                                     (1.0f -
                                      ((emitter->volPush + 1.0f) * distanceRatio -
                                       emitter->volPush *
                                           (1.0f - (1.0f - distanceRatio) * (1.0f - distanceRatio)))));
            }

            if (!(emitter->flags & S3D_EMITTER_FLAG_WAITING_FOR_ROOM))
            {
                if ((emitter->flags & 0x00000008) || (listener->flags & 1))
                {
                    v.x = listener->dir.x - emitter->dir.x;
                    v.y = listener->dir.y - emitter->dir.y;
                    v.z = listener->dir.z - emitter->dir.z;
                    relativeSpeed = sqrtf(v.x * v.x + v.y * v.y + v.z * v.z);

                    if (relativeSpeed > 0.0f)
                    {
                        d.x = (emitter->pos.x + emitter->dir.x * frameTime) -
                              (listener->pos.x + listener->dir.x * frameTime);
                        d.y = (emitter->pos.y + emitter->dir.y * frameTime) -
                              (listener->pos.y + listener->dir.y * frameTime);
                        d.z = (emitter->pos.z + emitter->dir.z * frameTime) -
                              (listener->pos.z + listener->dir.z * frameTime);
                        newDistance = sqrtf(d.x * d.x + d.y * d.y + d.z * d.z);

                        if (newDistance < distance)
                        {
                            *doppler = listener->soundSpeed / (listener->soundSpeed - relativeSpeed);
                        }
                        else
                        {
                            *doppler = listener->soundSpeed / (listener->soundSpeed + relativeSpeed);
                        }
                    }
                }

                if (distance != 0.0f)
                {
                    salApplyMatrix(listener->mat, &emitter->pos.x, &p.x);
                    if (p.z <= 0.0f)
                    {
                        pan.z += -listener->surroundDisFront < p.z ? -p.z / listener->surroundDisFront : 1.0f;
                    }
                    else
                    {
                        pan.z += listener->surroundDisBack > p.z ? -p.z / listener->surroundDisBack : -1.0f;
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
        *xPan = pan.x / listenerCount;
        *yPan = pan.y / listenerCount;
        *zPan = pan.z / listenerCount;
    }
}

static void SetFXParameters(SND_EMITTER* emitter, f32 vol, f32 xPan, f32 yPan, f32 zPan,
                                    f32 pitch)
{
    u32 handle;
    u16 value14;
    u8 i;
    SND_PARAMETER* ctrl;
    (void)yPan;
    handle = emitter->vid;
    if ((emitter->flags & S3D_EMITTER_FLAG_AGE_OUT) != 0)
    {
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME, clip127(127.0f * (emitter->fade * vol)));
    }
    else
    {
        synthFXSetCtrl(handle, S3D_CTRL_VOLUME, clip127(127.0f * vol));
    }

    synthFXSetCtrl(handle, S3D_CTRL_PAN, clip127(64.0f * (1.0f + xPan)));

    synthFXSetCtrl(handle, S3D_CTRL_SPATIAL_AZIMUTH, clip127(64.0f * (1.0f - zPan)));

    pitch = 8192.0f * pitch;
    if ((u32)pitch > S3D_CTRL_14BIT_LIMIT)
    {
        value14 = S3D_CTRL_14BIT_LIMIT;
    }
    else
    {
        value14 = (u16)(u32)pitch;
    }
    synthFXSetCtrl14(handle, S3D_CTRL_SPATIAL_PITCH, value14);

    if (emitter->paraInfo != (SND_PARAMETER_INFO*)0x0)
    {
        ctrl = emitter->paraInfo->paraArray;
        for (i = 0; i < emitter->paraInfo->numPara; i++)
        {
            if (((ctrl->ctrl < 0x40) || (ctrl->ctrl == S3D_CTRL_PITCH_BEND)) ||
                (ctrl->ctrl == S3D_CTRL_SPATIAL_PITCH))
            {
                synthFXSetCtrl14(handle, ctrl->ctrl, ctrl->paraData.value14);
            }
            else
            {
                synthFXSetCtrl(handle, ctrl->ctrl, ctrl->paraData.value7);
            }
            ctrl++;
        }
    }
}

/*
 * AddRunningEmitter - distance-sorted voice node insert.
 */
static void AddRunningEmitter(SND_EMITTER* emitter, f32 vol)
{
    START_GROUP* group;
    RUN_LIST* node;
    RUN_LIST* prev;
    int groupCount;
    int groupIndex;

    group = startGroup;
    groupCount = startGroupNum;
    for (groupIndex = 0; groupIndex < groupCount; groupIndex++)
    {
        if (emitter->group == group->id)
        {
            break;
        }
        group++;
    }

    if (groupIndex == groupCount)
    {
        startGroup[groupIndex].list = (START_LIST*)0x0;
        startGroup[groupIndex].running = (RUN_LIST*)0x0;
        startGroup[groupIndex].numRunning = 0;
        startGroup[groupIndex].id = emitter->group;
        startGroupNum++;
    }

    startGroup[groupIndex].numRunning++;
    node = startGroup[groupIndex].running;
    prev = (RUN_LIST*)0x0;
    while (node != (RUN_LIST*)0x0)
    {
        if (node->vol > vol)
        {
            break;
        }
        prev = node;
        node = node->next;
    }

    if (prev == (RUN_LIST*)0x0)
    {
        startGroup[groupIndex].running = &runList[runListNum];
    }
    else
    {
        prev->next = &runList[runListNum];
    }
    {
        RUN_LIST* newNode = &runList[runListNum];
        newNode->next = node;
        newNode->em = emitter;
    }
    runList[runListNum++].vol = vol;
}

/*
 * AddStartingEmitter - active spatial voice node insert.
 */
static int AddStartingEmitter(SND_EMITTER* emitter, f32 vol, f32 xPan, f32 yPan, f32 zPan,
                                  f32 pitch)
{
    START_GROUP* group;
    START_LIST* scan;
    int groupCount;
    int groupIndex;

    group = startGroup;
    groupCount = startGroupNum;
    for (groupIndex = 0; groupIndex < groupCount; groupIndex++)
    {
        if (emitter->group == group->id)
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
        startGroup[groupIndex].list = (START_LIST*)0x0;
        startGroup[groupIndex].running = (RUN_LIST*)0x0;
        startGroup[groupIndex].numRunning = 0;
        startGroup[groupIndex].id = emitter->group;
        startGroupNum++;
    }

    if (startListNumnum == S3D_MAX_ACTIVE_NODES)
    {
        return 0;
    }

    if ((scan = startGroup[groupIndex].list) != (START_LIST*)0x0)
    {
        while (scan->next != (START_LIST*)0x0)
        {
            if (scan->vol < vol)
            {
                break;
            }
            scan = scan->next;
        }
        startListNum[startListNumnum].next = scan->next;
        scan->next = &startListNum[startListNumnum];
    }
    else
    {
        startListNum[startListNumnum].next = startGroup[groupIndex].list;
        startGroup[groupIndex].list = &startListNum[startListNumnum];
    }

    {
        START_LIST* newNode = &startListNum[startListNumnum];
        newNode->em = emitter;
        newNode->pitch = pitch;
        newNode->xPan = xPan;
        newNode->yPan = yPan;
        newNode->zPan = zPan;
    }
    startListNum[startListNumnum++].vol = vol;
    return 1;
}
static void StartContinousEmitters(void)
{
    int groupIndex;
    START_LIST* node;
    SND_EMITTER* em;
    f32 dv;

    for (groupIndex = 0; groupIndex < startGroupNum; groupIndex++)
    {
        for (node = startGroup[groupIndex].list; node != (START_LIST*)0x0; node = node->next)
        {
            if ((startGroup[groupIndex].running != (RUN_LIST*)0x0) &&
                !((sSnd3dStereo != 0) &&
                  ((startGroup[groupIndex].id & S3D_GROUP_KEY_STEREO_LIMIT) != 0) &&
                  (startGroup[groupIndex].numRunning < startGroup[groupIndex].list->em->maxVoices)))
            {
                dv = node->vol - startGroup[groupIndex].running->vol;
                if (dv <= 0.08f)
                {
                    continue;
                }
                else if (dv <= 0.15f)
                {
                    em = node->em;
                    if (++em->VolLevelCnt < 0x14)
                    {
                        continue;
                    }
                }
                else
                {
                    node->em->VolLevelCnt = 0;
                }
            }

            em = node->em;
            if (((em->room != (SND_ROOM*)0x0) && (em->room->studio == 0xff)) ||
                ((em->vid = synthFXStart(
                      em->fxid, 0x7f, 0x40,
                      (em->room != (SND_ROOM*)0x0) ? em->room->studio : em->studio,
                      (em->flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0)) == S3D_INVALID_FX_HANDLE))
            {
                if ((em->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) == 0)
                {
                    em->flags |= S3D_EMITTER_FLAG_REMOVE;
                    em->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
                continue;
            }

            if ((em->flags & S3D_EMITTER_FLAG_SKIP_FADE_IN) == 0)
            {
                em->flags |= S3D_EMITTER_FLAG_AGE_OUT;
                em->fade = 0.0f;
            }
            else
            {
                em->fade = 1.0f;
            }
            SetFXParameters(em, node->vol, node->xPan, node->yPan, node->zPan,
                                    node->pitch);
            em->flags &= ~S3D_EMITTER_FLAG_PLAYING;
            startGroup[groupIndex].numRunning++;
            if (startGroup[groupIndex].running != (RUN_LIST*)0x0)
            {
                startGroup[groupIndex].running = startGroup[groupIndex].running->next;
            }
        }
    }
}
