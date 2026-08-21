#include "dlls/object_descriptor.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/dll_0047_cameramodepath.h"
#include "main/dll/dll_0049_cameramodecombat.h"
#include "main/dll/dll_004C_cameramodefixed.h"
#include "main/dll/dll_0053_cameramodecloudrunner.h"
#include "main/dll/dll_0056_cameramodearwing.h"
#include "main/dll/dll_0057_cameramodetitle.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "game/objects/object.h"
#include "main/objprint_api.h"
#include "string.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/obj_list.h"
#include "main/obj_query.h"
#include "main/objseq.h"
#include "util/carry.h"
#include "main/mm.h"
#include "main/frame_timing.h"
#include "main/maketex_api.h"
#include "main/maketex_sequence_api.h"
#include "main/maketex_timer_api.h"
#include "main/textrender_api.h"
#include "main/objseq_api.h"
#include "main/fileio.h"
#include "main/audio/stream_api.h"
#include "main/audio/audio_control_api.h"
#include "main/table_file.h"
#include "main/dll/partfx_interface.h"
#include "main/track_dolphin_api.h"
#include "main/asset_load.h"
#include "main/game_timer_control_api.h"
#include "main/vecmath_distance_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/model.h"
#include "main/render_envfx_api.h"
#include "main/render_sequence_api.h"
#include "main/audio/sfx.h"
#include "game/objects/object_setup.h"
#include "main/camera.h"
#include "main/curve.h"
#include "main/game_ui_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objtexture.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/shader_api.h"
#include "main/sky.h"
#include "main/sky_interface.h"
#include "main/dll/player_api.h"
#include "main/dll/player_status.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/pad.h"
#include "main/gamebit_ids.h"
#include "main/mldf_fileid.h"
#include "main/object_transform.h"
#include "main/maketex_yield_api.h"
#include "dolphin/os.h"
#include "main/pi_dolphin_api.h"
#include "main/audio/music_api.h"
#include "main/maketex.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"

typedef struct SeqRunFlags
{
    u8 useWorldSpace : 1;
} SeqRunFlags;

#define OBJSEQ_LINKED_PAIRS_PER_SLOT 16
#define MAKETEX_CAMMODE_NPCSPEAK 0x4d /* cameramode DLL dll_004D_cameramodenpcspeak */
#define MAKETEX_CAMMODE_DEFAULT  0x42 /* default gameplay cameramode DLL */

extern s8 seqGlobal3;
extern int gObjSeqTaskTextId;
extern int gObjSeqDeferredTaskTextId;
extern u8 gObjSeqCameraOverrideActive;
extern f32 gObjSeqCameraOverridePosX;
extern f32 gObjSeqCameraOverridePosY;
extern f32 gObjSeqCameraOverridePosZ;
extern s16 gObjSeqCameraOverrideRotX;
extern s16 gObjSeqCameraOverrideRotY;
extern s16 gObjSeqCameraOverrideRotZ;
extern f32 gObjSeqCameraOverrideW;
extern s16 gObjSeqSlotValues[];
extern GameObject* gObjSeqStartObjOverride;
extern u8 gObjSeqStartOffsetBack;
extern u8 gObjSeqCamPosOverridePending;
extern int gObjSeqSubtitleId;
extern SeqRunFlags gObjSeqRunFlags;
extern u8 gObjSeqPreemptCount;
extern int gObjSeqPreemptList[][2];
extern void* gObjSeqCameraSourceObj;
extern int gObjSeqPreparingStreamSlot;
extern int gObjSeqCamOwnerSeqIndex;
extern int gObjSeqStreamResumeOffset;
extern f32 gObjSeqStreamRemainingTime;
extern int gObjSeqTimedStreamSlot;

void seqClearTaskTexts(void)
{
    u32 v = -0x1;
    gObjSeqTaskTextId = v;
    gObjSeqDeferredTaskTextId = v;
}

void clearCurSeqNo(void)
{
    curSeqNo = 0x0;
}

int getCurSeqNo(void)
{
    return curSeqNo;
}

void ObjSeq_SetCameraTransformOverride(f32 x, f32 y, s16 rx, s16 ry, s16 rz, f32 z, f32 w)
{
    gObjSeqCameraOverrideActive = 1;
    gObjSeqCameraOverridePosX = x;
    gObjSeqCameraOverridePosY = y;
    gObjSeqCameraOverridePosZ = z;
    gObjSeqCameraOverrideRotX = rx;
    gObjSeqCameraOverrideRotY = ry;
    gObjSeqCameraOverrideRotZ = rz;
    gObjSeqCameraOverrideW = w;
}
GameObject* getFocusedNpc(void)
{
    return focusedNpc;
}

void ObjSeq_ClearModelLookVector(GameObject* obj);

/* Starts the prepared audio stream for a sequence slot and records its
 * subtitle timing. */
int ObjSeq_StartPreparedStream(int slot)
{
    int seqId = gObjSeqSlotSeqIdTable[slot] - 1;
    f32 streamTime;

    if (gObjSeqStreamSuppressed != 0 || AudioStream_IsPreparing() != 0)
    {
        return 0;
    }
    streamTime = gObjSeqSlotStreamTimeTable[slot] - (f32)gObjSeqStreamResumeOffset;
    gObjSeqStreamRemainingTime = streamTime;
    if (gObjSeqStreamRemainingTime != 0.0f)
    {
        gObjSeqTimedStreamSlot = slot;
    }
    gObjSeqStreamResumeOffset = -1;
    if (seqId == 0x54b || seqId == 0x550 || seqId == 0x551 || seqId == 0x574 || seqId == 0x579 || seqId == 0x57a)
    {
        gObjSeqStreamRemainingTime = 0.0f;
        gObjSeqTimedStreamSlot = -1;
    }
    gObjSeqPreparingStreamSlot = -1;
    AudioStream_StartPrepared();
    return 1;
}

int animatedObjGetSeqId(ObjSeqState* state)
{
    return gObjSeqSlotSeqIdTable[state->slot] - 1;
}

int ObjSeq_SetSlotValue(ObjSeqState* state, int value)
{
    gObjSeqSlotValues[(s8)state->slot] = (s16)value;
    return 1;
}

void ObjSeq_AudioStreamCallback(void)
{
    AudioStream_IsPreparing();
    AudioStream_Nop(0);
    if (gObjSeqDeferredTaskTextId != -1)
    {
        gameTextLoadTaskText(gObjSeqDeferredTaskTextId);
        gObjSeqDeferredTaskTextId = -1;
        gObjSeqTaskTextId = -1;
    }
    else if (gObjSeqSubtitleId != -1)
    {
        subtitleStop();
        subtitleStart(gObjSeqSubtitleId);
        gObjSeqSubtitleId = -1;
    }
}

int ObjSeq_SetCoordinateSpace(int unused, int space)
{
    switch (space)
    {
    case 0:
        gObjSeqRunFlags.useWorldSpace = 1;
        break;
    case 1:
        gObjSeqRunFlags.useWorldSpace = 0;
        break;
    }
    return 0;
}

int ObjSeq_setOverridePos(f32 x, f32 y, f32 z)
{
    gObjSeqCamPosOverridePending = 1;
    objSeqOverridePos[0] = x;
    objSeqOverridePos[1] = y;
    objSeqOverridePos[2] = z;
    return 1;
}

int ObjSeq_SetObjs(int objs, GameObject* arg, int flags)
{
    u8 flagsByte = (u8)flags;
    objSeqObjs = objs;
    gObjSeqStartObjOverride = arg;
    gObjSeqStartOffsetBack = flagsByte;
    return 1;
}

void cameraFocusNpc(int param1, GameObject* obj)
{
    struct
    {
        f32 vec[3];
        u8 tag;
    } buf;
    ObjHitVolumeRuntimeTransform* hitTransform;

    if ((*gCameraInterface)->getMode() == MAKETEX_CAMMODE_NPCSPEAK)
        return;
    focusedNpc = obj;
    hitTransform = obj->anim.hitVolumeTransforms;
    if (hitTransform == NULL || param1 == 7 || param1 == 6)
    {
        buf.vec[0] = obj->anim.worldPosX;
        buf.vec[1] = obj->anim.worldPosY;
        buf.vec[2] = obj->anim.worldPosZ;
    }
    else
    {
        buf.vec[0] = hitTransform->jointX;
        buf.vec[1] = hitTransform->jointY;
        buf.vec[2] = hitTransform->jointZ;
    }
    buf.tag = (u8)param1;
    (*gCameraInterface)->setMode(MAKETEX_CAMMODE_NPCSPEAK, 1, 0, 0x10, buf.vec, 0, 0xff);
}

void ObjSeq_ClearModelLookVector(GameObject* obj)
{
    s16* v = objFindJointPoseVector(obj, 0);
    if (v != NULL)
    {
        v[1] = 0;
        v[0] = 0;
    }
}

/* Object-sequence turn-to-face-player step: starts (mode 4) or advances
 * (mode 5) a smooth turn of the object toward the player, blending the model
 * vector and animation as it goes. */
int ObjSeq_TurnToFacePlayer(GameObject* obj, ObjSeqState* state, s16 turnDegrees, s16 yawThreshold,
                            s16 maxAngle, s16 animRight, s16 animLeft)
{
    GameObject* player;
    s16* modelVec;
    int yawd;
    s16 turn;
    int mode;
    f32 out;
    f32 delta[3];
    f32 dist;
    f32 rate;
    f32 yaw;

    player = Obj_GetPlayerObject();
    yawThreshold = (s16)(182.04445f * yawThreshold);
    maxAngle = (s16)(182.04445f * maxAngle);
    turnDegrees = (s16)(182.04445f * turnDegrees);
    mode = (s8)state->movementState;
    if (mode == 4)
    {
        state->flags = state->flags & ~2;
        modelVec = objFindJointPoseVector(obj, 0);
        if (modelVec != NULL)
        {
            state->flags = state->flags & ~8;
        }
        state->freeCallback = (ObjAnimSequenceFreeCallback)ObjSeq_ClearModelLookVector;
        state->posOffsetX = 0.0f;
        state->posOffsetY = 0.0f;
        state->posOffsetZ = 0.0f;
        yawd = Obj_GetYawDeltaToObject(obj, player, (float*)0);
        if (((s16)yawd >= 0 ? (s16)yawd : -(s16)yawd) < yawThreshold)
        {
            turn = 0;
        }
        else
        {
            turn = (s16)((s16)yawd > 0 ? (s16)yawd - yawThreshold : (s16)yawd + yawThreshold);
        }
        state->rotOffsetX = turn;
        {
            f32* dp = delta;
            ObjHitVolumeRuntimeTransform* ovr = obj->anim.hitVolumeTransforms;
            if (ovr == NULL)
            {
                dp[0] = player->anim.localPosX - obj->anim.localPosX;
                dp[1] = player->anim.localPosY - obj->anim.localPosY;
                dp[2] = player->anim.localPosZ - obj->anim.localPosZ;
            }
            else
            {
                dp[0] = player->anim.localPosX - ovr->jointX;
                dp[1] = player->anim.localPosY - ovr->jointY;
                dp[2] = player->anim.localPosZ - ovr->jointZ;
            }
            dp[1] += 30.0f;
            dist = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
            state->rotOffsetY = (s16)getAngle(dp[1], dist);
        }
        state->rotOffsetZ = 0;
        state->movementState = 5;
        state->posOffsetScale = 0.0f;
        if (turn != 0)
        {
            rate = (f32)turnDegrees / (f32)turn;
            state->posOffsetDecay = rate >= 0.0f ? rate : -rate;
        }
        else
        {
            state->posOffsetDecay = 1.0f;
        }
        {
            f32 c = state->posOffsetDecay;
            state->posOffsetDecay = c < 0.0f ? 0.0f : (c > 0.25f ? 0.25f : c);
        }
        if (animRight != -1)
        {
            if (animLeft != -1)
            {
                state->flags = state->flags & ~4;
                if (state->rotOffsetX < 0)
                {
                    if (animLeft != -1)
                    {
                        ObjAnim_SetCurrentMove(obj, animLeft, 0.0f, 0);
                    }
                }
                else
                {
                    if (animRight != -1)
                    {
                        ObjAnim_SetCurrentMove(obj, animRight, 0.0f, 0);
                    }
                }
            }
        }
        state->freeCallback = (ObjAnimSequenceFreeCallback)ObjSeq_ClearModelLookVector;
        return 1;
    }
    else if (mode == 5)
    {
        state->posOffsetScale = state->posOffsetScale + state->posOffsetDecay;
        if (state->posOffsetScale > 1.0f)
        {
            state->posOffsetScale = 1.0001f;
        }
        obj->anim.rotX +=
            (s16)(state->posOffsetDecay * (f32)state->rotOffsetX);
        modelVec = objFindJointPoseVector(obj, 0);
        if (modelVec != NULL)
        {
            state->flags = state->flags & ~8;
            yawd = Obj_GetYawDeltaToObject(obj, player, (float*)0);
            yaw = (f32)(s16)yawd;
            {
                f32 cur = (f32)modelVec[1];
                yaw = cur * (1.0f - state->posOffsetScale) + yaw * state->posOffsetScale;
            }
            yaw = (yaw < (f32)-maxAngle) ? (f32)-maxAngle : ((yaw > (f32)maxAngle) ? (f32)maxAngle : yaw);
            modelVec[1] = yaw;
            modelVec[0] = (f32)state->rotOffsetY * state->posOffsetScale;
        }
        if (animRight != -1)
        {
            if (animLeft != -1)
            {
                s16 t50 = state->rotOffsetX;
                f32 fa = (f32)(t50 >= 0 ? t50 : -t50);
                fa = fa * 3.142f / 325767.0f;
                ObjAnim_SampleRootCurvePhase(&obj->anim, fa, &out);
                ObjAnim_AdvanceCurrentMove(obj, out, (f32)framesThisStep, NULL);
            }
        }
        if (state->posOffsetScale > 1.0f)
        {
            state->movementState = 0;
            state->flags = state->flags | 8;
            modelVec = objFindJointPoseVector(obj, 0);
            if (modelVec != NULL)
            {
                state->baseRotY = modelVec[1];
                state->baseRotX = modelVec[0];
            }
            else
            {
                state->baseRotY = 0;
                state->baseRotX = 0;
            }
            if (state->posOffsetScale > 1.0f)
            {
                state->flags = state->flags | 4;
            }
        }
        return 1;
    }
    return 0;
}


/* Shell sort over (key, val) pairs, ascending by key. */
void ObjSeq_setGlobal2(s16 x)
{
    seqGlobal2 = x;
}
s16 ObjSeq_getGlobal2(void)
{
    return seqGlobal2;
}
void ObjSeq_setGlobal1(s16 x)
{
    seqGlobal1 = x;
}
s16 ObjSeq_getGlobal1(void)
{
    return seqGlobal1;
}
void ObjSeq_setGlobal3(s8 x)
{
    seqGlobal3 = x;
}

u8 ObjSeq_getGlobal3(void)
{
    return seqGlobal3;
}

void ObjSeq_yield(ObjSeqState* seq, int value)
{
    seq->savedFrame = value;
    seq->sequenceControlFlags |= OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME;
}

void ObjSeq_preempt(int key, int value)
{
    u8 count = gObjSeqPreemptCount;
    int i = (s8)count;
    if (i >= 40)
        return;
    gObjSeqPreemptList[i][0] = key;
    gObjSeqPreemptList[i][1] = value;
    gObjSeqPreemptCount++;
}

void endObjSequence(int seq)
{
    int j;
    int objCount;
    int objIdx;
    GameObject* frees[32];
    GameObject** objs;
    int i;
    int nFree;
    GameObject** ret;

    ret = ObjList_GetObjects(&objIdx, &objCount);
    nFree = 0;
    i = 0;
    objs = ret;
    for (; i < objCount; i++)
    {
        GameObject* obj = *objs;
        if (obj->seqIndex == seq)
        {
            obj->seqIndex = -1;
        }
        if (obj->anim.classId == 0x10)
        {
            ObjSeqState* st = (ObjSeqState*)obj->extra;
            if ((s8)st->slot == seq)
            {
                if (obj == gObjSeqCameraSourceObj)
                {
                    gObjSeqCameraSourceObj = 0;
                }
                frees[nFree++] = obj;
                if (st->freeCallback != NULL)
                {
                    (*(void (**)(void*, GameObject*, ObjSeqState*))&st->freeCallback)(st->callbackContext, obj, st);
                    st->freeCallback = NULL;
                }
                if (nFree == 0x10)
                {
                    debugPrintf(sEndObjSequenceMaxFreesError);
                }
            }
        }
        objs++;
    }
    if (curSeqNo == seq)
    {
        curSeqNo = 0;
        Pause_ResetMenuFrameCounter();
    }
    if (seq == gObjSeqPreparingStreamSlot)
    {
        AudioStream_CancelPrepared();
        gObjSeqPreparingStreamSlot = -1;
    }
    for (j = 0; j < nFree; j++)
    {
        Obj_FreeObject(frees[j]);
    }
    if (seq == gObjSeqCamOwnerSeqIndex)
    {
        if ((*gCameraInterface)->getMode() == MAKETEX_CAMMODE_NPCSPEAK)
        {
            (*gCameraInterface)->setMode(MAKETEX_CAMMODE_DEFAULT, 0, 3, 0, NULL, 0, 0);
            gObjSeqCamOwnerSeqIndex = 0;
            curSeqNo = 0;
            Pause_ResetMenuFrameCounter();
        }
    }
    gObjSeqStartObjOverride = 0;
    gObjSeqSlotSeqIdTable[seq] = 0;
}

f32 gObjSeqCameraFov = 60.0f;
int gObjSeqTaskTextId = -1;
int gObjSeqSubtitleId = -1;
int gObjSeqDeferredTaskTextId = -1;
int gObjSeqPreparingStreamSlot = -1;
int gObjSeqTimedStreamSlot = -1;
int gObjSeqStreamResumeOffset = -1;
int objSeqObjs = -1;
f32 gObjSeqShakeAmplitude = 0.2f;
char sSeqAAnimDataTag[] = "SEQA";
char sSeqBAnimDataTag[] = "SEQB";
int lbl_803DB744[1] = {0};
GXColor gObjSeqDefaultColor = {0x20, 0x20, 0x20, 0xFF};
int lbl_803DB74C[1] = {0};

typedef struct ObjSeqBgRotationCmd
{
    s16 index;
    s16 xrot;
    s16 yrot;
} ObjSeqBgRotationCmd;

typedef struct ObjSeqBgCmd
{
    GameObject* object;
    s16 param;
    union
    {
        struct
        {
            s8 opcode;
            s8 pad;
        };
        s16 flags;
    };
} ObjSeqBgCmd;

typedef struct ObjSeqPendingCmd0B
{
    u8* cmd;
    s16 reps;
    s16 frame;
} ObjSeqPendingCmd0B;

typedef struct RomCurveNode
{
    u8 pad00[0x08];
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[0x07];
    s8 directionMask;
    s32 links[4];
    s8 yaw;
    s8 pitch;
    u8 tangentScale;
} RomCurveNode;

typedef struct RomCurveInterpState
{
    s32 fromNodeId;
    s32 toNodeId;
    union
    {
        struct
        {
            f32 fromTime;
            f32 segmentTime1;
            f32 segmentTime2;
            f32 segmentTime3;
            f32 segmentTime4;
            f32 segmentTime5;
            f32 segmentTime6;
            f32 segmentTime7;
            f32 toTime;
        };
        f32 segmentTimes[9];
    };
} RomCurveInterpState;

#define ROM_CURVE_NODE_ANGLE(v)    ((3.1415927f * (f32)((s32)(v) << 8)) / 32768.0f)
#define ROM_CURVE_NODE_SCALE(node) (2.0f * (f32)(u8)((node)->tangentScale))

typedef struct ObjCurveKey
{
    f32 value;
    s8 tangentAndMode;
    u8 pad05;
    s16 frame;
} ObjCurveKey;

typedef struct ObjSeqPlacement
{
    u8 pad00[8];
    f32 baseX;
    f32 groundOffset;
    f32 baseZ;
    u8 pad14[8];
    s16 targetType;
    u8 pad1E;
    s8 slot;
} ObjSeqPlacement;

typedef struct ObjSeqAnimPlacement
{
    ObjPlacement base;
    s16 animDataIndex;
    s16 sequenceGameBit;
    s16 targetType;
    u8 pad1E;
    s8 slot;
    u8 unk20;
    u8 unk21;
    s8 startOnLoad;
    u8 pad23;
    u8 positionDamping;
    u8 pad25[3];
} ObjSeqAnimPlacement;

typedef struct ObjSeqAnimDataHeader
{
    char tag[4];
    s16 dataSize;
    s16 commandCount;
} ObjSeqAnimDataHeader;

typedef struct ObjSeqAnimLookup
{
    s16 baseAnimId;
} ObjSeqAnimLookup;

typedef struct ObjSeqStreamMapEntry
{
    int trackId;
    u32* streamIds;
} ObjSeqStreamMapEntry;

#define OBJSEQ_STREAM_MAP_COUNT 5

STATIC_ASSERT(sizeof(ObjSeqStreamMapEntry) == 8);

STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, animDataIndex) == 0x18);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, sequenceGameBit) == 0x1A);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, targetType) == 0x1C);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, slot) == 0x1F);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, unk20) == 0x20);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, unk21) == 0x21);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, startOnLoad) == 0x22);
STATIC_ASSERT(offsetof(ObjSeqAnimPlacement, positionDamping) == 0x24);
STATIC_ASSERT(sizeof(ObjSeqAnimPlacement) == 0x28);
STATIC_ASSERT(sizeof(ObjSeqAnimDataHeader) == 8);

extern int ObjSeq_EvaluateCondition(int condition, u8* seq, void* obj);
extern void ObjSeq_ApplyFrameCurves(GameObject* obj, GameObject* seqObj, u8* seq, int frame);
extern void ObjSeq_RebuildCurveStateToFrame(GameObject* obj, GameObject* seqObj, u8* seq, int mode);
extern void ObjSeq_ApplyLinkedObjectTransform(GameObject* obj, GameObject* seqObj, u8* seq);
extern void animatedObjFreeAndSavePlayerPos(GameObject* obj, GameObject* seqObj, u8* seq);
extern ObjSeqBgRotationCmd gObjSeqBgCmds[];
extern u8 objSeqXrotChanged[];
extern s16 objSeqXrotValues[];
extern s8 gObjSeqBoolFlags[];
extern s8 gObjSeqCondFlags[];
extern s8 gObjSeqSlotResults[];
extern ObjSeqBgCmd gObjSeqDeferredCmds[];
extern u8 gObjSeqRuntimeBuffer[];
void ObjSeq_setCamVars(int camA, int camB, int camC, int camD);
int objSeqFindLabel(u8* seq, int label);
int objSeqFindConditional(u8* seq, GameObject* seqState);
void objCallSeqFn(GameObject* obj, GameObject* sourceObj, ObjSeqState* seq, int action);
void objSeqDoBgCmds0D(u8* seq, GameObject* obj, int skipSpawns);
void ObjSeq_SetupInitialPlaybackState(GameObject* obj, GameObject** seqObj, u8* seq, ObjSeqPlacement* placement, void** outAction);
void ObjSeq_setXrot(int index, int xrot);
int ObjSeq_getBool(int index);
void ObjSeq_setBool(int index, int value);
void ObjSeq_addBgCmd(int index, int xrot, int yrot);
void ObjSeq_seqState_free(u8* seq);
void ObjSeq_seqState_init(u8* seq);
void* ObjSeq_FindTargetObject(GameObject* obj);
void ObjSeq_RefreshActionCursor(void* obj, void* seqFile, u8* seq);
void ObjSeq_onMapSetup(void);

void ObjSeq_release(void);
void ObjSeq_initialise(void);
void RomCurveInterp_BuildSegmentTimeTable(RomCurveInterpState* out, RomCurveNode* curve, RomCurveNode* next, f32 t,
                                          int flag);
void RomCurveInterp_UpdateSegmentWindow(RomCurveInterpState* state, f32 t);
void RomCurveInterp_InitFromNode(RomCurveInterpState* out, int id);
int RomCurveInterp_EvaluateOffsetPosition(RomCurveInterpState* state, f32* offset, f32* outPos, s16* outAngle,
                                          int ignoreY);
f32 objCurveInterpolate(ObjCurveKey* keys, int count, int frame);

/* Camera mode ids passed to gCameraInterface->setMode; each == cameramode DLL number. */
/* placement stand-in spawned for missing seq actors; retail OBJECTS.bin name
   "Override" (DLL 0xC6) */
#define OBJSEQ_OVERRIDE_OBJ 0x6
/* retail OBJECTS.bin name "VariableObj" (DLL 0xC6) */
#define OBJSEQ_VARIABLE_OBJ 0x443
/* seq actor that carries the cutscene camera; retail OBJECTS.bin name
   "AnimCamera" (DLL 0xC6) */
#define OBJSEQ_ANIMCAMERA_OBJ 0x1e

/* playable-character placement ids; a seq actor carrying either one drives the
   live player object instead of spawning its own. retail OBJECTS.bin names
   "Sabre" and "Krystal" (no owning DLL) */
#define OBJSEQ_SABRE_OBJ   0x0
#define OBJSEQ_KRYSTAL_OBJ 0x1f

#define OBJSEQ_CAMMODE_DEFAULT      0x42 /* default gameplay cameramode DLL */
#define OBJSEQ_CAMMODE_CAMTALK      0x45 /* dll_0045_camTalk */
#define OBJSEQ_CAMMODE_STATIC       0x48 /* dll_0048_cameramodestatic */
#define OBJSEQ_CAMMODE_SHIPBATTLE   0x4a /* dll_004A_cameramodeshipbattle */
#define OBJSEQ_CAMMODE_FIXED        0x4c /* dll_004C_cameramodefixed */

extern char sObjLoadAnimdataNullACRomTabWarning[];

/* GameCube controller button masks */
#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200

/* player-target group; its first object is used as the camera focus target */
#define OBJSEQ_TARGET_OBJGROUP 0xf

/* GameObject::objectFlags bit: object is bound to an active sequence (set when
   it becomes a seq callback target, cleared on release; tested elsewhere as the
   "under sequence control / blocked from normal update" gate). */
#define OBJECT_OBJFLAG_SEQ_ATTACHED 0x1000

/* Env-effect ids co-activated by seq opcodes 48/50 (A set) and 49 (B set);
   opaque distinct roles per index. */
#define OBJSEQ_ENVFX_A0 0x134
#define OBJSEQ_ENVFX_A1 0x135
#define OBJSEQ_ENVFX_A2 0x142
#define OBJSEQ_ENVFX_B0 0x136
#define OBJSEQ_ENVFX_B1 0x137
#define OBJSEQ_ENVFX_B2 0x143

extern u8 lbl_80399E50[];
extern char sObjSequenceMissingObjectFormat[];
extern s8 gObjSeqJumpLatch[];
int objSeqExecCmd06(GameObject* obj, GameObject* sourceObj, u8* seq, int cmd, s8 flag);

extern ObjSeqBgCmd lbl_8039944C[];
int ObjSeq_ExecuteActionCommand(GameObject* obj, u8* action, u8** cmd, s8 flags, void* out);
void* ObjSeq_ToggleCommand3Target(GameObject* obj, u8* seq, ObjSeqPlacement* placement);

typedef struct CamMode
{
    int mode;
    u8 flag;
} CamMode;

int ObjSeq_update(GameObject* obj, f32 t);

u8 gObjSeqPreemptCount;
f32 gObjSeqLinkedSavedPosX;
f32 gObjSeqLinkedSavedPosY;
f32 gObjSeqLinkedSavedPosZ;
s16 gObjSeqLinkedSavedPitch;
u8 gObjSeqLinkedTransformValid;
s8 gObjSeqDeferredCmdCount;
u8 gObjSeqSkippingToEnd;
u8 lbl_803DD111;
u8 gObjSeqCameraActive;
int gObjSeqCamMode;
int gObjSeqCamModeArgB;
int gObjSeqCamModeArgC;
int gObjSeqCamModeArgD;
GameObject* focusedNpc;
u8 gObjSeqCameraOverrideActive;
f32 gObjSeqCameraOverridePosX;
f32 gObjSeqCameraOverridePosY;
f32 gObjSeqCameraOverridePosZ;
s16 gObjSeqCameraOverrideRotX;
s16 gObjSeqCameraOverrideRotY;
s16 gObjSeqCameraOverrideRotZ;
f32 gObjSeqCameraOverrideW;
f32 lbl_803DD0DC;
u8 gObjSeqStop;
u8 gObjSeqCamPosOverridePending;
u8 gObjSeqFnDispatched;
ObjSeqAnimLookup* gObjSeqAnimLookup;
f32 gObjSeqFovOverrideValue;
f32 gObjSeqCurvePosOffsetX;
f32 gObjSeqCurvePosOffsetY;
f32 gObjSeqCurvePosOffsetZ;
int gObjSeqPendingCmd0BCount;
s8 gObjSeqBgCmdCount;
void* gObjSeqCameraSourceObj;
u16 lbl_803DD0B6;
SeqRunFlags gObjSeqRunFlags;
f32 gObjSeqSavedCamPosX;
f32 gObjSeqSavedCamPosY;
f32 gObjSeqSavedCamPosZ;
f32 gObjSeqSavedCamFov;
int gObjSeqSavedCamPitch;
int gObjSeqSavedCamYaw;
int gObjSeqSavedCamRoll;
int gObjSeqStreamSuppressed;
int gObjSeqInputOverrideActive;
u8 curSeqNo;
s16 lbl_803DD08A;
u8 gObjSeqFovOverrideActive;
int seqGlobal4;
s8 seqGlobal3;
GameObject* gObjSeqStartObjOverride;
u8 gObjSeqStartOffsetBack;
f32 gObjSeqStreamRemainingTime;
s16 gObjSeqStreamStopped;
s16 seqGlobal2;
s16 seqGlobal1;
u32 gObjSeqCurrentTrackId;
int gObjSeqCamOwnerSeqIndex;
s16 lbl_803DD062;
s16 lbl_803DD060;
typedef struct SeqRunRec
{
    s16 slot;
    s16 flags;
    s16 count;
} SeqRunRec;

typedef struct SeqRunTables
{
    u8 pad0[0x2a80];
    SeqRunRec recs[0x1e];
    u8 pad1[0x800];
    u8 marks[0xb0];
    int handles[0x55];
    u8 cmdFlags[0x58];
    u8 counts[0x58];
    s16 headings[0x55];
    u8 pad2[0xae];
    f32 dists[0x55];
    f32 frames[0x55];
    u8 pad3[0xb0];
    s16 modes[0x55];
} SeqRunTables;

typedef struct ObjSeqQueuedBgCmd
{
    s16 index;
    s16 xrot;
    s16 yrot;
} ObjSeqQueuedBgCmd;

typedef struct ObjSeqRunBgState
{
    u8 pad0000[0x2A80];
    ObjSeqQueuedBgCmd queuedCmds[0x1E];
    u8 pad2B34[0x338C - 0x2B34];
    u8 slotMarks[0x55];
    u8 pad33E1[0x3740 - 0x33E1];
    f32 slotDistances[0x55];
    f32 previousSlotDistances[0x55];
    s8 pendingFrames[0x55];
    u8 pad3A3D[3];
    u8 slotStates[0x55];
    u8 pad3A95[0x3B44 - 0x3A95];
    s8 boolFlags[0x58];
    s8 conditionFlags[0x58];
    u8 slotResults[0x58];
    u8 previousSlotResults[0x58];
} ObjSeqRunBgState;

STATIC_ASSERT(offsetof(ObjSeqRunBgState, slotMarks) == 0x338C);
STATIC_ASSERT(offsetof(ObjSeqRunBgState, pendingFrames) == 0x39E8);
STATIC_ASSERT(offsetof(ObjSeqRunBgState, boolFlags) == 0x3B44);
STATIC_ASSERT(offsetof(ObjSeqRunBgState, slotResults) == 0x3BF4);

void RomCurveInterp_BuildSegmentTimeTable(RomCurveInterpState* out, RomCurveNode* curve, RomCurveNode* next, f32 t,
                                          int flag);
int RomCurveInterp_EvaluateOffsetPosition(RomCurveInterpState* state, f32* offset, f32* outPos, s16* outAngle,
                                          int ignoreY);


static inline u8* ObjSeq_GetActiveModel(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

typedef struct ObjSeqPreemptEntry
{
    GameObject* obj;
    int flags;
} ObjSeqPreemptEntry;

typedef struct ObjSeqLinkedPair
{
    GameObject* seqObj;
    GameObject* ownerObj;
} ObjSeqLinkedPair;

typedef struct ObjSeqCastEntry
{
    s32 targetObjId;
    u16 flags;
    u16 objId;
} ObjSeqCastEntry;

static inline int objSeqIsObjMonitored(ObjSeqPreemptEntry* walk, GameObject* obj)
{
    int i;
    int n;

    n = (s8)gObjSeqPreemptCount;
    for (i = 0; i < n; i++)
    {
        if (walk->obj == obj)
        {
            return 1;
        }
        walk++;
    }
    return 0;
}

static inline int objSeqRemoveMonitoredObj(u8* base, ObjSeqPreemptEntry** monp, GameObject* obj)
{
    int v;
    int j;
    int k;
    int n;
    int flags;
    ObjSeqPreemptEntry* p;

    n = (s8)gObjSeqPreemptCount;
    for (j = 0; j < n; j++)
    {
        if ((*monp)->obj == obj)
        {
            flags = *(int*)(base + j * 8 + 0x3d50);
            gObjSeqPreemptCount -= 1;
            p = (ObjSeqPreemptEntry*)(base + j * 8 + 0x3d4c);
            for (k = j; k < (s8)gObjSeqPreemptCount; k++)
            {
                v = (int)p[1].obj;
                p->obj = (GameObject*)v;
                p->flags = v;
                p++;
            }
            return flags;
        }
        (*monp)++;
    }
    return 0;
}

int ObjSeq_start(int seqIdx, GameObject* obj, int flags)
{
    u8* base;
    SeqRunTables* st;
    ObjSeqCastEntry* walk2;
    ObjSeqCastEntry* walk;
    int packed;
    ObjSeqPreemptEntry* mon;
    int i;
    int idx;
    int count;
    int first;
    int bit;
    int objId;
    int slot;
    u8* hdr;
    GameObject* parent;
    u8* srcSeq;
    ObjSeqAnimPlacement* setup;
    ObjSeqState* seq;
    int size;
    s16 heading;
    int camArg;
    GameObject* player;
    int doCam;
    GameObject* newObj;
    s16* slotPtr;
    u8* buf;
    ObjSeqLinkedPair* blk;
    u8* p;
    s16* mapTbl;
    int j;
    int seqFlags;
    int found;
    int cur;
    s16 val;
    u32 objIdU;
    u32 mapFlags;
    u32 trackId;
    f32 x;
    f32 y;
    f32 z;

    base = gObjSeqRuntimeBuffer;
    st = (SeqRunTables*)base;
    srcSeq = (u8*)obj->anim.placementData;
    camArg = 0;
    doCam = 0;
    player = Obj_GetPlayerObject();

    if (seqIdx == -1)
    {
        return -1;
    }
    if (seqIdx < 0 || seqIdx >= obj->anim.modelInstance->sequenceCount)
    {
        return -1;
    }

    for (i = 0x19; i < 0x55; i++)
    {
        p = base + i * 2;
        p = (u8*)((int)p + 0x3a98);
        if (*(s16*)p == 0)
        {
            slot = i;
            *(s16*)p = 1;
            blk = (ObjSeqLinkedPair*)(base + i * 0x80);
            for (j = 0; j < OBJSEQ_LINKED_PAIRS_PER_SLOT; j++)
            {
                blk->seqObj = NULL;
                blk++;
            }
            i = 0x56;
        }
    }
    if (i == 0x55)
    {
        return -1;
    }

    mapTbl = obj->anim.modelInstance->sequenceMap;
    if (mapTbl != NULL)
    {
        seqIdx = mapTbl[seqIdx];
    }

    cur = obj->seqIndex;
    if (cur != -1 && gObjSeqStartObjOverride == NULL)
    {
        endObjSequence(cur);
    }

    val = seqIdx + 1;
    *(slotPtr = (s16*)(base + 0x3a98) + slot) = val;
    gObjSeqTaskTextId = -1;
    gObjSeqSubtitleId = -1;

    mon = (ObjSeqPreemptEntry*)(base + 0x3d4c);
    found = objSeqIsObjMonitored(mon, obj);
    if (found == 0)
    {
        gObjSeqTaskTextId = seqIdx;
    }

    hdr = mmAlloc(0x20, 0x11, 0);
    getTabEntry(hdr, MLDF_FILEID_OBJSEQ_TAB, seqIdx * 2, 8);
    first = *(s16*)hdr;
    count = ((s16*)hdr)[1] - first;
    size = count << 3;
    buf = mmAlloc(size, 0x11, 0);
    getTabEntry(buf, MLDF_FILEID_OBJSEQ_BIN, first * 8, size);
    mm_free(hdr);

    if (gObjSeqStartObjOverride != NULL)
    {
        obj = gObjSeqStartObjOverride;
    }
    obj->seqIndex = slot;
    parent = obj->anim.parent;
    x = obj->anim.localPosX;
    y = obj->anim.localPosY;
    z = obj->anim.localPosZ;
    if (gObjSeqRunFlags.useWorldSpace)
    {
        parent = NULL;
        x = obj->anim.worldPosX;
        y = obj->anim.worldPosY;
        z = obj->anim.worldPosZ;
    }
    heading = obj->anim.rotX;
    if (gObjSeqStartOffsetBack != 0)
    {
        x -= obj->anim.rootMotionScale *
             (obj->anim.hitboxScale * mathSinf((3.1415927f * (f32)obj->anim.rotX) / 32768.0f));
        z -= obj->anim.rootMotionScale *
             (obj->anim.hitboxScale * mathCosf((3.1415927f * (f32)obj->anim.rotX) / 32768.0f));
    }

    i = 0;
    st->cmdFlags[obj->seqIndex] = 0;
    base[obj->seqIndex + 0x3334] = 0;
    gObjSeqSlotValues[obj->seqIndex] = 0;
    *(int*)((u8*)&st->handles[0] + obj->seqIndex * 4) = obj->anim.romDefNo;

    walk = (ObjSeqCastEntry*)buf;
    bit = 1;
    for (; i < count; i++)
    {
        if ((flags & (bit << i)) && (walk->flags & 0x4000))
        {
            objIdU = walk->objId;
            if (objIdU == OBJSEQ_KRYSTAL_OBJ || objIdU == OBJSEQ_SABRE_OBJ)
            {
                if (playerStatusIsPositive(Obj_GetPlayerObject()) == 0)
                {
                    return -1;
                }
            }
        }
        walk++;
    }

    idx = 0;
    walk2 = (ObjSeqCastEntry*)buf;
    packed = ((seqIdx & 0x7ff) << 4) | 0x8000;
    for (; idx < count; idx++)
    {
        if (flags & (1 << idx))
        {
            setup = (ObjSeqAnimPlacement*)Obj_AllocObjectSetup(0x28, OBJSEQ_OVERRIDE_OBJ);
            objId = walk2->objId;
            if (objId == OBJSEQ_KRYSTAL_OBJ || objId == OBJSEQ_SABRE_OBJ)
            {
                GameObject* pp = Obj_GetPlayerObject();
                pp->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
            }
            if (objId == 0xffff)
            {
                setup->base.objectId = OBJSEQ_OVERRIDE_OBJ;
                setup->targetType = obj->anim.romDefNo + 4;
                if (obj->anim.romDefNo == OBJSEQ_VARIABLE_OBJ && objSeqObjs != -1)
                {
                    setup->targetType = objSeqObjs + 4;
                }
                walk2->flags |= 0x8000;
            }
            else if (objId == 0xfffe)
            {
                setup->base.objectId = OBJSEQ_ANIMCAMERA_OBJ;
                setup->targetType = 3;
                curSeqNo = slot;
            }
            else
            {
                if (walk2->flags & 0x4000)
                {
                    setup->base.objectId = OBJSEQ_OVERRIDE_OBJ;
                    if (objId == OBJSEQ_VARIABLE_OBJ)
                    {
                        if (objSeqObjs != -1)
                        {
                            setup->targetType = objSeqObjs + 4;
                        }
                        else
                        {
                            setup->targetType = objId + 4;
                        }
                    }
                    else
                    {
                        setup->targetType = objId + 4;
                    }
                }
                else
                {
                    setup->base.objectId = objId;
                    setup->targetType = 0;
                }
            }
            if (walk2->flags & 0x8000)
            {
                setup->unk20 = 0;
                setup->unk21 = 0;
            }
            else
            {
                setup->unk20 = 1;
                setup->unk21 = 1;
            }
            if (idx == 0 && (walk2->flags & 0x1000) && player != NULL)
            {
                playerSetOverrideParentSlack(player);
            }
            setup->animDataIndex = packed | (idx & 0xf);
            setup->sequenceGameBit = -1;
            if (idx != 0)
            {
                if (gObjSeqCamPosOverridePending != 0 && setup->base.objectId == OBJSEQ_ANIMCAMERA_OBJ)
                {
                    setup->base.posX = x + *(f32*)(base + 0x2bd4);
                    setup->base.posY = y + *(f32*)(base + 0x2bd8);
                    setup->base.posZ = z + *(f32*)(base + 0x2bdc);
                    gObjSeqCamPosOverridePending = 0;
                }
                else
                {
                    setup->base.posX = x;
                    setup->base.posY = y;
                    setup->base.posZ = z;
                }
            }
            else
            {
                setup->base.posX = obj->anim.localPosX;
                setup->base.posY = obj->anim.localPosY;
                setup->base.posZ = obj->anim.localPosZ;
            }
            setup->slot = slot;
            setup->startOnLoad = 1;
            setup->positionDamping = (walk2->flags & 0xf00) >> 8;
            setup->base.color[0] = 2;
            setup->base.color[1] = 1;
            if (srcSeq != NULL)
            {
                setup->base.color[1] = setup->base.color[1] | (srcSeq[5] & 0x18);
            }
            if (setup->base.objectId == OBJSEQ_ANIMCAMERA_OBJ)
            {
                setup->base.color[0] = 1;
            }
            if (setup->base.objectId == OBJSEQ_VARIABLE_OBJ && objSeqObjs != -1)
            {
                setup->base.objectId = objSeqObjs;
            }
            newObj = objSetupObject(&setup->base, 5, -1, -1, parent);
            newObj->seqIndex = -2;
            seq = newObj->extra;
            seq->heading = heading;
            seq->flags = -1;
            seq->flags = seq->flags & ~0x400;
            seq->conditionOpcodes[0] = 0;
            seq->conditionOpcodes[1] = 0;
            seq->conditionOpcodes[2] = 0;
            seq->conditionOpcodes[3] = 0;
            if (walk2->flags & 1)
            {
                seq->flags = seq->flags & ~1;
            }
            if (walk2->flags & 2)
            {
                seq->flags = seq->flags & ~2;
            }
            if (walk2->flags & 4)
            {
                seq->heading = 0;
            }
            if (walk2->flags & 8)
            {
                seq->flags = seq->flags & ~0x100;
            }
            if (walk2->flags & 0x80)
            {
                seq->stateFlags = seq->stateFlags | 4;
            }
            if (walk2->flags & 0x40)
            {
                seq->stateFlags = seq->stateFlags | 2;
            }
            if (walk2->flags & 0x2000)
            {
                if (idx == 0 && player != NULL)
                {
                    playerSetCutsceneCameraFlag(player);
                }
                if (gObjSeqCamOwnerSeqIndex == 0 || gObjSeqCamOwnerSeqIndex == obj->seqIndex)
                {
                    gObjSeqCamOwnerSeqIndex = obj->seqIndex;
                    curSeqNo = slot;
                }
                seq->movementState = 4;
                if (camArg == 0)
                {
                    camArg = walk2->flags & 0xf00;
                    camArg >>= 8;
                }
                doCam = 1;
            }
            else
            {
                seq->movementState = -1;
            }
            if ((objId == OBJSEQ_KRYSTAL_OBJ || objId == OBJSEQ_SABRE_OBJ) && (seq->flags & 1))
            {
                playerSetInCutscene(player);
            }
            seq->targetObjId = walk2->targetObjId;
            seq->savedFlags = seq->flags;
            if (idx == 0)
            {
                *(u8*)((u8*)&st->cmdFlags[0] + obj->seqIndex) = walk2->flags;
                *(int*)((u8*)&st->handles[0] + obj->seqIndex * 4) =
                    ((ObjPlacement*)newObj->anim.placementData)->ident;
                mapFlags = obj->anim.modelInstance->flags;
                if ((mapFlags & OBJDEF_FLAG_HITBOX_GROUP) && !(mapFlags & OBJDEF_FLAG_CAN_HOLD_PLAYER))
                {
                    parent = obj;
                    z = y = x = 0.0f;
                    heading = 0;
                }
            }
        }
        walk2++;
    }

    st->headings[obj->seqIndex] = heading;
    base[obj->seqIndex + 0x3590] = 0;
    base[obj->seqIndex + 0x338c] = 0;
    seqFlags = objSeqRemoveMonitoredObj(base, &mon, obj);
    if (seqFlags != 0)
    {
        st->cmdFlags[obj->seqIndex] |= 0x10;
    }
    else
    {
        gObjSeqStreamStopped = 0;
        trackId = (u32)(*slotPtr - 1) & 0x3fff;
        gObjSeqCurrentTrackId = trackId;
        if (AudioStream_Play(trackId, ObjSeq_AudioStreamCallback) == 0)
        {
            if (gObjSeqTaskTextId != -1)
            {
                gameTextLoadTaskText(gObjSeqTaskTextId);
                gObjSeqTaskTextId = -1;
            }
        }
        else
        {
            gObjSeqPreparingStreamSlot = slot;
            gObjSeqDeferredTaskTextId = gObjSeqTaskTextId;
            gObjSeqTimedStreamSlot = -1;
            gObjSeqStreamRemainingTime = 0.0f;
            gObjSeqStreamResumeOffset = -1;
        }
    }

    st->dists[obj->seqIndex] = seqFlags;
    st->frames[obj->seqIndex] = seqFlags;

    if (slot >= 0 && slot < 0x55)
    {
        if (gObjSeqBgCmdCount < 0x1e)
        {
            st->recs[gObjSeqBgCmdCount].slot = slot;
            st->recs[gObjSeqBgCmdCount].count = count;
            st->recs[gObjSeqBgCmdCount++].flags = seqFlags;
        }
    }

    if (doCam != 0)
    {
        cameraFocusNpc(camArg, obj);
    }
    mm_free(buf);
    gObjSeqStartOffsetBack = 0;
    gObjSeqRunFlags.useWorldSpace = 0;
    return slot;
}


void ObjSeq_func13(void)
{
}


int ObjSeq_func12(void)
{
    return 0;
}

int ObjSeq_func0E(void)
{
    return 0;
}

void ObjSeq_setGlobal4(int value)
{
    seqGlobal4 = value;
}

int ObjSeq_getGlobal4(void)
{
    return seqGlobal4;
}

int ObjSeq_func0F(void)
{
    return 1;
}

static inline GameObject* objSeqFindLinkedObject(u8* seqObj, GameObject* candidate)
{
    ObjSeqLinkedPair* slotBase;
    ObjSeqLinkedPair* entry;
    int j;

    j = 0;
    slotBase = (ObjSeqLinkedPair*)(gObjSeqRuntimeBuffer + ((ObjSeqState*)seqObj)->slot * 0x80);
    entry = slotBase;
    for (; j < OBJSEQ_LINKED_PAIRS_PER_SLOT; j++)
    {
        if (entry->seqObj == candidate)
        {
            return slotBase[j].ownerObj;
        }
        entry++;
    }
    return NULL;
}

int ObjSeq_resolveTargetObject(GameObject* obj)
{
    int objectCount;
    int unused;
    void** objects;
    u8* seqObj;
    ObjSeqPlacement* model;
    GameObject* found;
    GameObject* candidate;
    int objType;
    int i;
    GameObject* linked;
    f32 bestDist;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;

    objects = (void**)ObjList_GetObjects(&unused, &objectCount);
    seqObj = obj->extra;
    model = (ObjSeqPlacement*)obj->anim.placementData;
    if (obj->anim.classId == 0x11)
    {
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        return -1;
    }

    switch (model->targetType)
    {
    case 0:
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        break;
    case 1:
        ((ObjSeqState*)seqObj)->targetObj = Obj_GetPlayerObject();
        break;
    case 2:
        ((ObjSeqState*)seqObj)->targetObj = getTrickyObject();
        break;
    case 3:
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        ((ObjSeqState*)seqObj)->isCameraSeq = (s8)(model->targetType - 2);
        if (gObjSeqCamOwnerSeqIndex != 0)
        {
            gObjSeqCamOwnerSeqIndex = 0;
        }
        if ((lbl_80399E50[((ObjSeqState*)seqObj)->slot] & 0x10) == 0)
        {
            (*gCameraInterface)->setLetterbox(0x41, 1);
        }
        break;
    default:
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        objType = model->targetType - 4;
        if (objType == OBJSEQ_KRYSTAL_OBJ || objType == OBJSEQ_SABRE_OBJ)
        {
            ((ObjSeqState*)seqObj)->targetObj = Obj_GetPlayerObject();
        }
        else if (((ObjSeqState*)seqObj)->targetObjId != 0)
        {
            ((ObjSeqState*)seqObj)->targetObj = ObjList_FindObjectById(((ObjSeqState*)seqObj)->targetObjId);
        }
        else
        {
            bestDist = -1.0f;
            for (i = 0; i < objectCount; i++)
            {
                candidate = objects[i];
                linked = objSeqFindLinkedObject(seqObj, candidate);
                if (linked == obj)
                {
                    ((ObjSeqState*)seqObj)->targetObj = candidate;
                    break;
                }
                if (linked == NULL)
                {
                    if (candidate->anim.romDefNo == objType)
                    {
                        dx = obj->anim.localPosX - candidate->anim.localPosX;
                        dy = obj->anim.localPosY - candidate->anim.localPosY;
                        dz = obj->anim.localPosZ - candidate->anim.localPosZ;
                        distSq = dx * dx + dy * dy + dz * dz;
                        if (bestDist < 0.0f || distSq < bestDist)
                        {
                            bestDist = distSq;
                            ((ObjSeqState*)seqObj)->targetObj = candidate;
                        }
                    }
                }
            }
        }
        break;
    }

    found = *(GameObject**)seqObj;
    if (found != NULL)
    {
        if (((ObjSeqState*)seqObj)->slot < 0x19)
        {
            if (found->seqIndex != -1)
            {
                endObjSequence(found->seqIndex);
            }
        }
        return (*(GameObject**)seqObj)->anim.defId;
    }
    return -1;
}

void* ObjSeq_FindTargetObject(GameObject* obj)
{
    int objectCount;
    int unused;
    void** objects;
    int targetId;
    int objectType;
    GameObject* candidate;
    void* bestObj;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;
    f32 bestDistSq;

    targetId = ((ObjSeqState*)obj->extra)->targetObjId;
    if (targetId != 0)
    {
        return ObjList_FindObjectById(targetId);
    }

    objects = (void**)ObjList_GetObjects(&unused, &objectCount);
    objectType = ((ObjSeqPlacement*)obj->anim.placementData)->targetType - 4;
    if (objectType == 0x1f || objectType == 0)
    {
        return Obj_GetPlayerObject();
    }
    if (objectType == 0x24 || objectType == 0x25)
    {
        return getTrickyObject();
    }

    {
        bestDistSq = -1.0f;
        bestObj = NULL;
        for (i = 0; i < objectCount; i++)
        {
            candidate = objects[i];
            if (candidate->anim.romDefNo == objectType)
            {
                dx = obj->anim.localPosX - candidate->anim.localPosX;
                dy = obj->anim.localPosY - candidate->anim.localPosY;
                dz = obj->anim.localPosZ - candidate->anim.localPosZ;
                distSq = dx * dx + dy * dy + dz * dz;
                if (bestDistSq < 0.0f || distSq < bestDistSq)
                {
                    bestDistSq = distSq;
                    bestObj = candidate;
                }
            }
        }
    }
    return bestObj;
}

#define ObjSeq_GetObjects(unused, count) (ObjList_GetObjects((unused), (count)))

void ObjSeq_runBgCmds(void)
{
    int ok;
    int keepCount;
    GameObject** objects;
    int matchCount;
    GameObject** objPtr;
    u8* base;
    ObjSeqRunBgState* state;
    ObjSeqQueuedBgCmd* cmd;
    ObjSeqQueuedBgCmd* keepWalk;
    ObjSeqQueuedBgCmd* keepBase;
    int count;
    int i;
    int index;
    int xrot;
    ObjSeqPlacement* model;
    ObjSeqState* seqp;
    GameObject* candidate;
    GameObject** mp;
    int n;
    s8* pending;
    u8* results;
    u8* actions;
    f32* dists;
    f32* frames;
    u8* marks;
    s8 frames8;
    GameObject* matched[0x28];
    ObjSeqQueuedBgCmd keepBuf[0x1e];
    int objectCount;
    int unused;

    base = gObjSeqRuntimeBuffer;
    state = (ObjSeqRunBgState*)base;
    objects = ObjSeq_GetObjects(&unused, &objectCount);
    if (lbl_803DD060 != lbl_803DD062)
    {
        lbl_803DD062 = lbl_803DD060;
    }

    pending = state->pendingFrames;
    results = state->slotResults;
    actions = state->previousSlotResults;
    dists = state->slotDistances;
    frames = state->previousSlotDistances;
    marks = state->slotMarks;
    frames8 = framesThisStep;

    for (i = 0; i < 0x55; i++)
    {
        *pending = 0;
        if ((s8)*results != 0 && (s8)*actions == 0)
        {
            *pending = frames8;
        }
        *actions = *results;
        *results = 0;
        *frames = *dists;
        *dists = -1.0f;
        if (*marks == 2)
        {
            *marks = 1;
        }
        else
        {
            *marks = 0;
        }
        pending++;
        results++;
        actions++;
        dists++;
        frames++;
        marks++;
    }

    count = gObjSeqBgCmdCount;
    keepCount = 0;
    cmd = (ObjSeqQueuedBgCmd*)(base + 0x2a80) + count;
    keepBase = keepBuf;
    keepWalk = keepBase;
    while (count > 0)
    {
        cmd--;
        count--;
        index = cmd->index;
        xrot = cmd->xrot;
        i = 0;
        state->boolFlags[index] = 0;
        state->conditionFlags[index] = 0;
        state->slotStates[index] = 0;
        matchCount = 0;
        ok = 1;
        objPtr = objects;
        for (; i < objectCount; i++)
        {
            candidate = *objPtr;
            if (candidate->anim.classId == 0x10)
            {
                model = (ObjSeqPlacement*)candidate->anim.placementData;
                seqp = candidate->extra;
                if (model != NULL && model->slot == index)
                {
                    if (model->targetType >= 4 && ObjSeq_FindTargetObject(candidate) == NULL)
                    {
                        ok = 0;
                        logPrintf(sObjSequenceMissingObjectFormat, model->targetType - 4);
                    }
                    else
                    {
                        seqp->targetObj = NULL;
                    }
                    if (matchCount < 0x28)
                    {
                        matched[matchCount++] = candidate;
                    }
                }
            }
            objPtr++;
        }

        n = 0;
        mp = matched;
        for (; n < matchCount; n++)
        {
            candidate = *mp;
            model = (ObjSeqPlacement*)candidate->anim.placementData;
            if (model != NULL && model->slot == index)
            {
                seqp = candidate->extra;
                if (ok != 0)
                {
                    seqp->runState = 2;
                    seqp->pendingStartFrame = xrot;
                    ObjSeq_update(candidate, 1.0f);
                    Obj_GetWorldPosition(candidate, &candidate->anim.worldPosX,
                                         &candidate->anim.worldPosY, &candidate->anim.worldPosZ);
                }
                else
                {
                    seqp->runState = 3;
                }
            }
            mp++;
        }

        if (ok == 0)
        {
            keepWalk->index = index;
            keepWalk++;
            keepBuf[keepCount++].xrot = xrot;
        }
    }

    for (i = 0; i < keepCount; i++)
    {
        ((ObjSeqQueuedBgCmd*)(base + 0x2a80))[i].index = keepBase->index;
        ((ObjSeqQueuedBgCmd*)(base + 0x2a80))[i].xrot = keepBase->xrot;
        keepBase++;
    }
    gObjSeqBgCmdCount = keepCount;
}

static inline f32 ObjSeq_SampleTrackCurve(u8* seq, int track, int frame)
{
    f32 val;
    if (((ObjSeqState*)seq)->animEntries == NULL)
    {
        return 0.0f;
    }
    val = 0.0f;
    if (((ObjSeqState*)seq)->trackRunLength[track] != 0)
    {
        val = objCurveInterpolate(
            (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[track] * 8),
            ((ObjSeqState*)seq)->trackRunLength[track] & 0xfff, frame);
    }
    return val;
}


void ObjSeq_seqState_free(u8* seq)
{
    void* ptr;

    ptr = ((ObjSeqState*)seq)->cmds;
    if (ptr != NULL)
    {
        mm_free(ptr);
        ((ObjSeqState*)seq)->cmds = NULL;
        ((ObjSeqState*)seq)->animEntries = NULL;
    }
    ptr = ((ObjSeqState*)seq)->curveInterp;
    if (ptr != NULL)
    {
        mm_free(ptr);
        ((ObjSeqState*)seq)->curveInterp = NULL;
    }
}

void ObjSeq_seqState_init(u8* seq)
{
    int animIndex;
    int runLength;
    int track;
    int animCount;
    int commandIndex;
    ObjSeqCommand* command;

    for (animCount = 0; animCount < 0x13; animCount++)
    {
        ((ObjSeqState*)seq)->trackRunLength[animCount] = 0;
    }

    track = 0;
    animIndex = 0;
    while (animIndex < ((ObjSeqState*)seq)->animCount)
    {
        runLength = 0;
        commandIndex = ((ObjSeqState*)seq)->animCount;
        while (animIndex + runLength < commandIndex &&
               track == ((s8)(((ObjSeqState*)seq)->animEntries + (animIndex + runLength) * 8)[5] & 0x1f))
        {
            runLength++;
        }
        ((ObjSeqState*)seq)->trackRunLength[track] = runLength;
        ((ObjSeqState*)seq)->trackAnimStart[track] = animIndex;
        track++;
        animIndex += runLength;
    }

    ((ObjSeqState*)seq)->endFrame = 1000;
    commandIndex = 0;
    while (commandIndex < 2 && commandIndex < ((ObjSeqState*)seq)->cmdCount)
    {
        command = (ObjSeqCommand*)(((ObjSeqState*)seq)->cmds + commandIndex * 4);
        if ((s8)((u8*)command)[0] == -1)
        {
            ((ObjSeqState*)seq)->endFrame = command->param + 1;
        }
        commandIndex++;
    }
}


void objLoadAnimdata(ObjSeqState* seq, ObjSeqAnimPlacement* placement)
{
    ObjSeqRunBgState* runBgState = (ObjSeqRunBgState*)gObjSeqRuntimeBuffer;
    s16 size;
    int animId;
    int fileOffset;
    ObjSeqAnimDataHeader hdr;

    if (placement->animDataIndex == -1)
    {
        return;
    }

    seq->animCount = 0;
    seq->cmdCount = 0;
    animId = placement->animDataIndex;
    if ((animId & 0x8000) != 0)
    {
        getTabEntry(gObjSeqAnimLookup, MLDF_FILEID_OBJSEQ2C_TAB, ((animId & 0x7ff0) >> 4) * 2, 8);
        animId = gObjSeqAnimLookup->baseAnimId + (animId & 0xf);
    }
    else
    {
        animId = animId + 1;
    }

    if (getTableFileEntry(MLDF_FILEID_ANIMCURV_TAB_A, animId, &fileOffset) == 0)
    {
        logPrintf(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    loadAndDecompressDataFile(MLDF_FILEID_ANIMCURV_BIN_A, &hdr, fileOffset, 8, 0, 0, 0);
    if (strncmp(hdr.tag, sSeqAAnimDataTag, 4) != 0 && strncmp(hdr.tag, sSeqBAnimDataTag, 4) != 0)
    {
        logPrintf(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    size = hdr.dataSize;
    seq->cmdCount = hdr.commandCount;
    if (size == 0)
    {
        logPrintf(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    seq->cmds = mmAlloc(size, 0x11, 0);
    if (seq->cmds == NULL)
    {
        logPrintf(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    loadAndDecompressDataFile(MLDF_FILEID_ANIMCURV_BIN_A, seq->cmds, fileOffset + 8, hdr.dataSize, 0, 0, 0);
    seq->animCount = (s16)(((hdr.dataSize >> 2) - hdr.commandCount) >> 1);
    seq->animEntries = seq->cmds + hdr.commandCount * 4;

    seq->slot = placement->slot;
    if (seq->slot > -1)
    {
        runBgState->conditionFlags[seq->slot] = 0;
        runBgState->boolFlags[seq->slot] = 0;
        runBgState->slotStates[seq->slot] = 0;
    }

    if (placement->startOnLoad != 0)
    {
        seq->runState = 2;
    }
    else
    {
        seq->runState = 0;
    }
    ObjSeq_seqState_init((u8*)seq);
}


void ObjSeq_updateCamera(void);

u32 lbl_8030EC00[4] = {0x28E5, 0x28E6, 0x28E7, 0x28E8};
u32 lbl_8030EC10[3] = {0x501C, 0x501D, 0x501E};
u32 lbl_8030EC1C[3] = {0x51A1, 0x51A2, -1};
u32 lbl_8030EC28[7] = {0x51A4, 0x51A5, 0x51A7, 0x51A8, 0x51A9, 0x51AA, 0x51AB};
u32 lbl_8030EC44[4] = {0x51AC, 0x51AD, 0x51AE, 0x51AF};
u32 lbl_8030EC54[4] = {0x2A, 0x25, 0x21, 0x2B};
u32 lbl_8030EC64[3] = {-1, -1, -1};
u32 lbl_8030EC70[3] = {-1, -1, 0x525};
u32 lbl_8030EC7C[7] = {0x2E5, 0x2E6, 0x2E8, 0x2EA, 0x2EA, 0x2E8, 0x2E9};
u32 lbl_8030EC98[4] = {0x2ED, 0x2EE, 0x2EF, 0x2F0};

ObjSeqStreamMapEntry gObjSeqStreamTableA[OBJSEQ_STREAM_MAP_COUNT] = {
    {0x35F, lbl_8030EC00}, {0x45A, lbl_8030EC10}, {0x117, lbl_8030EC1C},
    {0xC3, lbl_8030EC28},  {0x122, lbl_8030EC44},
};
ObjSeqStreamMapEntry gObjSeqStreamTableB[OBJSEQ_STREAM_MAP_COUNT] = {
    {0x35F, lbl_8030EC54}, {0x45A, lbl_8030EC64}, {0x117, lbl_8030EC70},
    {0xC3, lbl_8030EC7C},  {0x122, lbl_8030EC98},
};

s16 gObjSeqSlotValues[86] = {0};

int gObjSeqScriptedButtonMasks[7] = {0x100, 0x200, 0x40000, 0x80000, 0x20000, 0x10000, -1};

int gObjSeqMsgIds[] = {
    0x00050001, 0x00050002, 0x00050003, 0x00060001, 0x00060002, 0x000A0001, 0x000A0002, 0x000A0003,
    8,          9,          0x00030002, 0x00030003, 0x000A0004, 0x000A0005, 0x000A0006, 0x000F000B,
    0x000F000C, 0x000F000D, 0x000F000E, 0x000F000F, 0x000F0010, 0x00130001, 0x00130002,
};

s8 gObjSeqMsgSendModes[24] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0};
typedef struct ObjSeqDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback onMapSetup;
    ObjectDescriptorCallback addBgCmd;
    ObjectDescriptorCallback setBool;
    ObjectDescriptorCallback getBool;
    ObjectDescriptorCallback update;
    ObjectDescriptorCallback updateCamera;
    ObjectDescriptorCallback objLoadAnimdata;
    ObjectDescriptorCallback seqState_init;
    ObjectDescriptorCallback seqState_free;
    ObjectDescriptorCallback runBgCmds;
    ObjectDescriptorCallback resolveTargetObject;
    ObjectDescriptorCallback slot0E;
    ObjectDescriptorCallback slot0F;
    ObjectDescriptorCallback getGlobal4;
    ObjectDescriptorCallback setGlobal4;
    ObjectDescriptorCallback slot12;
    ObjectDescriptorCallback slot13;
    ObjectDescriptorCallback start;
    ObjectDescriptorCallback endObjSequence;
    ObjectDescriptorCallback setCamVars;
    ObjectDescriptorCallback preempt;
    ObjectDescriptorCallback yield;
    ObjectDescriptorCallback getGlobal3;
    ObjectDescriptorCallback setGlobal3;
    ObjectDescriptorCallback getGlobal1;
    ObjectDescriptorCallback setGlobal1;
    ObjectDescriptorCallback getGlobal2;
    ObjectDescriptorCallback setGlobal2;
    ObjectDescriptorCallback setXrot;
    ObjectDescriptorCallback turnToFacePlayer;
    ObjectDescriptorCallback setObjs;
    ObjectDescriptorCallback setOverridePos;
    ObjectDescriptorCallback setCoordinateSpace;
} ObjSeqDllInterface;

ObjSeqDllInterface ObjSeq_funcs = {
    0,
    0,
    0,
    0x230000,
    (ObjectDescriptorCallback)ObjSeq_initialise,
    (ObjectDescriptorCallback)ObjSeq_release,
    0,
    (ObjectDescriptorCallback)ObjSeq_onMapSetup,
    (ObjectDescriptorCallback)ObjSeq_addBgCmd,
    (ObjectDescriptorCallback)ObjSeq_setBool,
    (ObjectDescriptorCallback)ObjSeq_getBool,
    (ObjectDescriptorCallback)ObjSeq_update,
    (ObjectDescriptorCallback)ObjSeq_updateCamera,
    (ObjectDescriptorCallback)objLoadAnimdata,
    (ObjectDescriptorCallback)ObjSeq_seqState_init,
    (ObjectDescriptorCallback)ObjSeq_seqState_free,
    (ObjectDescriptorCallback)ObjSeq_runBgCmds,
    (ObjectDescriptorCallback)ObjSeq_resolveTargetObject,
    (ObjectDescriptorCallback)ObjSeq_func0E,
    (ObjectDescriptorCallback)ObjSeq_func0F,
    (ObjectDescriptorCallback)ObjSeq_getGlobal4,
    (ObjectDescriptorCallback)ObjSeq_setGlobal4,
    (ObjectDescriptorCallback)ObjSeq_func12,
    (ObjectDescriptorCallback)ObjSeq_func13,
    (ObjectDescriptorCallback)ObjSeq_start,
    (ObjectDescriptorCallback)endObjSequence,
    (ObjectDescriptorCallback)ObjSeq_setCamVars,
    (ObjectDescriptorCallback)ObjSeq_preempt,
    (ObjectDescriptorCallback)ObjSeq_yield,
    (ObjectDescriptorCallback)ObjSeq_getGlobal3,
    (ObjectDescriptorCallback)ObjSeq_setGlobal3,
    (ObjectDescriptorCallback)ObjSeq_getGlobal1,
    (ObjectDescriptorCallback)ObjSeq_setGlobal1,
    (ObjectDescriptorCallback)ObjSeq_getGlobal2,
    (ObjectDescriptorCallback)ObjSeq_setGlobal2,
    (ObjectDescriptorCallback)ObjSeq_setXrot,
    (ObjectDescriptorCallback)ObjSeq_TurnToFacePlayer,
    (ObjectDescriptorCallback)ObjSeq_SetObjs,
    (ObjectDescriptorCallback)ObjSeq_setOverridePos,
    (ObjectDescriptorCallback)ObjSeq_SetCoordinateSpace,
};

char sEndObjSequenceMaxFreesError[41] = "endObjSequence: max number of obj frees\n\000";
char sObjSequenceMissingObjectFormat[38] = " SEQUENCE: Could not Find Object %i \n\000";
char sObjLoadAnimdataNullACRomTabWarning[45] = "<objLoadAnimdata>  Warning ACRomTab is NULL\n\000";

void ObjSeq_updateCamera(void)
{
    CameraModeFixedPose cameraPose;
    CameraModeViewfinderSettings viewfinderSettings;
    CameraModePathSettings pathSettings;
    CamMode mode48;
    int groupObjCount;
    GameObject* obj;
    u8* model;
    CameraObject* camObj;
    f32 x;
    f32 y;
    f32 z;
    s16 pitch;
    s16 yaw;
    s16 roll;
    int code;

    obj = gObjSeqCameraSourceObj;
    if (obj != NULL)
    {
        model = (u8*)obj->anim.placementData;
        if (gObjSeqCameraOverrideActive != 0)
        {
            x = gObjSeqCameraOverridePosX;
            y = gObjSeqCameraOverridePosY;
            z = gObjSeqCameraOverridePosZ;
        }
        else
        {
            x = obj->anim.worldPosX;
            y = obj->anim.worldPosY;
            z = obj->anim.worldPosZ;
        }
        pitch = obj->anim.rotX;
        yaw = obj->anim.rotY;
        roll = obj->anim.rotZ;
        if (obj->anim.parent != NULL)
        {
            pitch = (s16)(pitch + obj->anim.parentAnim->rotX);
        }
        lbl_803DD0DC = 1.0f;
        if ((s8)gObjSeqCameraActive == 0)
        {
            cameraPose.worldPosition.x = x;
            cameraPose.worldPosition.y = y;
            cameraPose.worldPosition.z = z;
            cameraPose.sequenceRotation.pitch = (s16)(0x8000 - pitch);
            cameraPose.sequenceRotation.yaw = (s16)-yaw;
            cameraPose.sequenceRotation.roll = roll;
            if ((s8)gObjSeqFovOverrideActive != 0)
            {
                cameraPose.fov = gObjSeqFovOverrideValue;
                gObjSeqCameraFov = gObjSeqFovOverrideValue;
            }
            else
            {
                cameraPose.fov = gObjSeqCameraFov;
            }
            (*gCameraInterface)
                ->setMode(OBJSEQ_CAMMODE_FIXED, 0, 1, sizeof(CameraModeFixedPose), &cameraPose, model[0x24], 0xff);
            gObjSeqCameraActive = 1;
        }
        else
        {
            camObj = (*gCameraInterface)->getCamera();
            camObj->anim.worldPosX = x;
            camObj->anim.worldPosY = y;
            camObj->anim.worldPosZ = z;
            Obj_TransformWorldPointToLocal(camObj->anim.worldPosX, camObj->anim.worldPosY, camObj->anim.worldPosZ,
                                           &camObj->anim.localPosX, &camObj->anim.localPosY, &camObj->anim.localPosZ,
                                           (GameObject*)camObj->anim.parent);
            camObj->anim.rotX = (s16)(0x8000 - pitch);
            camObj->anim.rotY = (s16)-yaw;
            camObj->anim.rotZ = roll;
            if ((s8)gObjSeqFovOverrideActive != 0)
            {
                camObj->fov = gObjSeqFovOverrideValue;
                gObjSeqCameraFov = gObjSeqFovOverrideValue;
            }
            else
            {
                camObj->fov = gObjSeqCameraFov;
            }
            gObjSeqSavedCamPosX = camObj->anim.worldPosX;
            gObjSeqSavedCamPosY = camObj->anim.worldPosY;
            gObjSeqSavedCamPosZ = camObj->anim.worldPosZ;
            gObjSeqSavedCamPitch = camObj->anim.rotX;
            gObjSeqSavedCamYaw = camObj->anim.rotY;
            gObjSeqSavedCamRoll = camObj->anim.rotZ;
            gObjSeqSavedCamFov = camObj->fov;
        }
    }
    else
    {
        if ((s8)gObjSeqCameraActive != 0)
        {
            if (gObjSeqCamOwnerSeqIndex == 0)
            {
                switch (gObjSeqCamMode)
                {
                case CAMERA_MODE_PATH_RESOURCE_ID:
                    pathSettings.pathTag = gObjSeqCamModeArgB;
                    pathSettings.skipTransition = gObjSeqCamModeArgC;
                    (*gCameraInterface)
                        ->setMode(CAMERA_MODE_PATH_RESOURCE_ID, 1, 3, sizeof(CameraModePathSettings), &pathSettings,
                                  gObjSeqCamModeArgD, 0xff);
                    break;
                case 0x48:
                    mode48.mode = gObjSeqCamModeArgB;
                    if ((code = gObjSeqCamModeArgD) == 0)
                    {
                        mode48.flag = 1;
                    }
                    (*gCameraInterface)->setMode(OBJSEQ_CAMMODE_STATIC, 1, 3, 8, &mode48, code, 0xff);
                    break;
                case 0x4a:
                    (*gCameraInterface)->setMode(OBJSEQ_CAMMODE_SHIPBATTLE, 1, 0, 0, NULL, gObjSeqCamModeArgD, 0xff);
                    break;
                case 0x4c:
                    cameraPose.savedWorldPosition.x = gObjSeqSavedCamPosX;
                    cameraPose.savedWorldPosition.y = gObjSeqSavedCamPosY;
                    cameraPose.savedWorldPosition.z = gObjSeqSavedCamPosZ;
                    cameraPose.sequenceRotation.pitch = gObjSeqSavedCamPitch;
                    cameraPose.sequenceRotation.yaw = gObjSeqSavedCamYaw;
                    cameraPose.sequenceRotation.roll = gObjSeqSavedCamRoll;
                    cameraPose.fov = gObjSeqSavedCamFov;
                    (*gCameraInterface)
                        ->setMode(OBJSEQ_CAMMODE_FIXED, 1, 0, sizeof(CameraModeFixedPose), &cameraPose, 0, 0xff);
                    break;
                case 0x45:
                    (*gCameraInterface)->setMode(OBJSEQ_CAMMODE_CAMTALK, 1, 0, 0, NULL, gObjSeqCamModeArgD, 0xff);
                    break;
                case CAMERA_MODE_VIEWFINDER_RESOURCE_ID:
                    if (gObjSeqCamModeArgB != 0)
                    {
                        viewfinderSettings.radius = 90.0f;
                        viewfinderSettings.yOffset = 20.0f;
                        viewfinderSettings.height = 5;
                        (*gCameraInterface)
                            ->setMode(CAMERA_MODE_VIEWFINDER_RESOURCE_ID, 1, 1,
                                      sizeof(CameraModeViewfinderSettings), &viewfinderSettings, 0, 0xff);
                    }
                    else
                    {
                        viewfinderSettings.radius = 90.0f;
                        viewfinderSettings.yOffset = 20.0f;
                        viewfinderSettings.height = 0x1e;
                        (*gCameraInterface)
                            ->setMode(CAMERA_MODE_VIEWFINDER_RESOURCE_ID, 1, 0,
                                      sizeof(CameraModeViewfinderSettings), &viewfinderSettings, 0, 0xff);
                    }
                    break;
                case CAMERA_MODE_COMBAT_RESOURCE_ID:
                    (*gCameraInterface)
                        ->setMode(CAMERA_MODE_COMBAT_RESOURCE_ID, 1, 0, gObjSeqCamModeArgB, &gObjSeqCamModeArgC,
                                  gObjSeqCamModeArgD, 0xff);
                    break;
                case CAMERA_MODE_CLOUDRUNNER_RESOURCE_ID:
                    (*gCameraInterface)->setMode(CAMERA_MODE_CLOUDRUNNER_RESOURCE_ID, 1, 0, 0, NULL, 0, 0xff);
                    break;
                case CAMERA_MODE_ARWING_RESOURCE_ID:
                    (*gCameraInterface)
                        ->setMode(CAMERA_MODE_ARWING_RESOURCE_ID, 1, gObjSeqCamModeArgB, 0, NULL, 0, 0);
                    break;
                case CAMERA_MODE_TITLE_RESOURCE_ID:
                    (*gCameraInterface)->setMode(CAMERA_MODE_TITLE_RESOURCE_ID, 0, 3, 0, NULL, 0, 0);
                    (*gCameraInterface)
                        ->setFocus(*(void**)(void*)objGetAllOfType(OBJSEQ_TARGET_OBJGROUP, &groupObjCount), 0);
                    break;
                default:
                    if (gObjSeqCamModeArgB == 0)
                    {
                        gObjSeqCamModeArgB = 1;
                    }
                    (*gCameraInterface)
                        ->setMode(OBJSEQ_CAMMODE_DEFAULT, 0, gObjSeqCamModeArgB, 0, NULL, gObjSeqCamModeArgD, 0xff);
                    break;
                }
            }
            gObjSeqCameraActive = 0;
            gObjSeqCameraFov = 60.0f;
            gObjSeqCamModeArgB = 1;
            gObjSeqCamModeArgD = 0x5a;
            gObjSeqCamMode = 0x42;
            curSeqNo = 0;
        }
        else
        {
            gObjSeqCamModeArgB = 1;
            gObjSeqCamModeArgD = 0x5a;
            gObjSeqCamMode = 0x42;
        }
    }

    gObjSeqFovOverrideActive = 0;
    gObjSeqCameraSourceObj = NULL;
    gObjSeqCameraOverrideActive = 0;
}

void animatedObjFreeAndSavePlayerPos(GameObject* obj, GameObject* seqObj, u8* seq)
{
    void (*callback)(void* ctx, u8* obj);
    GameObject* player;
    int clearBit;

    callback = ((ObjSeqState*)seq)->freeCallback;
    if (callback != NULL)
    {
        callback(((ObjSeqState*)seq)->callbackContext, (u8*)obj);
        ((ObjSeqState*)seq)->freeCallback = NULL;
    }

    if ((s8)((ObjSeqState*)seq)->slot == gObjSeqPreparingStreamSlot)
    {
        AudioStream_CancelPrepared();
        gObjSeqPreparingStreamSlot = -1;
    }

    if (((ObjSeqState*)seq)->runState != 0)
    {
        if ((s8)((ObjSeqState*)seq)->isCameraSeq != 0)
        {
            ((ObjSeqState*)seq)->isCameraSeq = 0;
        }
        if (((ObjSeqState*)seq)->targetObj != NULL)
        {
            seqObj->pendingParentObj = NULL;
            seqObj->objectFlags &= ~OBJECT_OBJFLAG_SEQ_ATTACHED;
            ((ObjSeqState*)seq)->targetObj = NULL;
        }
    }

    if (((ObjSeqState*)seq)->flags136.mapEvent != 0U)
    {
        player = Obj_GetPlayerObject();
        (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 0, getCurMapLayer());
        clearBit = 0;
        ((ObjSeqState*)seq)->flags136.mapEvent = clearBit;
    }

    ((ObjSeqState*)seq)->runState = 0;
}


f32 objCurveInterpolate(ObjCurveKey* keys, int count, int frame)
{
    int index;
    int mode;
    int prevIndex;
    int keyIndex;
    ObjCurveKey* key;
    ObjCurveKey* prev;
    f32 values[4];
    f32 deltaNext;
    f32 deltaPrev;
    f32 span;
    f32 t;

    if (count <= 0)
    {
        return 0.0f;
    }

    index = 0;
    while (index < count && keys[index].frame < frame)
    {
        index++;
    }

    if (index == count)
    {
        return keys[count - 1].value;
    }
    if (index == 0)
    {
        return keys[0].value;
    }
    if (frame == keys[index].frame)
    {
        t = keys[index].value;
        mode = keys[index].tangentAndMode & 3;
        if (mode > 1 && index < count - 1)
        {
            t = keys[index + 1].value;
        }
        return t;
    }

    prevIndex = index - 1;
    prev = &keys[prevIndex];
    mode = prev->tangentAndMode & 3;
    values[0] = prev->value;
    if (mode == 0)
    {
        deltaNext = prev[1].value - values[0];
        if (prevIndex > 0)
        {
            deltaPrev = values[0] - prev[-1].value;
        }
        else
        {
            deltaPrev = deltaNext;
        }
        if (deltaNext < 0.0f)
        {
            deltaNext = -deltaNext;
        }
        if (deltaPrev < 0.0f)
        {
            deltaPrev = -deltaPrev;
        }
        deltaPrev = deltaNext + deltaPrev;
        t = deltaPrev / 16.0f;
        values[2] = t * (f32)(prev->tangentAndMode >> 2);
    }

    span = (f32)(keys[prevIndex + 1].frame - keys[prevIndex].frame);
    keyIndex = index;
    if (index < count)
    {
        key = &keys[keyIndex];
        values[1] = key->value;
        if (mode == 0)
        {
            index++;
            if (index < count)
            {
                deltaPrev = key[1].value - values[1];
            }
            else
            {
                deltaPrev = deltaNext;
            }
            if (deltaPrev < 0.0f)
            {
                deltaPrev = -deltaPrev;
            }
            deltaPrev = deltaNext + deltaPrev;
            t = deltaPrev / 16.0f;
            values[3] = t * (f32)(keys[keyIndex].tangentAndMode >> 2);
        }
    }

    if (span > 0.0f)
    {
        t = (f32)(frame - keys[keyIndex - 1].frame) / span;
        if (mode == 0)
        {
            return Curve_EvalHermite(values, t, NULL);
        }
        if (mode == 1)
        {
            return t * (values[1] - values[0]) + values[0];
        }
        return values[1];
    }
    return values[1];
}

int objSeqExecCmd06(GameObject* obj, GameObject* sourceObj, u8* seq, int cmd, s8 flag)
{
    u8* base = gObjSeqRuntimeBuffer;
    ObjAnimComponent* sourceAnim = &sourceObj->anim;
    u32 cmdByte;
    int cmdArg = (cmd >> 8) & 0xff;
    int pair[2];
    GameObject* player;
    u8 flags;
    u8* slotFlags;
    int trackId;
    int slot;
    int off;
    int* streams;
    f32 dist;
    f32 strength;

    cmdByte = cmd & 0xff;
    switch (cmdByte)
    {
    case 2:
        if (flag != 0)
        {
            break;
        }
        pair[0] = 0x19;
        pair[1] = 0x15;
        if (((ObjSeqState*)seq)->curveId < 0)
        {
            ((ObjSeqState*)seq)->curveId = (*gRomCurveInterface)->find(
                obj->anim.localPosX, obj->anim.localPosY,
                obj->anim.localPosZ, pair, 2, cmdArg);
            if (((ObjSeqState*)seq)->curveId > -1)
            {
                if (((ObjSeqState*)seq)->curveInterp != NULL)
                {
                    mm_free(((ObjSeqState*)seq)->curveInterp);
                    ((ObjSeqState*)seq)->curveInterp = NULL;
                }
                ((ObjSeqState*)seq)->curveInterp = mmAlloc(0x2c, 0x11, 0);
                if (((ObjSeqState*)seq)->curveInterp != NULL)
                {
                    RomCurveInterp_InitFromNode(((ObjSeqState*)seq)->curveInterp, ((ObjSeqState*)seq)->curveId);
                }
                else
                {
                    ((ObjSeqState*)seq)->curveId = -1;
                }
            }
        }
        break;
    case 9:
        if (flag != 0)
        {
            break;
        }
        ((ObjSeqState*)seq)->stateFlags |= 1;
        break;
    case 18:
        if (flag != 0)
        {
            break;
        }
        slotFlags = base + (s8)((ObjSeqState*)seq)->slot;
        flags = *(slotFlags += 0x3538);
        if ((flags & 0x10) != 0)
        {
            *slotFlags = flags & ~0x10;
        }
        else
        {
            *slotFlags = flags | 0x10;
        }
        break;
    case 14:
        if (flag != 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] == 0)
        {
            (*gScreenTransitionInterface)->start(cmdArg, SCREEN_TRANSITION_BLACK);
        }
        break;
    case 15:
        if (flag != 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] == 0)
        {
            (*gScreenTransitionInterface)->step(cmdArg, SCREEN_TRANSITION_BLACK);
        }
        break;
    case 20:
        gObjSeqCamMode = CAMERA_MODE_PATH_RESOURCE_ID;
        gObjSeqCamModeArgB = cmdArg & 0x7f;
        gObjSeqCamModeArgC = 1;
        gObjSeqCamModeArgD = 0x78;
        break;
    case 23:
        if (flag != 0)
        {
            break;
        }
        if (cmdArg >= sourceAnim->modelInstance->modelCount)
        {
            break;
        }
        if (sourceObj->anim.classId == 1)
        {
            if (((s16*)(base + 0x3a98))[(s8)((ObjSeqState*)seq)->slot] - 1 != 0x45)
            {
                break;
            }
            if (cmdArg == 1)
            {
                cmdArg = 0;
            }
            playerSetDisguised(sourceObj, cmdArg);
        }
        else
        {
            Obj_SetActiveModelIndex(sourceObj, cmdArg);
        }
        break;
    case 24:
        if (sourceObj->anim.classId == 1)
        {
            playerPullOutStaff(sourceObj, cmdArg);
        }
        break;
    case 25:
        if (sourceObj->anim.classId == 1)
        {
            playerPutAwayStaff(sourceObj, cmdArg);
        }
        break;
    case 26:
        gObjSeqCamMode = 0x42;
        gObjSeqCamModeArgB = 4;
        gObjSeqCamModeArgC = 0;
        gObjSeqCamModeArgD = 0;
        break;
    case 33:
        ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags | 0x400;
        ((ObjSeqState*)seq)->flags136.modelSlot = cmdArg;
        break;
    case 34:
        ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags & ~0x400;
        ((ObjSeqState*)seq)->flags136.modelSlot = 0;
        break;
    case 35:
        ((ObjSeqState*)seq)->flags136.mapEvent = 1;
        break;
    case 36:
        (*gMapEventInterface)->savePoint(NULL, 0, 1, getCurMapLayer());
        break;
    case 38:
        playerLock(Obj_GetPlayerObject(), cmdArg);
        break;
    case 44:
        setMotionBlur(1, cmdArg / 10.0f);
        break;
    case 45:
        setMotionBlur(0, 0.0f);
        break;
    case 46:
        Rcp_SetMonochromeFilterEnabled(1);
        break;
    case 47:
        Rcp_SetMonochromeFilterEnabled(0);
        break;
    case 48:
        mainSetBits(GAMEBIT_ENV_isOutdoor, 1);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_A0, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_A1, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_A2, 0);
        break;
    case 49:
        mainSetBits(GAMEBIT_ENV_isOutdoor, 1);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_B0, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_B1, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_B2, 0);
        break;
    case 50:
        mainSetBits(GAMEBIT_ENV_isOutdoor, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_A0, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_A1, 0);
        getEnvfxActVoid(Obj_GetPlayerObject(), Obj_GetPlayerObject(), OBJSEQ_ENVFX_A2, 0);
        skyRefreshPlayerEnvFx();
        break;
    }

    switch (cmdByte)
    {
    case 0:
        gObjSeqStop = 1;
        return 0;
    case 7:
        if (flag != 0)
        {
            break;
        }
        CameraShake_Enable();
        player = Obj_GetPlayerObject();
        if (player == NULL)
        {
            break;
        }
        dist = Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX);
        strength = 2.0f * (f32)(cmdArg - 7) + 1.0f;
        if (dist < 200.0f)
        {
            if (dist > 50.0f)
            {
                strength *= 1.0f - (dist - 50.0f) / 150.0f;
            }
            CameraShake_StartDampened(gObjSeqShakeAmplitude * strength, gObjSeqShakeAmplitude * strength,
                              gObjSeqShakeAmplitude);
        }
        break;
    case 10:
        gameTimerInit(0x12, cmdArg);
        break;
    case 11:
        gameTimerInit(0x11, cmdArg);
        break;
    case 12:
        timerSetToCountUp();
        break;
    case 37:
        gameTimerStop();
        break;
    case 13:
        Sfx_StopObjectChannel(sourceObj, 0x7f);
        break;
    case 16:
        ((ObjSeqState*)seq)->unk7D = cmdArg;
        break;
    case 21:
        gObjSeqCamMode = 0x48;
        gObjSeqCamModeArgB = cmdArg & 0x7f;
        gObjSeqCamModeArgC = 1;
        gObjSeqCamModeArgD = 0x78;
        break;
    case 51:
        gObjSeqCamModeArgD = cmdArg;
        break;
    case 23:
        if (flag != 0)
        {
            break;
        }
        if (sourceObj->anim.classId == 1)
        {
            break;
        }
        if (cmdArg >= sourceAnim->modelInstance->modelCount)
        {
            break;
        }
        Obj_SetActiveModelIndex(sourceObj, cmdArg);
        break;
    case 27:
        (*gMapEventInterface)->setObjGroupStatus(sourceAnim->mapEventSlot, cmdArg, 1);
        break;
    case 28:
        (*gMapEventInterface)->setObjGroupStatus(sourceAnim->mapEventSlot, cmdArg, 0);
        break;
    case 29:
        (*gMapEventInterface)->setMapAct(sourceAnim->mapEventSlot, cmdArg);
        break;
    case 19:
        if (flag != 0)
        {
            break;
        }
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3538] &= ~0x10;
        break;
    case 30:
        if (flag != 0)
        {
            break;
        }
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3538] |= 0x10;
        break;
    case 31:
        (*gMapEventInterface)->clearRestartPoint();
        break;
    case 32:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case 39:
        if (gObjSeqPreparingStreamSlot == (s8)((ObjSeqState*)seq)->slot)
        {
            gObjSeqStreamResumeOffset = (int)((f32*)(base + 0x3894))[(s8)((ObjSeqState*)seq)->slot];
            gObjSeqStreamStopped = ObjSeq_StartPreparedStream(((ObjSeqState*)seq)->slot) == 0;
        }
        break;
    case 40:
        slot = ((ObjSeqState*)seq)->slot;
        if (base[slot + 0x3334] == 0)
        {
            trackId = (u32)(((s16*)(base + 0x3a98))[slot] - 1) & 0x3fff;
            gObjSeqCurrentTrackId = trackId;
            streams = (int*)seqPairTableLookup(gObjSeqStreamTableA, OBJSEQ_STREAM_MAP_COUNT, trackId);
            if (streams != NULL)
            {
                off = cmdArg * 4;
                if (AudioStream_Play(*(int*)((u8*)streams + off), ObjSeq_AudioStreamCallback) != 0)
                {
                    gObjSeqPreparingStreamSlot = slot;
                }
                streams = (int*)seqPairTableLookup(gObjSeqStreamTableB, OBJSEQ_STREAM_MAP_COUNT, trackId);
                if (streams != NULL)
                {
                    gObjSeqSubtitleId = *(int*)((u8*)streams + off);
                }
            }
        }
        break;
    }
    return 1;
}

void ObjSeq_setCamVars(int camA, int camB, int camC, int camD)
{
    gObjSeqCamMode = camA;
    gObjSeqCamModeArgB = camB;
    gObjSeqCamModeArgC = camC;
    gObjSeqCamModeArgD = camD;
}

int seqDoSubCmd0B(GameObject* obj, GameObject* sourceObj, u8* seq, u8* cmdsArg, s16 xrot, s16 countArg, s8 flag1, s8 flag2)
{
    u8* cmds;
    int count;
    int opcode;
    int operand;
    int top16;
    int subId;
    int i;
    int freeSlot;
    u32 packed;
    int result;
    int j;
    int found;
    int eventIdx;
    u8 eventId;
    u8 slotVal;
    int slot;

    i = 0;
    cmds = cmdsArg;
    count = countArg;
    for (; i < count; i++)
    {
        packed = *(u32*)cmds;
        opcode = packed & 0x3f;
        operand = (packed >> 6) & 0x3ff;
        top16 = packed >> 16;
        if (opcode == 2 || opcode == 3)
        {
            if ((top16 & 0x8000) != 0)
            {
                top16 |= 0xffff0000;
            }
            subId = operand;
            operand = 0;
        }

        result = 0;
        switch (opcode)
        {
        case 6:
            if (objSeqExecCmd06(obj, sourceObj, seq, operand | (top16 << 8), flag2) == 0)
            {
                return 1;
            }
            result = -1;
            operand = 0;
            break;
        case 7:
            if (sourceObj != obj)
            {
                switch ((s8)gObjSeqMsgSendModes[operand])
                {
                case 1:
                    ObjMsg_SendToObjects(0, 2, obj, gObjSeqMsgIds[operand], (u32)obj);
                    break;
                case 2:
                    ObjMsg_SendToNearbyObjects(0, 600.0f, 2, obj, gObjSeqMsgIds[operand], (u32)obj);
                    break;
                default:
                    ObjMsg_SendToObject(sourceObj, gObjSeqMsgIds[operand], obj, 0);
                    break;
                }
            }
            result = -1;
            operand = 0;
            break;
        case 8:
            if (flag2 == 0)
            {
                found = 0;
                freeSlot = -1;
                for (j = 0; j < 10; j++)
                {
                    slotVal = seq[j + 0x12c];
                    if (slotVal == operand)
                    {
                        found = 1;
                    }
                    if (slotVal == 0)
                    {
                        freeSlot = j;
                    }
                }
                if (found == 0 && freeSlot != -1)
                {
                    ((ObjSeqState*)seq)->conditionOpcodes[freeSlot] = operand;
                    ((ObjSeqState*)seq)->conditionFrames[freeSlot] = objSeqFindLabel(seq, top16);
                }
                result = 0;
            }
            break;
        case 9:
            break;
        default:
            result = ObjSeq_EvaluateCondition(operand, seq, obj->anim.placementData);
            break;
        }

        if (result > 0 && flag1 == 0)
        {
            switch (opcode)
            {
            case 1:
                if (flag2 != 0)
                {
                    break;
                }
                slot = (s8)((ObjSeqState*)seq)->slot;
                if ((s8)gObjSeqJumpLatch[slot] == 0)
                {
                    gObjSeqJumpLatch[slot] = 1;
                    ((ObjSeqState*)seq)->curFrame = top16;
                    ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
                }
                return 1;
            case 10:
                if (flag2 != 0)
                {
                    break;
                }
                slot = (s8)((ObjSeqState*)seq)->slot;
                if ((s8)gObjSeqJumpLatch[slot] == 0)
                {
                    gObjSeqJumpLatch[slot] = 1;
                    ((ObjSeqState*)seq)->curFrame = objSeqFindLabel(seq, top16);
                    ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
                }
                return 1;
            case 2:
                switch (subId)
                {
                case 0:
                    eventId = top16;
                    ((ObjSeqState*)seq)->curEventId = eventId;
                    eventIdx = ((ObjSeqState*)seq)->eventCount;
                    if ((u32)eventIdx < 10)
                    {
                        ((ObjSeqState*)seq)->eventCount += 1;
                        ((ObjSeqState*)seq)->eventIds[eventIdx] = eventId;
                    }
                    break;
                case 1:
                    ((ObjSeqState*)seq)->seqCounter = top16;
                    break;
                case 3:
                    seqGlobal1 = top16;
                    break;
                case 4:
                    seqGlobal2 = top16;
                    break;
                case 5:
                    gObjSeqBoolFlags[(s8)((ObjSeqState*)seq)->slot] = top16;
                    break;
                case 6:
                    mainSetBits(((ObjSeqState*)seq)->gameBit, top16 != 0);
                    break;
                case 2:
                    break;
                }
                break;
            case 3:
                if (flag2 != 0)
                {
                    break;
                }
                switch (subId)
                {
                case 0:
                    ((ObjSeqState*)seq)->seqCounter = ((ObjSeqState*)seq)->seqCounter + top16;
                    break;
                case 1:
                    break;
                }
                break;
            case 4:
                if (flag2 != 0)
                {
                    break;
                }
                ((ObjSeqState*)seq)->curFrame = xrot;
                ((ObjSeqState*)seq)->prevFrame = xrot;
                ((ObjSeqState*)seq)->pendingConditionId = (s8)(operand + 1);
                gObjSeqJumpLatch[(s8)((ObjSeqState*)seq)->slot] = 1;
                return 1;
            case 5:
                if (flag2 != 0)
                {
                    break;
                }
                return 0;
            case 0:
            case 6:
            case 7:
            case 8:
            case 9:
                break;
            }
        }
        cmds += 4;
    }
    return 0;
}

int ObjSeq_EvaluateCondition(int condition, u8* seq, void* obj)
{
    f32 sunTime;
    int result;

    result = 0;

    switch (condition)
    {
    case OBJSEQ_COND_SEQCOUNTER_LT1:
        if (((ObjSeqState*)seq)->seqCounter <= 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_SEQCOUNTER_GT0:
        if (((ObjSeqState*)seq)->seqCounter > 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_DAYTIME:
        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_NIGHTTIME:
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_BOOL_EQ0:
        if (gObjSeqBoolFlags[(s8)((ObjSeqState*)seq)->slot] == 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_BOOL_EQ1:
        if (gObjSeqBoolFlags[(s8)((ObjSeqState*)seq)->slot] == 1)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_VAR1_EQ0:
        if (gObjSeqCondFlags[(s8)((ObjSeqState*)seq)->slot] == 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_VAR1_NE0:
        if (gObjSeqCondFlags[(s8)((ObjSeqState*)seq)->slot] != 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_GLOBAL1_LE0:
        if (seqGlobal1 <= 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_GLOBAL1_GT0:
        if (seqGlobal1 > 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_GLOBAL2_LE0:
        if (seqGlobal2 <= 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_GLOBAL2_GT0:
        if (seqGlobal2 > 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_TIMER_DISABLED:
        if (isGameTimerDisabled() != 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_TIMER_ENABLED:
        if (isGameTimerDisabled() == 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_GLOBAL3_NE0:
        if (seqGlobal3 != 0)
        {
            result = 1;
        }
        break;
    case OBJSEQ_COND_GLOBAL3_EQ0:
        if (seqGlobal3 == 0)
        {
            result = 1;
        }
        break;
    default:
        result = 1;
        break;
    }
    return result;
}

void RomCurveInterp_BuildSegmentTimeTable(RomCurveInterpState* out, RomCurveNode* curve, RomCurveNode* next, f32 t,
                                          int flag)
{
    f32 curveScale;
    f32 nextScale;
    f32 xPoints[4];
    f32 yPoints[4];
    f32 zPoints[4];
    f32 xSamples[9];
    f32 ySamples[9];
    f32 zSamples[9];
    f32* times;
    f32 dx;
    f32 dy;
    f32 dz;
    int i;

    curveScale = ROM_CURVE_NODE_SCALE(curve);
    nextScale = ROM_CURVE_NODE_SCALE(next);

    xPoints[0] = curve->x;
    xPoints[2] = curveScale * mathSinf(ROM_CURVE_NODE_ANGLE(curve->yaw));
    xPoints[1] = next->x;
    xPoints[3] = nextScale * mathSinf(ROM_CURVE_NODE_ANGLE(next->yaw));

    yPoints[0] = curve->y;
    yPoints[2] = curveScale * mathSinf(ROM_CURVE_NODE_ANGLE(curve->pitch));
    yPoints[1] = next->y;
    yPoints[3] = nextScale * mathSinf(ROM_CURVE_NODE_ANGLE(next->pitch));

    zPoints[0] = curve->z;
    zPoints[2] = curveScale * mathCosf(ROM_CURVE_NODE_ANGLE(curve->yaw));
    zPoints[1] = next->z;
    zPoints[3] = nextScale * mathCosf(ROM_CURVE_NODE_ANGLE(next->yaw));

    Curve_SampleSegmentPoints(xPoints, yPoints, zPoints, xSamples, ySamples, zSamples, 8, Curve_BuildHermiteCoeffs);

    times = (f32*)out;
    times[2] = 0.0f;
    for (i = 0; i < 8; i++)
    {
        dx = xSamples[i + 1] - xSamples[i];
        dy = ySamples[i + 1] - ySamples[i];
        dz = zSamples[i + 1] - zSamples[i];
        times[i + 3] = times[i + 2] + sqrtf(dx * dx + dy * dy + dz * dz);
    }
    if ((s8)flag == 1)
    {
        t -= out->toTime;
    }
    for (i = 0; i <= 8; i++)
    {
        times[i + 2] += t;
    }
}

void RomCurveInterp_UpdateSegmentWindow(RomCurveInterpState* state, f32 t)
{
    RomCurveNode* prev;
    RomCurveNode* fromNode;
    RomCurveNode* toNode;
    int found;
    int i;
    int mask;
    int val;
    f32 thr;

    fromNode = NULL;
    if (t < state->fromTime)
    {
        fromNode = (RomCurveNode*)(*gRomCurveInterface)->getById(state->fromNodeId);
    }
    if (fromNode != NULL)
    {
        while (t < (thr = state->fromTime))
        {
            mask = 1;
            for (i = 0; i < 4; i++)
            {
                val = fromNode->links[i];
                if (val > -1 && (fromNode->directionMask & mask) != 0)
                {
                    found = val;
                    i = 5;
                }
                mask <<= 1;
            }
            if (i != 6)
            {
                state->toTime = thr;
                state->toNodeId = state->fromNodeId;
                state->fromNodeId = -1;
                return;
            }
            state->toNodeId = state->fromNodeId;
            state->fromNodeId = found;
            prev = fromNode;
            fromNode = (RomCurveNode*)(*gRomCurveInterface)->getById(state->fromNodeId);
            RomCurveInterp_BuildSegmentTimeTable(state, fromNode, prev, state->fromTime, 1);
        }
    }
    toNode = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
    if (toNode == NULL)
    {
        return;
    }
    while (t >= (thr = state->toTime))
    {
        mask = 1;
        for (i = 0; i < 4; i++)
        {
            val = toNode->links[i];
            if (val > -1 && (toNode->directionMask & mask) == 0)
            {
                found = val;
                i = 5;
            }
            mask <<= 1;
        }
        if (i != 6)
        {
            state->fromTime = thr;
            state->fromNodeId = state->toNodeId;
            state->toNodeId = -1;
            return;
        }
        state->fromNodeId = state->toNodeId;
        state->toNodeId = found;
        prev = toNode;
        toNode = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
        RomCurveInterp_BuildSegmentTimeTable(state, prev, toNode, state->toTime, 0);
    }
}

void RomCurveInterp_InitFromNode(RomCurveInterpState* out, int id)
{
    RomCurveNode* curve;
    int i;
    int mask;
    int found;
    int val;

    out->fromNodeId = id;
    out->toNodeId = -1;
    curve = (RomCurveNode*)(*gRomCurveInterface)->getById(out->fromNodeId);
    mask = 1;
    for (i = 0; i < 4; i++)
    {
        val = curve->links[i];
        if (val > -1 && (curve->directionMask & mask) == 0)
        {
            found = val;
            i = 5;
        }
        mask <<= 1;
    }
    if (i != 6)
    {
        out->fromNodeId = -1;
    }
    else
    {
        out->toNodeId = found;
        RomCurveInterp_BuildSegmentTimeTable(out, curve, (RomCurveNode*)(*gRomCurveInterface)->getById(out->toNodeId),
                                             0.0f, 0);
    }
}

int RomCurveInterp_EvaluateOffsetPosition(RomCurveInterpState* state, f32* offset, f32* outPos, s16* outAngle,
                                          int ignoreY)
{
    RomCurveNode* from;
    RomCurveNode* to;
    f32 segmentT;
    f32 t;
    f32 fromScale;
    f32 toScale;
    f32 xPoints[4];
    f32 yPoints[4];
    f32 zPoints[4];
    f32 xTangent;
    f32 yTangent;
    f32 zTangent;
    f32 length;
    f32 scale;
    int segment;
    int i;

    t = offset[2];
    RomCurveInterp_UpdateSegmentWindow(state, t);
    from = (RomCurveNode*)(*gRomCurveInterface)->getById(state->fromNodeId);
    if (from != NULL && state->toNodeId > -1)
    {
        to = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
        i = 0;
        while (i <= 8 && t >= state->segmentTimes[i])
        {
            i++;
        }
        segment = i - 1;
        {
            f32* times = (f32*)state;
            segmentT = segment;
            segmentT += (t - times[segment + 2]) / (times[segment + 3] - times[segment + 2]);
        }
        segmentT = segmentT / 8.0f;

        fromScale = ROM_CURVE_NODE_SCALE(from);
        toScale = ROM_CURVE_NODE_SCALE(to);

        xPoints[0] = from->x;
        xPoints[2] = fromScale * mathSinf(ROM_CURVE_NODE_ANGLE(from->yaw));
        xPoints[1] = to->x;
        xPoints[3] = toScale * mathSinf(ROM_CURVE_NODE_ANGLE(to->yaw));

        yPoints[0] = from->y;
        yPoints[2] = fromScale * mathSinf(ROM_CURVE_NODE_ANGLE(from->pitch));
        yPoints[1] = to->y;
        yPoints[3] = toScale * mathSinf(ROM_CURVE_NODE_ANGLE(to->pitch));

        zPoints[0] = from->z;
        zPoints[2] = fromScale * mathCosf(ROM_CURVE_NODE_ANGLE(from->yaw));
        zPoints[1] = to->z;
        zPoints[3] = toScale * mathCosf(ROM_CURVE_NODE_ANGLE(to->yaw));

        {
            outPos[0] = Curve_EvalHermite(xPoints, segmentT, &xTangent);
            if ((s8)ignoreY == 0)
            {
                outPos[1] = Curve_EvalHermite(yPoints, segmentT, &yTangent);
            }
            outPos[2] = Curve_EvalHermite(zPoints, segmentT, &zTangent);
        }

        length = sqrtf(xTangent * xTangent + zTangent * zTangent);
        if (length > 0.1f)
        {
            scale = offset[0] / length;
            *outAngle = (s16)(getAngle(xTangent, zTangent) + 0x8000);
            xTangent *= scale;
            zTangent *= scale;
            outPos[0] += zTangent;
            outPos[2] -= xTangent;
            if ((s8)ignoreY == 0)
            {
                outPos[1] += offset[1];
            }
        }
    }
    else
    {
        if (from == NULL)
        {
            from = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
        }
        if (from != NULL)
        {
            outPos[0] = from->x;
            if ((s8)ignoreY == 0)
            {
                outPos[1] = from->y + offset[1];
            }
            outPos[2] = from->z;
            outPos[0] += offset[0] * mathCosf(ROM_CURVE_NODE_ANGLE(from->yaw));
            outPos[2] += offset[0] * mathSinf(ROM_CURVE_NODE_ANGLE(from->yaw));
            *outAngle = (s16)(((s32)from->yaw << 8) + 0x8000);
        }
        else
        {
            return 0;
        }
    }
    return 1;
}

void ObjSeq_UpdateCurvePosition(GameObject* obj, u8* seq)
{
    GameObject* object;
    ObjSeqState* state;
    ObjSeqPlacement* placement;
    RomCurveNode* node;
    f32 outPos[3];
    f32 offset[3];
    f32 dx;
    f32 dy;
    f32 dz;
    f32 angleCos;
    f32 angleSin;

    object = obj;
    state = (ObjSeqState*)seq;
    placement = (ObjSeqPlacement*)object->anim.placementData;
    if (placement == NULL)
    {
        return;
    }

    if (state->curveId < 0)
    {
        dx = object->anim.localPosX - placement->baseX;
        dz = object->anim.localPosZ - placement->baseZ;
        angleSin = mathSinf((3.1415927f * (f32)state->heading) / 32768.0f);
        angleCos = mathCosf((3.1415927f * (f32)state->heading) / 32768.0f);
        object->anim.localPosX = angleSin * dz + (angleCos * dx + placement->baseX);
        object->anim.localPosZ = -(angleSin * dx - (angleCos * dz + placement->baseZ));
        return;
    }

    node = (RomCurveNode*)(*gRomCurveInterface)->getById(state->curveId);
    if (node == NULL)
    {
        return;
    }

    dx = object->anim.localPosX - placement->baseX;
    dy = object->anim.localPosY - placement->groundOffset;
    dz = object->anim.localPosZ - placement->baseZ;
    offset[0] = dx;
    offset[1] = dy;
    offset[2] = dz;
    outPos[0] = object->anim.localPosX;
    outPos[1] = object->anim.localPosY;
    outPos[2] = object->anim.localPosZ;

    if (node->links[0] < 0)
    {
        object->anim.localPosX = outPos[0];
        object->anim.localPosY = outPos[1];
        object->anim.localPosZ = outPos[2];
        return;
    }

    if (RomCurveInterp_EvaluateOffsetPosition(state->curveInterp, offset, outPos, &state->heading,
                                              state->groundSnapEnabled) != 0)
    {
        object->anim.localPosX = outPos[0];
        object->anim.localPosY = outPos[1];
        object->anim.localPosZ = outPos[2];
        return;
    }

    angleSin = mathSinf((3.1415927f * (f32)state->heading) / 32768.0f);
    angleCos = mathCosf((3.1415927f * (f32)state->heading) / 32768.0f);
    object->anim.localPosX = angleSin * dz + (angleCos * dx + placement->baseX);
    object->anim.localPosZ = -(angleSin * dx - (angleCos * dz + placement->baseZ));
}
int objSeqFindLabel(u8* seq, int label)
{
    int commandCount;
    int commandIndex;
    u32 packed;
    int currentLabel;
    ObjSeqCommand* command;

    currentLabel = 0;
    commandIndex = 0;
    commandCount = ((ObjSeqState*)seq)->cmdCount;
    while (commandIndex < commandCount)
    {
        command = (ObjSeqCommand*)(((ObjSeqState*)seq)->cmds + commandIndex * 4);
        if ((s8)((u8*)command)[0] == 0)
        {
            currentLabel = command->param;
        }
        else if ((s8)((u8*)command)[0] == 0xb)
        {
            if (command->param > 0)
            {
                packed = *(u32*)((u8*)command + 4);
                if ((int)(packed & 0x3f) == 9 && (int)(packed >> 16) == label)
                {
                    return currentLabel;
                }
                commandIndex += command->param;
            }
        }
        currentLabel += ((u8*)command)[1];
        commandIndex++;
    }
    return -1;
}

int objSeqFindConditional(u8* seq, GameObject* seqState)
{
    int currentLabel;
    int commandIndex;
    ObjSeqCommand* command;
    u32 packed;

    currentLabel = -1;
    commandIndex = 0;
    while (commandIndex < ((ObjSeqState*)seq)->cmdCount)
    {
        command = (ObjSeqCommand*)(((ObjSeqState*)seq)->cmds + commandIndex * 4);
        if ((s8)((u8*)command)[0] == 0)
        {
            currentLabel = command->param;
        }
        else if ((s8)((u8*)command)[0] == 0xb)
        {
            if (command->param > 0)
            {
                packed = *(u32*)((u8*)command + 4);
                if ((int)(packed & 0x3f) == 4 &&
                    ObjSeq_EvaluateCondition((packed >> 6) & 0x3ff, seq, seqState->anim.placementData) != 0)
                {
                    currentLabel -= 10;
                    if (currentLabel < 0)
                    {
                        currentLabel = 0;
                    }
                    return currentLabel;
                }
                commandIndex += command->param;
            }
        }
        currentLabel += ((u8*)command)[1];
        commandIndex++;
    }
    return -1;
}
void objCallSeqFn(GameObject* obj, GameObject* sourceObj, ObjSeqState* seq, int action)
{
    int callbackResult;
    s8 actionSlot;
    int movementState;
    int flags;
    u8* sourceModel;

    (void)action;

    sourceModel = (u8*)sourceObj->anim.placementData;
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
    obj->anim.previousWorldPosX = obj->anim.worldPosX;
    obj->anim.previousWorldPosY = obj->anim.worldPosY;
    obj->anim.previousWorldPosZ = obj->anim.worldPosZ;

    if (obj->animEventCallback != NULL)
    {
        callbackResult = (*(int (**)(GameObject*, GameObject*, ObjSeqState*, int))&obj->animEventCallback)(obj, sourceObj, seq, action);
        if (callbackResult == 4)
        {
            gObjSeqStop = 1;
        }
        else if (callbackResult != 0)
        {
            actionSlot = seq->slot;
            if (gObjSeqSlotResults[actionSlot] < 2)
            {
                gObjSeqSlotResults[actionSlot] = callbackResult;
            }
        }
        seq->eventCount = 0;
        seq->curEventId = 0;
    }
    else
    {
        if ((s8)seq->isCameraSeq != 0)
        {
            seq->movementState = 0;
            return;
        }

        movementState = (s8)seq->movementState;
        if (movementState >= 4)
        {
            if (ObjSeq_TurnToFacePlayer(obj, seq, 6, 0x1e, 0x50, -1, -1) != 0)
            {
                actionSlot = seq->slot;
                if (gObjSeqSlotResults[actionSlot] < 2)
                {
                    gObjSeqSlotResults[actionSlot] = 1;
                }
            }
        }
        else if (movementState != 0)
        {
            if (movementState != 2)
            {
                seq->posOffsetScale = 1.0f;
                seq->posOffsetX =
                    obj->anim.localPosX - sourceObj->anim.localPosX;
                seq->posOffsetY =
                    obj->anim.localPosY - sourceObj->anim.localPosY;
                seq->posOffsetZ =
                    obj->anim.localPosZ - sourceObj->anim.localPosZ;
                seq->movementState = 2;
            }
            if ((s8)sourceModel[0x20] == 1)
            {
                seq->posOffsetDecay = 0.016666668f;
                actionSlot = seq->slot;
                if (gObjSeqSlotResults[actionSlot] < 2)
                {
                    gObjSeqSlotResults[actionSlot] = 1;
                }
            }
            seq->posOffsetScale =
                seq->posOffsetScale - seq->posOffsetDecay * timeDelta;
            if (seq->posOffsetScale <= 0.0f)
            {
                seq->movementState = 0;
            }
        }
    }

    flags = obj->anim.resetHitboxFlags;
    flags &= ~7;
    obj->anim.resetHitboxFlags = flags;
    Obj_GetWorldPosition(obj, &obj->anim.worldPosX, &obj->anim.worldPosY, &obj->anim.worldPosZ);
    if (obj->anim.hitReactState != NULL)
    {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject = 0;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->priorityHitCount = 0;
    }
    if (obj->anim.hitboxTransformState != NULL)
    {
        obj->anim.hitboxTransformState->contactObjectCount = 0;
    }
}

void objSeqDoBgCmds0D(u8* seq, GameObject* obj, int skipSpawns)
{
    ObjSeqBgCmd* cmd;
    int cmdObj;
    int cmdParam;
    void* resource;
    int transitionSlot;
    int scriptedButtons;

    if (gObjSeqInputOverrideActive != 0 && obj->seqIndex != (s8)((ObjSeqState*)seq)->slot)
    {
        (*gGameUIInterface)->setInputOverride(0, 0, 0);
    }

    while (gObjSeqDeferredCmdCount > 0)
    {
        gObjSeqDeferredCmdCount--;
        cmd = &gObjSeqDeferredCmds[gObjSeqDeferredCmdCount];
        cmdParam = cmd->param;
        cmdObj = (int)cmd->object;

        switch (cmd->opcode)
        {
        case 3:
            if ((u8)skipSpawns == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)cmdObj, cmdParam, NULL, 0x10000, -1, NULL);
            }
            break;
        case 4:
            if ((u8)skipSpawns == 0)
            {
                ObjSeq_defaultActionCallback(cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
            }
            break;
        case 5:
            if ((u8)skipSpawns == 0)
            {
                resource = Resource_Acquire((u16)(cmdParam + 0xab), 1);
                if (resource != NULL)
                {
                    (*(void (**)(int, int, int, int, int, int, int))((char*)*(int**)resource + 0x4))(
                        cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
                }
                if (resource != NULL)
                {
                    Resource_Release(resource);
                }
            }
            break;
        case 9:
            if ((u8)skipSpawns == 0)
            {
                switch (cmdParam & 0x2f)
                {
                case 6:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->start(transitionSlot, SCREEN_TRANSITION_WHITE_WIPE);
                    break;
                case 7:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->step(transitionSlot, SCREEN_TRANSITION_WHITE_WIPE);
                    break;
                case 8:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->start(transitionSlot, SCREEN_TRANSITION_WHITE);
                    break;
                case 9:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->step(transitionSlot, SCREEN_TRANSITION_WHITE);
                    break;
                case 0xb:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->start(transitionSlot, SCREEN_TRANSITION_RED);
                    break;
                case 0xc:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->stepWithBlend(transitionSlot, SCREEN_TRANSITION_RED, 0.2f);
                    break;
                }
            }
            break;
        case 0xb:
            mainSetBits(cmdParam, 1);
            break;
        case 0xc:
            mainSetBits(cmdParam, 0);
            break;
        case 0xd:
            if ((u8)skipSpawns == 0)
            {
                scriptedButtons = gObjSeqScriptedButtonMasks[cmdParam];
                (*gGameUIInterface)->setInputOverride(scriptedButtons, 0, 0);
                if (gObjSeqScriptedButtonMasks[cmdParam] != -1)
                {
                    gObjSeqInputOverrideActive = 1;
                }
                else
                {
                    gObjSeqInputOverrideActive = 0;
                }
            }
            break;
        }
    }
}

int ObjSeq_ExecuteActionCommand(GameObject* obj, u8* action, u8** cmdPtr, s8 flags, void* out)
{
    u8* base = gObjSeqRuntimeBuffer;
    s8 noExec;
    s8 doUpdate;
    s8 flag8;
    s8 f;
    u8* seq;
    GameObject* activeObj;
    ObjSeqCommand* cmd;
    ObjSeqPlacement* model;
    ObjAnimState* animState;
    u8* act2;
    ObjAnimState* st2;
    u8* entry;
    s16* sfxTimerEntry;
    ObjSeqState* sfxState;
    int opcode;
    int sub;
    int restart;
    int reps;
    int val;
    int slot;
    int minRot;
    f32 blend;
    f32 t;

    (void)out;

    cmd = (ObjSeqCommand*)*cmdPtr;
    f = flags;
    noExec = (s8)(f & 1);
    doUpdate = (s8)(f & 2);
    flag8 = (s8)(f & 8);
    if (noExec == 0)
    {
        doUpdate = 1;
    }
    seq = obj->extra;
    model = (ObjSeqPlacement*)obj->anim.placementData;
    activeObj = *(GameObject**)seq;
    if (activeObj == NULL)
    {
        activeObj = obj;
    }

    opcode = (s8)((u8*)cmd)[0];
    switch (opcode)
    {
    case SEQACT_ANIM:
        if (flag8 != 0)
        {
            break;
        }
        ((ObjSeqState*)seq)->moveId = (s16)(cmd->param & 0xfff);
        if (activeObj->anim.classId == 1 && ((ObjSeqState*)seq)->moveId < 4)
        {
            ((ObjSeqState*)seq)->moveId += 0x531;
        }
        ((ObjSeqState*)seq)->moveBlendParam = (cmd->param >> 8) & 0xf0;
        if (action == NULL)
        {
            break;
        }
        animState = ((ObjAnimBank*)action)->currentState;
        if (activeObj->anim.currentMove == ((ObjSeqState*)seq)->moveId)
        {
            if ((s8)animState->frameType != 0)
            {
                restart = 0;
            }
            else
            {
                restart = 1;
            }
        }
        else
        {
            restart = 1;
        }
        if (doUpdate == 0)
        {
            break;
        }
        if (restart == 0)
        {
            break;
        }
        if ((((ObjSeqState*)seq)->flags & 4) == 0)
        {
            break;
        }
        if (action == NULL)
        {
            break;
        }
        animState->framePhase =
            activeObj->anim.currentMoveProgress * animState->frameLength;
        if (((ObjSeqState*)seq)->trackRunLength[10] != 0)
        {
            sub = ((ObjSeqState*)seq)->curFrame - 1;
            if (((ObjSeqState*)seq)->animEntries != NULL && ((ObjSeqState*)seq)->trackRunLength[10] != 0)
            {
                objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[10] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[10] & 0xfff, sub);
            }
        }
        if (activeObj->anim.classId == 1)
        {
            act2 = ObjSeq_GetActiveModel(activeObj);
            animState = ((ObjAnimBank*)act2)->currentState;
            animState->lastBlendMoveIndex = -1;
            animState->eventState = 0;
            animState->prevEventState = 0;
            st2 = ((ObjAnimBank*)act2)->activeState;
            if (st2 != NULL)
            {
                st2->lastBlendMoveIndex = -1;
                st2->eventCountdown = 0;
                st2->eventState = 0;
                st2->prevEventState = 0;
            }
        }
        ((ObjSeqState*)seq)->fade = 1.0f;
        ObjAnim_SetCurrentMove(activeObj, ((ObjSeqState*)seq)->moveId,
                               (f32)((ObjSeqState*)seq)->moveBlendParam / 256.0f, 0);
        break;
    case SEQACT_MOVEMODE:
        if (flag8 != 0)
        {
            break;
        }
        if ((s8)((ObjSeqState*)seq)->isCameraSeq != 0 && (s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] != 0)
        {
            ((ObjSeqState*)seq)->useRootMotionSpeed = 0;
            break;
        }
        ((ObjSeqState*)seq)->useRootMotionSpeed = 1 - ((ObjSeqState*)seq)->useRootMotionSpeed;
        break;
    case SEQACT_GROUND_MODE:
        *(s8*)&((ObjSeqState*)seq)->groundSnapEnabled = 1 - ((ObjSeqState*)seq)->groundSnapEnabled;
        break;
    case SEQACT_OVERRIDE:
        if (flag8 != 0)
        {
            break;
        }
        if ((f & 4) != 0)
        {
            break;
        }
        activeObj = ObjSeq_ToggleCommand3Target(obj, seq, model);
        activeObj->anim.activeMove = -1;
        break;
    case SEQACT_CONDITION:
        if (doUpdate != 0 && cmd->param > 0 && gObjSeqPendingCmd0BCount < 0x14)
        {
            *(u8**)((entry = base + gObjSeqPendingCmd0BCount * 8) + 0x2b34) = (u8*)cmd + 4;
            *(s16*)(entry + 0x2b3a) = ((ObjSeqState*)seq)->curFrame;
            reps = cmd->param;
            gObjSeqPendingCmd0BCount = gObjSeqPendingCmd0BCount + 1;
            *(s16*)(entry + 0x2b38) = reps;
        }
        ((ObjSeqState*)seq)->cmdCursor += cmd->param;
        break;
    case SEQACT_VTXANIM:
        if (flag8 != 0)
        {
            break;
        }
        if (doUpdate == 0)
        {
            break;
        }
        if (action == NULL)
        {
            break;
        }
        if (((ObjModel*)action)->file->morphTargetCount == 0)
        {
            break;
        }
        blend = (f32)(int)((cmd->param >> 8) & 0xff);
        if (blend != 0.0f)
        {
            t = 1.0f / blend;
        }
        else
        {
            t = 1.0f;
        }
        sub = cmd->param & 0xff;
        if (sub < 0xf)
        {
            ObjModel_SetBlendChannelTargets((ObjModel*)action, 2, ((ObjModel*)action)->blendChannels[2].morphTargetB, sub - 1,
                                            t, 0);
        }
        else
        {
            ObjModel_SetBlendChannelTargets((ObjModel*)action, 0, ((ObjModel*)action)->blendChannels[0].morphTargetB, sub - 1,
                                            t, 0);
        }
        break;
    case SEQACT_STORYBOARD:
        if (flag8 != 0)
        {
            break;
        }
        (*gGameUIInterface)->showNpcDialogue(cmd->param, 0x14, 0x8c, 0);
        break;
    case SEQACT_ENVFX:
        if (noExec != 0)
        {
            break;
        }
        if (((cmd->param >> 12) & 0xf) == 8)
        {
            break;
        }
        if ((s8)gObjSeqDeferredCmdCount < 10)
        {
            entry = base + gObjSeqDeferredCmdCount * 8;
            *(GameObject**)(entry + 0x3ca4) = activeObj;
            *(s8*)((int)entry + 0x3caa) = (s8)((cmd->param >> 12) & 0xf);
            if (*(s8*)((int)entry + 0x3caa) == 0xb || *(s8*)((int)entry + 0x3caa) == 0xc)
            {
                u8* entry2;
                val = ((ObjSeqCommand*)cmd)[1].param;
                entry2 = base + (s8)(gObjSeqDeferredCmdCount++) * 8;
                *(s16*)(entry2 + 0x3ca8) = val;
            }
            else
            {
                val = (s16)(cmd->param & 0xfff);
                gObjSeqDeferredCmdCount++;
                *(s16*)(entry + 0x3ca8) = val;
            }
        }
        break;
    case SEQACT_SETTIME:
        break;
    }

    if (noExec != 0)
    {
        return 0;
    }

    if ((s8)gObjSeqSkippingToEnd != 0 || (s8)lbl_803DD111 != 0)
    {
        if ((s8)((u8*)cmd)[0] == 0xd)
        {
            switch ((cmd->param >> 12) & 0xf)
            {
            case 2:
                getEnvfxActVoid(activeObj, activeObj, cmd->param & 0xfff, 0);
                break;
            case 6:
                warpToMap(cmd->param & 0xfff, 0);
                break;
            case 5:
                break;
            }
        }
        return 0;
    }

    switch ((s8)((u8*)cmd)[0])
    {
    case SEQACT_SFX:
        if (flag8 != 0)
        {
            break;
        }
        if (((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x20) == 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 3)
        {
            break;
        }
        if (((cmd->param >> 12) & 0xf) != 0xf)
        {
            Sfx_PlayFromObject(obj, (u16)(cmd->param & 0xfff));
        }
        else
        {
            Sfx_PlayFromObject(obj, (u16)(cmd->param & 0xfff));
            ((ObjSeqState*)seq)->sfxTimer[3] = -1;
            ((ObjSeqState*)seq)->sfxId[3] = (s16)(cmd->param & 0xfff);
        }
        break;
    case SEQACT_ENVFX:
        switch ((cmd->param >> 12) & 0xf)
        {
        case 0:
            if (((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x20) != 0)
            {
                val = (cmd->param & 0xfff) + 1;
                if (val == 0xd9 || val == 0x92)
                {
                    Music_Trigger(val, 1);
                }
            }
            break;
        case 2:
            getEnvfxActVoid(activeObj, activeObj, cmd->param & 0xfff, 0);
            break;
        case 6:
            if (flag8 != 0)
            {
                break;
            }
            warpToMap(cmd->param & 0xfff, 0);
            break;
        case 7:
            if (flag8 != 0)
            {
                break;
            }
            break;
        case 8:
            if (flag8 != 0)
            {
                break;
            }
            ((ObjSeqState*)seq)->texId5 = (u8)(cmd->param & 0xfff);
            ((ObjSeqState*)seq)->texId4 = ((ObjSeqState*)seq)->texId5;
            break;
        case 0xe:
            if (flag8 != 0)
            {
                break;
            }
            ((ObjSeqState*)seq)->texId5 = (u8)(cmd->param & 0xfff);
            break;
        case 0xf:
            if (flag8 != 0)
            {
                break;
            }
            ((ObjSeqState*)seq)->texId4 = (u8)(cmd->param & 0xfff);
            break;
        }
        break;
    case SEQACT_SFX_WITH_DURATION:
        if (flag8 != 0)
        {
            break;
        }
        if (((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x20) == 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 3)
        {
            break;
        }
        if (((cmd->param >> 12) & 0xf) != 0xf)
        {
            minRot = 0x7fff;
            slot = 0;
            for (val = 0; val < 3; val++)
            {
                if (((ObjSeqState*)seq)->sfxTimer[val] < (s16)minRot)
                {
                    slot = val;
                    minRot = ((ObjSeqState*)seq)->sfxTimer[val];
                }
            }
        }
        else
        {
            slot = 3;
        }
        sfxTimerEntry = &((ObjSeqState*)seq)->sfxTimer[slot];
        if (*sfxTimerEntry > 0)
        {
            Sfx_RemoveLoopedObjectSound(obj, (u16)((ObjSeqState*)seq)->sfxId[slot]);
        }
        ((u8*)cmd)[1] = ((u8*)cmd)[5];
        ((u8*)cmd)[4] = 0x63;
        *sfxTimerEntry = ((ObjSeqCommand*)cmd)[1].param;
        sfxState = (ObjSeqState*)seq;
        sfxState->sfxId[slot] = (s16)(cmd->param & 0xfff);
        Sfx_AddLoopedObjectSound(obj, (u16)sfxState->sfxId[slot]);
        break;
    }
    return 0;
}


void ObjSeq_SetupInitialPlaybackState(GameObject* obj, GameObject** seqObj, u8* seq, ObjSeqPlacement* placement, void** outAction)
{
    GameObject* activeObj;
    s16* modelVec;
    f32 groundY[2];
    long long time;
    u8* historyBase;

    historyBase = gObjSeqRuntimeBuffer;
    if ((s8)((ObjSeqState*)seq)->isCameraSeq != 0)
    {
        gObjSeqCamModeArgB = 1;
        gObjSeqCamModeArgD = 0x5a;
        gObjSeqCamMode = 0x42;
    }

    ((ObjSeqState*)seq)->curFrame = ((ObjSeqState*)seq)->pendingStartFrame;
    ((ObjSeqState*)seq)->prevFrame = -0x3c;
    ObjSeq_ApplyFrameCurves(obj, *seqObj, seq, 0);
    ObjSeq_RebuildCurveStateToFrame(obj, *seqObj, seq, 1);

    activeObj = *(GameObject**)obj->extra;
    if (activeObj == NULL)
    {
        activeObj = obj;
    }
    *outAction = ObjSeq_GetActiveModel(activeObj);
    *seqObj = activeObj;

    ObjSeq_UpdateCurvePosition(obj, seq);
    if ((s8)((ObjSeqState*)seq)->groundSnapEnabled == 1 &&
        trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY,
                             obj->anim.localPosZ, groundY, 0) == 0)
    {
        obj->anim.localPosY =
            obj->anim.localPosY +
            ((obj->anim.localPosY - groundY[0]) - placement->groundOffset);
    }

    obj->anim.rotX += ((ObjSeqState*)seq)->heading;
    if (*seqObj != obj && (s8)gObjSeqFnDispatched == 0)
    {
        objCallSeqFn(*seqObj, obj, (ObjSeqState*)seq, ((u8*)(historyBase + 0x3c4c))[(s8)((ObjSeqState*)seq)->slot]);
    }

    ObjSeq_ApplyLinkedObjectTransform(obj, *seqObj, seq);
    ((ObjSeqState*)seq)->texId5 = 0;
    ((ObjSeqState*)seq)->texId4 = 0;
    ((ObjSeqState*)seq)->runState = 1;
    ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
    if ((s8)gObjSeqStop != 0)
    {
        animatedObjFreeAndSavePlayerPos(obj, *seqObj, seq);
    }

    ((f32*)(historyBase + 0x3740))[(s8)((ObjSeqState*)seq)->slot] = (f32)((ObjSeqState*)seq)->curFrame;
    ((s16*)(historyBase + 0x2be0))[(s8)((ObjSeqState*)seq)->slot] = ((ObjSeqState*)seq)->curFrame;
    time = OSGetTime();
    ((long long*)(historyBase + 0x2f38))[(s8)((ObjSeqState*)seq)->slot] = time;
    time = OSGetTime();
    ((long long*)(historyBase + 0x2c90))[(s8)((ObjSeqState*)seq)->slot] = time;

    if (*seqObj != NULL)
    {
        objModelClearJointVectors(*seqObj);
        if ((*seqObj)->anim.classId == 1)
        {
            modelVec = objFindJointPoseVector(obj, 1);
            if (modelVec != NULL)
            {
                modelVec[0] = 0;
                modelVec[1] = 0;
                modelVec[2] = 0;
            }
        }
    }
}

void* ObjSeq_ToggleCommand3Target(GameObject* obj, u8* seq, ObjSeqPlacement* placement)
{
    void* result;
    GameObject* activeObj;
    ObjSeqLinkedPair* entry;
    int j;
    ObjSeqLinkedPair* slotBase;
    int slotOff;
    GameObject* seqObj;
    f32 groundY[2];

    result = obj;
    ((ObjSeqState*)seq)->targetAttached = (s8)(((ObjSeqState*)seq)->targetAttached ^ 1);
    if ((s8)((ObjSeqState*)seq)->targetAttached != 0)
    {
        ObjSeq_resolveTargetObject(obj);
        seqObj = *(GameObject**)seq;
        if (seqObj != NULL)
        {
            result = seqObj;
            seqObj->pendingParentObj = obj;
            seqObj->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
            ((ObjSeqState*)seq)->callbackContext = seqObj;

            activeObj = *(GameObject**)seq;
            j = 0;
            slotOff = (s8)((ObjSeqState*)seq)->slot * 0x80;
            slotBase = (ObjSeqLinkedPair*)(gObjSeqRuntimeBuffer + slotOff);
            entry = slotBase;
            for (; j < OBJSEQ_LINKED_PAIRS_PER_SLOT; j++)
            {
                if (entry->seqObj == NULL || entry->seqObj == activeObj)
                {
                    break;
                }
                entry++;
            }
            slotBase[j].seqObj = activeObj;
            ((ObjSeqLinkedPair*)((u8*)(int)gObjSeqRuntimeBuffer + slotOff))[j].ownerObj = obj;
        }
    }
    else
    {
        if (((ObjSeqState*)seq)->targetObj != NULL)
        {
            if ((((ObjSeqState*)seq)->flags & 1) != 0)
            {
                obj->anim.localPosX = obj->anim.localPosX;
                obj->anim.localPosY = obj->anim.localPosY;
                obj->anim.localPosZ = obj->anim.localPosZ;
                ObjSeq_UpdateCurvePosition(obj, seq);
            }
            if ((s8)((ObjSeqState*)seq)->groundSnapEnabled == 1 &&
                trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY,
                                     obj->anim.localPosZ, groundY, 0) == 0)
            {
                obj->anim.localPosY =
                    obj->anim.localPosY +
                    ((obj->anim.localPosY - groundY[0]) - placement->groundOffset);
            }
            if ((((ObjSeqState*)seq)->flags & 2) != 0)
            {
                obj->anim.rotX += ((ObjSeqState*)seq)->heading;
            }
            obj->pendingParentObj = NULL;
            obj->objectFlags &= ~OBJECT_OBJFLAG_SEQ_ATTACHED;
            ((ObjSeqState*)seq)->targetObj = NULL;
            result = obj;
        }
    }
    return result;
}

void ObjSeq_RefreshActionCursor(void* obj, void* seqFile, u8* seq)
{
    int actionIndex;
    ObjSeqCommand* command;
    u8 opcode;
    int stop;

    if (((ObjSeqState*)seq)->cmds == NULL)
    {
        return;
    }

    ((ObjSeqState*)seq)->retriggerFrame = -1;
    ((ObjSeqState*)seq)->cmdCursor = 0;
    ((ObjSeqState*)seq)->fade = 0.0f;
    stop = 0;
    while (stop == 0 && ((ObjSeqState*)seq)->cmdCursor < ((ObjSeqState*)seq)->cmdCount)
    {
        actionIndex = ((ObjSeqState*)seq)->cmdCursor;
        command = (ObjSeqCommand*)(((ObjSeqState*)seq)->cmds + actionIndex * 4);
        opcode = ((u8*)command)[0];
        if ((s8)opcode == 0)
        {
            if (((ObjSeqState*)seq)->curFrame >= command->param)
            {
                ((ObjSeqState*)seq)->retriggerFrame = command->param;
                ((ObjSeqState*)seq)->cmdCursor++;
            }
            else
            {
                stop = 1;
            }
        }
        else if ((s8)opcode == 0xb && command->param > 0)
        {
            if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->retriggerFrame)
            {
                ((ObjSeqState*)seq)->retriggerFrame += ((u8*)command)[1];
                ((ObjSeqState*)seq)->cmdCursor = (s16)(((ObjSeqState*)seq)->cmdCursor + (command->param + 1));
            }
            else
            {
                stop = 1;
            }
        }
        else if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->retriggerFrame)
        {
            if ((s8)((u8*)command)[0] != 0xf)
            {
                ((ObjSeqState*)seq)->retriggerFrame += ((u8*)command)[1];
            }
            ((ObjSeqState*)seq)->cmdCursor++;
        }
        else
        {
            stop = 1;
        }
    }
}
void ObjSeq_RebuildCurveStateToFrame(GameObject* obj, GameObject* seqObj, u8* seq, int mode)
{
    struct
    {
        f32 x;
        f32 y;
        f32 z;
    } pos;
    f32* posp;
    int out[3];
    ObjSeqCommand* cmd;
    f32 speed;
    ObjSeqPlacement* model;
    u8* action;
    int found;
    int i;
    int targetFrame;
    s8 flags;
    int stop;
    int frame;
    f32 val;
    f32 rate;
    f32 prevX;
    f32 prevZ;
    int opcode;
    ObjSeqBgCmd* entry;

    ObjSeqState* state = (ObjSeqState*)seq;

    if (state->cmds == NULL)
    {
        return;
    }

    flags = 1;
    if (mode != 0)
    {
        flags |= 2;
    }

    model = (ObjSeqPlacement*)obj->anim.placementData;
    targetFrame = state->curFrame;
    lbl_803DD08A = targetFrame;
    state->cmdCursor = 0;
    state->retriggerFrame = -0x32;
    state->useRootMotionSpeed = 0;
    state->groundSnapEnabled = 0;
    state->targetAttached = 0;
    state->targetObj = NULL;
    state->isCameraSeq = 0;
    state->fade = 0.0f;
    state->curFrame = -1;

    found = -1;
    seqObj = obj;
    i = 0;
    while (i < state->cmdCount && state->curFrame <= targetFrame)
    {
        cmd = (ObjSeqCommand*)(state->cmds + i * 4);
        opcode = ((u8*)cmd)[0];
        switch ((s8)opcode)
        {
        case 3:
            flags = (s8)(flags | 4);
            seqObj = ObjSeq_ToggleCommand3Target(obj, seq, model);
            seqObj->anim.activeMove = -1;
            break;
        case 0:
            state->curFrame = cmd->param;
            break;
        case 9:
            found = state->curFrame;
            break;
        case 11:
            if (cmd->param > 0)
            {
                i += cmd->param;
            }
            break;
        default:
            if ((s8)opcode != 0xf)
            {
                state->curFrame += ((u8*)cmd)[1];
            }
            break;
        }
        i++;
    }

    state->curFrame = found;
    action = (u8*)seqObj->anim.banks[seqObj->anim.bankIndex];
    if (action != NULL)
    {
        val = ObjSeq_SampleTrackCurve(seq, 13, -1);
        prevX = model->baseX + val;
        val = ObjSeq_SampleTrackCurve(seq, 11, -1);
        prevZ = model->baseZ + val;
    }

    posp = &pos.x;
    entry = lbl_8039944C;
    while (state->curFrame < targetFrame)
    {
        state->curFrame += 1;
        frame = state->curFrame;
        val = ObjSeq_SampleTrackCurve(seq, 13, frame);
        pos.x = model->baseX + val;
        frame = state->curFrame;
        val = ObjSeq_SampleTrackCurve(seq, 12, frame);
        pos.y = model->groundOffset + val;
        frame = state->curFrame;
        val = ObjSeq_SampleTrackCurve(seq, 11, frame);
        pos.z = model->baseZ + val;

        if (state->curFrame > 0 && mode != 0)
        {
            if ((s8)state->useRootMotionSpeed == 1 && (s8)state->isCameraSeq == 0 &&
                action != NULL)
            {
                f32 dx = posp[0] - prevX;
                if (ObjAnim_SampleRootCurvePhase(&seqObj->anim,
                                                 sqrtf(dx * dx + (posp[2] - prevZ) * (posp[2] - prevZ)),
                                                 &speed) == 0)
                {
                    frame = state->curFrame - 1;
                    val = ObjSeq_SampleTrackCurve(seq, 9, frame);
                    speed = 0.0004f * val;
                }
            }
            else
            {
                frame = state->curFrame - 1;
                val = ObjSeq_SampleTrackCurve(seq, 9, frame);
                speed = 0.0004f * val;
            }

            if (action != NULL)
            {
                ObjAnim_AdvanceCurrentMove(seqObj, speed, 1.0f,
                                                                            &state->animEvents);
                if (mode != 0)
                {
                    if (state->fade > 0.0f)
                    {
                        if (state->trackRunLength[10] != 0)
                        {
                            frame = state->curFrame - 1;
                            rate = ObjSeq_SampleTrackCurve(seq, 10, frame);
                        }
                        else
                        {
                            rate = 8.0f;
                        }
                        if (rate < 1.0f)
                        {
                            rate = 1.0f;
                        }
                        rate = 1.0f / rate;
                        state->fade -= rate;
                        if (state->fade < 0.0f)
                        {
                            state->fade = 0.0f;
                        }
                    }
                }
            }
            else
            {
                seqObj->anim.currentMoveProgress += speed;
                val = 1.0f;
                while (seqObj->anim.currentMoveProgress > val)
                {
                    seqObj->anim.currentMoveProgress -= val;
                }
                rate = 1.0f;
                while (seqObj->anim.currentMoveProgress < 0.0f)
                {
                    seqObj->anim.currentMoveProgress += rate;
                }
            }
        }

        prevX = posp[0];
        prevZ = posp[2];

        stop = 0;
        gObjSeqPendingCmd0BCount = 0;
        while (stop == 0 && state->cmdCursor < state->cmdCount)
        {
            cmd = (ObjSeqCommand*)(state->cmds + state->cmdCursor * 4);
            opcode = (s8)((u8*)cmd)[0];
            if (opcode == 0)
            {
                if (state->curFrame >= cmd->param)
                {
                    state->retriggerFrame = cmd->param;
                    state->cmdCursor += 1;
                }
                else
                {
                    stop = 1;
                }
            }
            else
            {
                if (state->curFrame >= state->retriggerFrame)
                {
                    if (opcode != 0xf)
                    {
                        state->retriggerFrame += ((u8*)cmd)[1];
                    }
                    state->cmdCursor += 1;
                    if (ObjSeq_ExecuteActionCommand(obj, (u8*)action, (u8**)&cmd, flags, out) != 0)
                    {
                        return;
                    }
                    {
                        GameObject* t = *(GameObject**)obj->extra;
                        if (t == NULL)
                        {
                            t = obj;
                        }
                        action = ObjSeq_GetActiveModel(t);
                        seqObj = t;
                    }
                }
                else
                {
                    stop = 1;
                }
            }
        }

        for (i = 0; i < gObjSeqPendingCmd0BCount; i++)
        {
            if (seqDoSubCmd0B(obj, seqObj, seq, (u8*)entry[i].object, entry[i].flags, entry[i].param, 1, 0) != 0)
            {
                i = gObjSeqPendingCmd0BCount;
            }
            {
                GameObject* t = *(GameObject**)obj->extra;
                if (t == NULL)
                {
                    t = obj;
                }
                action = ObjSeq_GetActiveModel(t);
                seqObj = t;
            }
        }
        gObjSeqPendingCmd0BCount = 0;
    }
}

void ObjSeq_ApplyFrameCurves(GameObject* obj, GameObject* seqObj, u8* seq, int frame)
{
    ObjSeqPlacement* model;
    s16* vec;
    s16* vec2;
    ObjTextureRuntimeSlot* tex1;
    ObjTextureRuntimeSlot* tex2;
    ObjTextureRuntimeSlot* tex5;
    int slots;
    int k;
    int* modelIds;
    int i;
    int vol;
    s16 scroll;
    f32 val;

    model = (ObjSeqPlacement*)obj->anim.placementData;
    obj->anim.localPosX = model->baseX;
    obj->anim.localPosY = model->groundOffset;
    obj->anim.localPosZ = model->baseZ;
    obj->anim.rotY = 0;
    obj->anim.rotX = 0;
    obj->anim.rotZ = 0;
    if ((((ObjSeqState*)seq)->flags & 0x20) != 0)
    {
        seqObj->anim.alpha = 0xff;
    }
    gObjSeqCurvePosOffsetX = 0.0f;
    gObjSeqCurvePosOffsetY = 0.0f;
    gObjSeqCurvePosOffsetZ = 0.0f;

    if (((ObjSeqState*)seq)->animEntries != NULL)
    {
        val = ObjSeq_SampleTrackCurve(seq, 18, frame);
        vol = val;

        for (i = 0; i < 3; i++)
        {
            if (((ObjSeqState*)seq)->sfxTimer[i] != 0)
            {
                Sfx_IsPlayingFromObject(seqObj, (u16)((ObjSeqState*)seq)->sfxId[i]);
            }
        }

        if (vol > 0 && ((ObjSeqState*)seq)->sfxTimer[3] != 0)
        {
            if (Sfx_IsPlayingFromObject(seqObj, (u16)((ObjSeqState*)seq)->sfxId[3]) != 0)
            {
                Sfx_SetObjectSfxVolume(seqObj, (u16)((ObjSeqState*)seq)->sfxId[3], vol, 0.5f);
            }
        }

        if (((ObjSeqState*)seq)->animEntries == NULL)
        {
            val = 0.0f;
        }
        else
        {
            val = 0.0f;
            if (((ObjSeqState*)seq)->trackRunLength[7] != 0)
            {
                val = objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[7] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[7] & 0xfff, frame);
            }
        }
        obj->anim.rotX = 182.044f * val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
        {
            val = 0.0f;
        }
        else
        {
            val = 0.0f;
            if (((ObjSeqState*)seq)->trackRunLength[8] != 0)
            {
                val = objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[8] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[8] & 0xfff, frame);
            }
        }
        obj->anim.rotY = 182.044f * val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
        {
            val = 0.0f;
        }
        else
        {
            val = 0.0f;
            if (((ObjSeqState*)seq)->trackRunLength[6] != 0)
            {
                val = objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[6] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[6] & 0xfff, frame);
            }
        }
        obj->anim.rotZ = 182.044f * val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
        {
            val = 0.0f;
        }
        else
        {
            val = 0.0f;
            if (((ObjSeqState*)seq)->trackRunLength[13] != 0)
            {
                val = objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[13] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[13] & 0xfff, frame);
            }
        }
        gObjSeqCurvePosOffsetX = val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
        {
            val = 0.0f;
        }
        else
        {
            val = 0.0f;
            if (((ObjSeqState*)seq)->trackRunLength[12] != 0)
            {
                val = objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[12] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[12] & 0xfff, frame);
            }
        }
        gObjSeqCurvePosOffsetY = val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
        {
            val = 0.0f;
        }
        else
        {
            val = 0.0f;
            if (((ObjSeqState*)seq)->trackRunLength[11] != 0)
            {
                val = objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[11] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[11] & 0xfff, frame);
            }
        }
        gObjSeqCurvePosOffsetZ = val;

        gObjSeqLinkedSavedPosX = gObjSeqCurvePosOffsetX;
        gObjSeqLinkedSavedPosY = gObjSeqCurvePosOffsetY;
        gObjSeqLinkedSavedPosZ = gObjSeqCurvePosOffsetZ;
        gObjSeqLinkedSavedPitch = obj->anim.rotX;
        gObjSeqLinkedTransformValid = 1;
        obj->anim.localPosX = model->baseX + gObjSeqCurvePosOffsetX;
        obj->anim.localPosY = model->groundOffset + gObjSeqCurvePosOffsetY;
        obj->anim.localPosZ = model->baseZ + gObjSeqCurvePosOffsetZ;

        if (((ObjSeqState*)seq)->trackRunLength[14] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = 0.0f;
            }
            else
            {
                val = 0.0f;
                if (((ObjSeqState*)seq)->trackRunLength[14] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[14] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[14] & 0xfff, frame);
                }
            }
            if ((s8)((ObjSeqState*)seq)->isCameraSeq != 0)
            {
                if (val < 35.0f)
                {
                    val = 35.0f;
                }
                if (val > 120.0f)
                {
                    val = 125.0f;
                }
                gObjSeqFovOverrideActive = 1;
                gObjSeqFovOverrideValue = val;
            }
            else
            {
                ((ObjSeqState*)seq)->unk10 = val;
            }
        }

        if ((((ObjSeqState*)seq)->flags & 0x20) != 0 && ((ObjSeqState*)seq)->trackRunLength[3] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = 0.0f;
            }
            else
            {
                val = 0.0f;
                if (((ObjSeqState*)seq)->trackRunLength[3] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[3] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[3] & 0xfff, frame);
                }
            }
            if (val < 0.0f)
            {
                val = 0.0f;
            }
            if (val > 255.0f)
            {
                val = 255.0f;
            }
            seqObj->anim.alpha = val;
        }

        if (((ObjSeqState*)seq)->trackRunLength[4] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = 0.0f;
            }
            else
            {
                val = 0.0f;
                if (((ObjSeqState*)seq)->trackRunLength[4] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[4] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[4] & 0xfff, frame);
                }
            }
            (*gSkyInterface)->setTimeOfDay(60.0f * val);
        }

        if ((((ObjSeqState*)seq)->flags & 0x10) != 0 && ((ObjSeqState*)seq)->trackRunLength[5] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = 0.0f;
            }
            else
            {
                val = 0.0f;
                if (((ObjSeqState*)seq)->trackRunLength[5] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[5] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[5] & 0xfff, frame);
                }
            }
            seqObj->anim.rootMotionScale = val * seqObj->anim.modelInstance->rootMotionScaleBase;
        }

        if ((((ObjSeqState*)seq)->flags & 8) != 0)
        {
            vec = objFindJointPoseVector(seqObj, 0);
            if (vec != NULL)
            {
                if (((ObjSeqState*)seq)->trackRunLength[1] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
                    {
                        val = 0.0f;
                    }
                    else
                    {
                        val = 0.0f;
                        if (((ObjSeqState*)seq)->trackRunLength[1] != 0)
                        {
                            val = objCurveInterpolate((ObjCurveKey*)(((ObjSeqState*)seq)->animEntries +
                                                                     ((ObjSeqState*)seq)->trackAnimStart[1] * 8),
                                                      ((ObjSeqState*)seq)->trackRunLength[1] & 0xfff, frame);
                        }
                    }
                }
                else
                {
                    val = 0.0f;
                }
                vec[0] = (s16)(((ObjSeqState*)seq)->baseRotX + (int)(182.044f * val));

                if (((ObjSeqState*)seq)->trackRunLength[2] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
                    {
                        val = 0.0f;
                    }
                    else
                    {
                        val = 0.0f;
                        if (((ObjSeqState*)seq)->trackRunLength[2] != 0)
                        {
                            val = objCurveInterpolate((ObjCurveKey*)(((ObjSeqState*)seq)->animEntries +
                                                                     ((ObjSeqState*)seq)->trackAnimStart[2] * 8),
                                                      ((ObjSeqState*)seq)->trackRunLength[2] & 0xfff, frame);
                        }
                    }
                }
                else
                {
                    val = 0.0f;
                }
                vec[1] = (s16)(((ObjSeqState*)seq)->baseRotY + (int)(182.044f * val));

                if (((ObjSeqState*)seq)->trackRunLength[0] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
                    {
                        val = 0.0f;
                    }
                    else
                    {
                        val = 0.0f;
                        if (((ObjSeqState*)seq)->trackRunLength[0] != 0)
                        {
                            val = objCurveInterpolate((ObjCurveKey*)(((ObjSeqState*)seq)->animEntries +
                                                                     ((ObjSeqState*)seq)->trackAnimStart[0] * 8),
                                                      ((ObjSeqState*)seq)->trackRunLength[0] & 0xfff, frame);
                        }
                    }
                }
                else
                {
                    val = 0.0f;
                }
                vec[2] = 182.044f * val;

                if ((((ObjSeqState*)seq)->flags & 0x400) != 0)
                {
                    slots = ((ObjSeqState*)seq)->flags136.modelSlot;
                    modelIds = objGetLookAtJointKeys();
                    if (slots == 0)
                    {
                        slots = 9;
                    }
                    if (vec != NULL)
                    {
                        for (k = 1, modelIds++; k < slots; modelIds++, k++)
                        {
                            vec2 = objFindJointPoseVector(seqObj, *modelIds);
                            if (vec2 != NULL)
                            {
                                vec2[1] = vec[1];
                                vec2[0] = vec[0];
                                vec2[2] = vec[2];
                            }
                        }
                    }
                }
            }
        }

        if ((((ObjSeqState*)seq)->flags & 0x200) != 0)
        {
            vec = objFindJointPoseVector(seqObj, 1);
            if (vec != NULL)
            {
                if (((ObjSeqState*)seq)->trackRunLength[17] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
                    {
                        val = 0.0f;
                    }
                    else
                    {
                        val = 0.0f;
                        if (((ObjSeqState*)seq)->trackRunLength[17] != 0)
                        {
                            val = objCurveInterpolate((ObjCurveKey*)(((ObjSeqState*)seq)->animEntries +
                                                                     ((ObjSeqState*)seq)->trackAnimStart[17] * 8),
                                                      ((ObjSeqState*)seq)->trackRunLength[17] & 0xfff, frame);
                        }
                    }
                }
                else
                {
                    val = 0.0f;
                }
                vec[0] = 182.044f * val;
            }
        }

        if ((((ObjSeqState*)seq)->flags & 0x40) != 0)
        {
            tex1 = objFindTexture(seqObj, 1, 0);
            tex2 = objFindTexture(seqObj, 0, 0);
            if (tex1 != NULL || tex2 != NULL)
            {
                if (((ObjSeqState*)seq)->trackRunLength[15] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
                    {
                        val = 0.0f;
                    }
                    else
                    {
                        val = 0.0f;
                        if (((ObjSeqState*)seq)->trackRunLength[15] != 0)
                        {
                            val = objCurveInterpolate((ObjCurveKey*)(((ObjSeqState*)seq)->animEntries +
                                                                     ((ObjSeqState*)seq)->trackAnimStart[15] * 8),
                                                      ((ObjSeqState*)seq)->trackRunLength[15] & 0xfff, frame);
                        }
                    }
                }
                else
                {
                    val = 0.0f;
                }
                scroll = 10.0f * val;
                if (tex1 != NULL)
                {
                    tex1->offsetS = scroll;
                }
                if (tex2 != NULL)
                {
                    tex2->offsetS = (s16)-scroll;
                }

                if (((ObjSeqState*)seq)->trackRunLength[16] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
                    {
                        val = 0.0f;
                    }
                    else
                    {
                        val = 0.0f;
                        if (((ObjSeqState*)seq)->trackRunLength[16] != 0)
                        {
                            val = objCurveInterpolate((ObjCurveKey*)(((ObjSeqState*)seq)->animEntries +
                                                                     ((ObjSeqState*)seq)->trackAnimStart[16] * 8),
                                                      ((ObjSeqState*)seq)->trackRunLength[16] & 0xfff, frame);
                        }
                    }
                }
                else
                {
                    val = 0.0f;
                }
                scroll = (s16) - (int)(10.0f * val);
                if (tex1 != NULL)
                {
                    tex1->offsetT = scroll;
                }
                if (tex2 != NULL)
                {
                    tex2->offsetT = scroll;
                }
            }

            tex5 = objFindTexture(seqObj, 5, 0);
            tex2 = objFindTexture(seqObj, 4, 0);
            if (tex5 != NULL)
            {
                tex5->textureId = (s16)((ObjSeqState*)seq)->texId5 << 8;
            }
            if (tex2 != NULL)
            {
                tex2->textureId = (s16)((ObjSeqState*)seq)->texId4 << 8;
            }
        }
    }
    else
    {
        gObjSeqLinkedSavedPosX = 0.0f;
        gObjSeqLinkedSavedPosY = 0.0f;
        gObjSeqLinkedSavedPosZ = 0.0f;
        gObjSeqLinkedSavedPitch = 0;
        gObjSeqLinkedTransformValid = 1;
    }
}

void ObjSeq_ApplyLinkedObjectTransform(GameObject* obj, GameObject* seqObj, u8* seq)
{
    s16 basePitch;
    int baseYaw;
    int baseRoll;
    f32 baseX;
    f32 baseY;
    f32 baseZ;

    if (seqObj->anim.parent == obj->anim.parent || (s8)gObjSeqLinkedTransformValid == 0)
    {
        baseX = obj->anim.localPosX;
        baseY = obj->anim.localPosY;
        baseZ = obj->anim.localPosZ;
        basePitch = obj->anim.rotX;
    }
    else
    {
        baseX = gObjSeqLinkedSavedPosX;
        baseY = gObjSeqLinkedSavedPosY;
        baseZ = gObjSeqLinkedSavedPosZ;
        basePitch = gObjSeqLinkedSavedPitch;
    }

    baseYaw = obj->anim.rotY;
    baseRoll = obj->anim.rotZ;
    if (seqObj != obj)
    {
        if ((((ObjSeqState*)seq)->flags & 1) != 0)
        {
            if ((s8)((ObjSeqState*)seq)->movementState == 2)
            {
                seqObj->anim.localPosX =
                    ((ObjSeqState*)seq)->posOffsetX * ((ObjSeqState*)seq)->posOffsetScale + baseX;
                seqObj->anim.localPosY =
                    ((ObjSeqState*)seq)->posOffsetY * ((ObjSeqState*)seq)->posOffsetScale + baseY;
                seqObj->anim.localPosZ =
                    ((ObjSeqState*)seq)->posOffsetZ * ((ObjSeqState*)seq)->posOffsetScale + baseZ;
            }
            else
            {
                seqObj->anim.localPosX = baseX;
                seqObj->anim.localPosY = baseY;
                seqObj->anim.localPosZ = baseZ;
            }
        }
        if ((((ObjSeqState*)seq)->flags & 2) != 0)
        {
            if ((s8)((ObjSeqState*)seq)->movementState == 2)
            {
                seqObj->anim.rotX = (s16)((s32)basePitch + (s32)((f32)((ObjSeqState*)seq)->rotOffsetX *
                                                                   ((ObjSeqState*)seq)->posOffsetScale));
                seqObj->anim.rotY =
                    (s16)(baseYaw + (s32)((f32)((ObjSeqState*)seq)->rotOffsetY * ((ObjSeqState*)seq)->posOffsetScale));
                seqObj->anim.rotZ =
                    (s16)(baseRoll + (s32)((f32)((ObjSeqState*)seq)->rotOffsetZ * ((ObjSeqState*)seq)->posOffsetScale));
            }
            else
            {
                seqObj->anim.rotX = basePitch;
                seqObj->anim.rotY = baseYaw;
                seqObj->anim.rotZ = baseRoll;
            }
        }
    }

    if ((s8)((ObjSeqState*)seq)->isCameraSeq != 0 && (s8)((ObjSeqState*)seq)->useRootMotionSpeed != 0)
    {
        gObjSeqCameraSourceObj = obj;
        lbl_803DD0B6 = framesThisStep;
    }
    Obj_GetWorldPosition(seqObj, &seqObj->anim.worldPosX, &seqObj->anim.worldPosY,
                         &seqObj->anim.worldPosZ);
}
static inline int ObjSeq_CheckConditionOpcode(ObjSeqState* state, GameObject* obj, u8 conditionOpcode)
{
    ObjAnimSequenceConditionCallback cb;

    switch (conditionOpcode)
    {
    case 0x12:
        if (getButtonsJustPressed(0) & PAD_BUTTON_A)
        {
            return 1;
        }
        break;
    case 0x13:
        if (getButtonsJustPressed(0) & PAD_BUTTON_B)
        {
            return 1;
        }
        break;
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x18:
    case 0x19:
        cb = state->conditionCallback;
        if (cb != NULL)
        {
            return cb(state->callbackContext, (u8*)obj);
        }
        break;
    case 0x1a:
        return isTalkingToNpc() == 0;
    }
    return 0;
}

int ObjSeq_update(GameObject* obj, f32 t)
{
    u8* base = gObjSeqRuntimeBuffer;
    GameObject* activeObj;
    ObjAnimBank* action;
    ObjSeqCommand* cmd;
    f32 moveProgress;
    f32 groundY;
    ObjSeqPlacement* placement;
    ObjSeqState* seq;
    ObjSeqState* state;
    u8* p;
    ObjSeqBgCmd* entry;
    int runs;
    int step;
    int slot;
    int i;
    int k;
    int targetFrame;
    int stop;
    int opcode;
    int found;
    int pressed;
    int restart;
    s8 rewindStep;
    u8 conditionOpcode;
    int aInt;
    f32 val;
    f32 rate;
    f32 px;
    f32 pz;
    f32 fval;
    f32 prevX;
    f32 prevZ;

    (void)t;

    runs = 0;
    step = framesThisStepUnclamped;
    placement = (ObjSeqPlacement*)obj->anim.placementData;
    if (placement == NULL)
    {
        return 1;
    }

    seq = obj->extra;
    state = (ObjSeqState*)seq;
    if ((state->stateFlags & 2) != 0)
    {
        setJoypadDisabled();
    }
    activeObj = state->targetObj;
    gObjSeqStop = 0;
    gObjSeqLinkedTransformValid = 0;
    gObjSeqSkippingToEnd = 0;
    lbl_803DD111 = 0;

    if (state->runState == 3)
    {
        if (state->targetObj != NULL)
        {
            activeObj->pendingParentObj = obj;
            activeObj->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
        }
        return 0;
    }

    slot = state->slot;
    if (base[slot + 0x338c] == 1)
    {
        state->curFrame = ((s16*)(base + 0x3694))[slot];
        state->prevFrame = state->curFrame;
        ObjSeq_RefreshActionCursor(obj, activeObj, (u8*)seq);
    }
    else
    {
        state->curFrame = ((f32*)(base + 0x3894))[slot];
    }

    i = 3;
    p = (u8*)seq + 6;
    while (p -= 2, i-- != 0)
    {
        if (*(s16*)(p + 0x30) > 0)
        {
            *(s16*)(p + 0x30) -= framesThisStep;
            if (*(s16*)(p + 0x30) <= 0)
            {
                *(s16*)(p + 0x30) = 0;
                Sfx_RemoveLoopedObjectSound(obj, *(s16*)(p + 0x38));
            }
        }
    }
    ((u8*)(base + 0x3cf4))[state->slot] = 0;

    do
    {
        gObjSeqDeferredCmdCount = 0;
        if (state->runState == 0)
        {
            obj->anim.alpha = 0;
            return 1;
        }

        activeObj = obj;
        if (state->targetObj != NULL)
        {
            activeObj = state->targetObj;
            activeObj->pendingParentObj = obj;
            activeObj->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
        }
        else if (state->isCameraSeq == 0 && state->movementState < 4)
        {
            state->movementState = -1;
        }

        slot = state->slot;
        if ((s8)base[slot + 0x3c4c] != 0 && (rewindStep = (s8)base[slot + 0x39e8]) != 0)
        {
            state->curFrame -= rewindStep;
            if (state->curFrame < 0)
            {
                state->curFrame = 0;
            }
            state->prevFrame = (s16)(state->curFrame - 1);
            ObjSeq_RebuildCurveStateToFrame(obj, activeObj, (u8*)seq, 1);
        }

        gObjSeqFnDispatched = 0;
        if (activeObj != obj)
        {
            objCallSeqFn(activeObj, obj, seq, ((u8*)(base + 0x3c4c))[state->slot]);
            gObjSeqFnDispatched = 1;
        }

        if ((state->sequenceControlFlags & OBJSEQ_CONTROL_SET_LATCH_B) != 0)
        {
            ((u8*)(base + 0x3b9c))[state->slot] = 1;
        }
        if ((state->sequenceControlFlags & OBJSEQ_CONTROL_CLEAR_LATCH_B) != 0)
        {
            ((u8*)(base + 0x3b9c))[state->slot] = 0;
        }
        if ((state->sequenceControlFlags & OBJSEQ_CONTROL_SET_LATCH_A) != 0)
        {
            ((u8*)(base + 0x3b44))[state->slot] = 1;
        }
        if ((state->sequenceControlFlags & OBJSEQ_CONTROL_CLEAR_LATCH_A) != 0)
        {
            ((u8*)(base + 0x3b44))[state->slot] = 0;
        }
        if ((state->sequenceControlFlags & OBJSEQ_CONTROL_SET_STATE_LATCH) != 0)
        {
            ((u8*)(base + 0x3a40))[state->slot] = 1;
        }
        if ((state->sequenceControlFlags & OBJSEQ_CONTROL_CLEAR_STATE_LATCH) != 0)
        {
            ((u8*)(base + 0x3a40))[state->slot] = 0;
        }

        if (state->runState == 2)
        {
            ObjSeq_SetupInitialPlaybackState(obj, &activeObj, (u8*)seq, placement, (void**)&action);
            return 0;
        }

        if ((s8)((u8*)(base + 0x3c4c))[state->slot] == 1)
        {
            step = 0;
        }
        else if ((s8)((u8*)(base + 0x3c4c))[state->slot] == 2)
        {
            state->curFrame = state->endFrame;
            gObjSeqSkippingToEnd = 1;
        }
        else if ((s8)((u8*)(base + 0x3c4c))[state->slot] == 3)
        {
            found = objSeqFindConditional((u8*)seq, obj);
            if (found > -1)
            {
                ((u8*)(base + 0x3cf4))[state->slot] = 1;
                state->curFrame = found;
                state->prevFrame = state->curFrame;
            }
        }

        if (state->targetObj != NULL && ((GameObject*)state->targetObj)->seqIndex != -1 &&
            (((u8*)(base + 0x3538))[state->slot] & 0x10) == 0)
        {
            (*gCameraInterface)->setLetterbox(0x41, 1);
        }

        slot = state->slot;
        if (((u8*)(base + 0x3590))[slot] != 0)
        {
            state->heading = ((s16*)(base + 0x35e8))[slot];
        }

        if (state->pendingConditionId != 0)
        {
            if (ObjSeq_EvaluateCondition(state->pendingConditionId - 1, (u8*)seq, placement) == 0)
            {
                state->pendingConditionId = 0;
            }
            else
            {
                ((f32*)(base + 0x3740))[state->slot] = (f32)state->curFrame;
                return 0;
            }
        }

        state->curFrame = (s16)(state->curFrame + step);
        if (state->curFrame > state->endFrame)
        {
            state->curFrame = state->endFrame;
        }
        targetFrame = state->curFrame;
        ObjSeq_ApplyFrameCurves(obj, activeObj, (u8*)seq, targetFrame);
        obj->anim.localPosX = obj->anim.localPosX + state->posStepX;
        obj->anim.localPosY = obj->anim.localPosY + state->posStepY;
        obj->anim.localPosZ = obj->anim.localPosZ + state->posStepZ;
        obj->anim.rotZ += state->rotStepZ;
        obj->anim.rotY += state->rotStepY;
        obj->anim.rotX += state->rotStepX;

        action = (ObjAnimBank*)ObjSeq_GetActiveModel(activeObj);
        gObjSeqPendingCmd0BCount = 0;
        if (action != NULL)
        {
            val = ObjSeq_SampleTrackCurve((u8*)seq, 13, state->prevFrame);
            prevX = placement->baseX + val;
            val = ObjSeq_SampleTrackCurve((u8*)seq, 11, state->prevFrame);
            prevZ = placement->baseZ + val;
        }
        state->curFrame = state->prevFrame;

        while (state->curFrame < targetFrame)
        {
            state->curFrame += 1;
            val = ObjSeq_SampleTrackCurve((u8*)seq, 13, state->curFrame);
            px = placement->baseX + val;
            val = ObjSeq_SampleTrackCurve((u8*)seq, 11, state->curFrame);
            pz = placement->baseZ + val;

            if (state->curFrame > 0 && (state->flags & 4) != 0)
            {
                if (state->useRootMotionSpeed == 1 && state->isCameraSeq == 0 &&
                    action != NULL)
                {
                    f32 dx = px - prevX;
                    f32 dz = pz - prevZ;
                    if (ObjAnim_SampleRootCurvePhase(&activeObj->anim, sqrtf(dx * dx + dz * dz),
                                                     &moveProgress) == 0)
                    {
                        i = state->curFrame - 1;
                        val = ObjSeq_SampleTrackCurve((u8*)seq, 9, i);
                        moveProgress = 0.0004f * val;
                    }
                }
                else
                {
                    i = state->curFrame - 1;
                    val = ObjSeq_SampleTrackCurve((u8*)seq, 9, i);
                    moveProgress = 0.0004f * val;
                }

                if (action != NULL)
                {
                    ObjAnim_AdvanceCurrentMove(
                        activeObj, moveProgress, 1.0f, &state->animEvents);
                    if (state->fade > 0.0f)
                    {
                        if (state->trackRunLength[10] != 0)
                        {
                            i = state->curFrame - 1;
                            rate = ObjSeq_SampleTrackCurve((u8*)seq, 10, i);
                        }
                        else
                        {
                            rate = 8.0f;
                        }
                        if (rate < 1.0f)
                        {
                            rate = 1.0f;
                        }
                        rate = 1.0f / rate;
                        state->fade = state->fade - rate;
                        fval = state->fade;
                        if (fval < 0.0f)
                        {
                            state->fade = 0.0f;
                        }
                    }
                }
                else
                {
                    activeObj->anim.currentMoveProgress += moveProgress;
                    fval = 1.0f;
                    while (activeObj->anim.currentMoveProgress > fval)
                    {
                        activeObj->anim.currentMoveProgress -= fval;
                    }
                    rate = 1.0f;
                    val = 0.0f;
                    while (activeObj->anim.currentMoveProgress < val)
                    {
                        activeObj->anim.currentMoveProgress += rate;
                    }
                }
            }

            prevX = px;
            prevZ = pz;

            stop = 0;
            while (stop == 0 && state->cmdCursor < state->cmdCount)
            {
                cmd = (ObjSeqCommand*)(state->cmds + state->cmdCursor * 4);
                opcode = (s8)((u8*)cmd)[0];
                if (opcode == 0)
                {
                    if (state->curFrame >= cmd->param)
                    {
                        state->retriggerFrame = cmd->param;
                        state->cmdCursor += 1;
                    }
                    else
                    {
                        stop = 1;
                    }
                }
                else
                {
                    if (state->curFrame >= state->retriggerFrame)
                    {
                        if (opcode != 0xf)
                        {
                            state->retriggerFrame += ((u8*)cmd)[1];
                        }
                        state->cmdCursor += 1;
                        if (ObjSeq_ExecuteActionCommand(obj, (u8*)action, (u8**)&cmd, 0, 0) != 0)
                        {
                            targetFrame = state->curFrame;
                        }
                        {
                            GameObject* t = *(GameObject**)obj->extra;
                            if (t == NULL)
                            {
                                t = obj;
                            }
                            action = (ObjAnimBank*)ObjSeq_GetActiveModel(t);
                            activeObj = t;
                        }
                    }
                    else
                    {
                        stop = 1;
                    }
                }
            }
        }

        for (k = 0; k < 10; k++)
        {
            conditionOpcode = state->conditionOpcodes[k];
            if (conditionOpcode == 0)
            {
                continue;
            }
            pressed = ObjSeq_CheckConditionOpcode(state, obj, conditionOpcode);
            if (pressed != 0)
            {
                ((u8*)(base + 0x3cf4))[state->slot] = 1;
                state->curFrame = seq->conditionFrames[k];
                state->prevFrame = state->curFrame;
                state->conditionOpcodes[0] = 0;
                state->conditionOpcodes[1] = 0;
                state->conditionOpcodes[2] = 0;
                state->conditionOpcodes[3] = 0;
                state->conditionOpcodes[4] = 0;
                state->conditionOpcodes[5] = 0;
                state->conditionOpcodes[6] = 0;
                state->conditionOpcodes[7] = 0;
                state->conditionOpcodes[8] = 0;
                state->conditionOpcodes[9] = 0;
                break;
            }
        }

        if ((s8)gObjSeqFnDispatched == 0 && activeObj != obj)
        {
            objCallSeqFn(activeObj, obj, seq, ((u8*)(base + 0x3c4c))[state->slot]);
        }

        if (state->sequenceControlFlags != 0)
        {
            restart = 0;
            if ((state->sequenceControlFlags & OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME) != 0)
            {
                restart = 1;
                state->sequenceControlFlags =
                    state->sequenceControlFlags & ~OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME;
                state->curFrame = (s16)state->savedFrame;
                state->prevFrame = state->curFrame;
            }
            state->sequenceControlFlags = 0;
            ((s8*)(base + 0x3cf4))[state->slot] = restart;
        }

        state->eventCount = 0;
        state->curEventId = 0;
        if (action != NULL && (state->flags & 4) != 0)
        {
            action->currentState->eventCountdown = (u16)(int)(16384.0f * state->fade);
        }
        ObjSeq_UpdateCurvePosition(obj, (u8*)seq);
        if ((s8)state->groundSnapEnabled == 1 &&
            trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY,
                                 obj->anim.localPosZ, &groundY, 0) == 0)
        {
            obj->anim.localPosY =
                obj->anim.localPosY +
                ((obj->anim.localPosY - groundY) - placement->groundOffset);
        }
        obj->anim.rotX += state->heading;
        ObjSeq_ApplyLinkedObjectTransform(obj, activeObj, (u8*)seq);
        objSeqDoBgCmds0D((u8*)seq, activeObj, 0);

        for (k = 0; k < gObjSeqPendingCmd0BCount; k++)
        {
            entry = (ObjSeqBgCmd*)(base + k * 8);
            entry = (ObjSeqBgCmd*)((int)entry + 0x2b34);
            if (seqDoSubCmd0B(obj, activeObj, (u8*)seq, (u8*)entry->object, entry->flags, entry->param, 0, 0) != 0)
            {
                k = gObjSeqPendingCmd0BCount;
            }
            {
                GameObject* t = *(GameObject**)obj->extra;
                if (t == NULL)
                {
                    t = obj;
                }
                action = (ObjAnimBank*)ObjSeq_GetActiveModel(t);
                activeObj = t;
            }
        }

        if (gObjSeqStreamStopped != 0)
        {
            gObjSeqStreamStopped = ObjSeq_StartPreparedStream(gObjSeqPreparingStreamSlot) == 0;
        }
        state->prevFrame = state->curFrame;

        if ((s8)gObjSeqStop != 0)
        {
            {
                GameObject* t = *(GameObject**)obj->extra;
                if (t == NULL)
                {
                    t = obj;
                }
                action = (ObjAnimBank*)ObjSeq_GetActiveModel(t);
                activeObj = t;
                animatedObjFreeAndSavePlayerPos(obj, t, (u8*)seq);
            }
        }
        else
        {
            slot = state->slot;
            if (((s8*)(base + 0x3cf4))[slot] != 0)
            {
                ((s16*)(base + 0x3694))[slot] = state->curFrame;
                ((u8*)(base + 0x338c))[state->slot] = 2;
                ((f32*)(base + 0x3740))[state->slot] = (f32)state->curFrame;
            }
            if (-1.0f == ((f32*)(base + 0x3740))[slot = state->slot])
            {
                if (gObjSeqTimedStreamSlot == slot)
                {
                    fval = gObjSeqStreamRemainingTime;
                    aInt = fval;
                    gObjSeqStreamRemainingTime = fval - 0.16666667f;
                    fval = gObjSeqStreamRemainingTime;
                    if (aInt != (int)fval)
                    {
                        step--;
                        if (fval <= 0.0f)
                        {
                            gObjSeqTimedStreamSlot = -1;
                        }
                    }
                }
                ((f32*)(base + 0x3740))[state->slot] =
                    step + ((f32*)(base + 0x3894))[state->slot];
            }
        }

        if ((s8)gObjSeqStop != 0)
        {
            break;
        }
        if (state->curFrame >= state->endFrame)
        {
            break;
        }
    } while (runs-- != 0);

    return 0;
}

int ObjSeq_takeXrotChanged(int index)
{
    int changed;

    changed = objSeqXrotChanged[index];
    objSeqXrotChanged[index] = 0;
    return changed;
}

void ObjSeq_setXrot(int index, int xrot)
{
    s16 xrot16;

    objSeqXrotChanged[index] = 1;
    xrot16 = xrot;
    objSeqXrotValues[index] = xrot16;
}

int ObjSeq_getBool(int index)
{
    if (index < 0 || index >= 0x55)
    {
        return 0;
    }
    return gObjSeqBoolFlags[index];
}

void ObjSeq_setBool(int index, int value)
{
    s8 flag;

    if (index < 0 || index >= 0x55)
    {
        return;
    }
    flag = value;
    gObjSeqBoolFlags[index] = flag;
}

void ObjSeq_addBgCmd(int index, int xrot, int yrot)
{
    s8 count;
    s16 shortIndex;
    s16 shortXrot;
    s16 shortYrot;

    if (index < 0 || index >= 0x55)
    {
        return;
    }

    count = gObjSeqBgCmdCount;
    if (count >= 0x1e)
    {
        return;
    }

    shortIndex = index;
    shortYrot = yrot;
    shortXrot = xrot;
    gObjSeqBgCmds[count].index = shortIndex;
    gObjSeqBgCmds[count].yrot = shortYrot;
    gObjSeqBgCmds[gObjSeqBgCmdCount++].xrot = shortXrot;
}
u8 gObjSeqRuntimeBuffer[0x2A80];
int gObjSeqPreemptList[40][2];
s8 gObjSeqJumpLatch[0x58];
ObjSeqBgCmd gObjSeqDeferredCmds[0x50 / sizeof(ObjSeqBgCmd)];
s8 gObjSeqSlotResults[0xB0];
s8 gObjSeqCondFlags[0x58];
s8 gObjSeqBoolFlags[0x58];
s16 gObjSeqSlotSeqIdTable[0x56];
f32 gObjSeqSlotStreamTimeTable[0x81];
s16 objSeqXrotValues[0x156];
u8 objSeqXrotChanged[0x58];
u8 lbl_80399E50[0x58];
f32 objSeqOverridePos[0x259];
ObjSeqBgCmd lbl_8039944C[0xA0 / sizeof(ObjSeqBgCmd)];
ObjSeqBgRotationCmd gObjSeqBgCmds[0x1E];


#define OBJSEQ_SLOT_COUNT 85

typedef struct ObjSeqRuntimeStorage {
    u8 _reserved0000[0x338c];
    u8 marks[0x58];
    int handles[OBJSEQ_SLOT_COUNT];
    u8 _reserved3538[0x58];
    u8 counts[0x58];
    u8 _reserved35e8[0x158];
    f32 distances[OBJSEQ_SLOT_COUNT];
    f32 frames[OBJSEQ_SLOT_COUNT];
    u8 pending[0x58];
    u8 states[0x58];
    s16 modes[0x56];
    u8 flagsA[0x58];
    u8 flagsB[0x58];
    u8 results[0x58];
    u8 actions[0x58];
} ObjSeqRuntimeStorage;

STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, marks) == 0x338c);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, handles) == 0x33e4);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, counts) == 0x3590);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, distances) == 0x3740);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, frames) == 0x3894);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, pending) == 0x39e8);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, states) == 0x3a40);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, modes) == 0x3a98);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, flagsA) == 0x3b44);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, flagsB) == 0x3b9c);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, results) == 0x3bf4);
STATIC_ASSERT(offsetof(ObjSeqRuntimeStorage, actions) == 0x3c4c);

void ObjSeq_onMapSetup(void)
{
    u8* base = gObjSeqRuntimeBuffer;
    u8* flagsB;
    u8* flagsA;
    s16* modes;
    u8* actions;
    u8* results;
    u8* states;
    u8* pending;
    f32* frames;
    f32* dists;
    int* handles;
    u8* counts;
    u8* marks;
    int i = 0;
    f32 neg1;
    f32 zero;

    flagsB = base + offsetof(ObjSeqRuntimeStorage, flagsB);
    flagsA = base + offsetof(ObjSeqRuntimeStorage, flagsA);
    modes = (s16*)(base + offsetof(ObjSeqRuntimeStorage, modes));
    actions = base + offsetof(ObjSeqRuntimeStorage, actions);
    results = base + offsetof(ObjSeqRuntimeStorage, results);
    states = base + offsetof(ObjSeqRuntimeStorage, states);
    pending = base + offsetof(ObjSeqRuntimeStorage, pending);
    frames = (f32*)(base + offsetof(ObjSeqRuntimeStorage, frames));
    dists = (f32*)(base + offsetof(ObjSeqRuntimeStorage, distances));
    counts = base + offsetof(ObjSeqRuntimeStorage, counts);
    handles = (int*)(base + offsetof(ObjSeqRuntimeStorage, handles));
    marks = base + offsetof(ObjSeqRuntimeStorage, marks);

    {
        zero = 0.0f;
        neg1 = -1.0f;
        for (; i < 0x50; i += 8)
        {
            flagsB[0] = 0;
            flagsA[0] = 0;
            modes[0] = 0;
            actions[0] = 0;
            results[0] = 0;
            states[0] = 0;
            pending[0] = 0;
            frames[0] = zero;
            dists[0] = neg1;
            counts[0] = 0;
            handles[0] = 0;
            marks[0] = 0;
            flagsB[1] = 0;
            flagsA[1] = 0;
            modes[1] = 0;
            actions[1] = 0;
            results[1] = 0;
            states[1] = 0;
            pending[1] = 0;
            frames[1] = zero;
            dists[1] = neg1;
            counts[1] = 0;
            handles[1] = 0;
            marks[1] = 0;
            flagsB[2] = 0;
            flagsA[2] = 0;
            modes[2] = 0;
            actions[2] = 0;
            results[2] = 0;
            states[2] = 0;
            pending[2] = 0;
            frames[2] = zero;
            dists[2] = neg1;
            counts[2] = 0;
            handles[2] = 0;
            marks[2] = 0;
            flagsB[3] = 0;
            flagsA[3] = 0;
            modes[3] = 0;
            actions[3] = 0;
            results[3] = 0;
            states[3] = 0;
            pending[3] = 0;
            frames[3] = zero;
            dists[3] = neg1;
            counts[3] = 0;
            handles[3] = 0;
            marks[3] = 0;
            flagsB[4] = 0;
            flagsA[4] = 0;
            modes[4] = 0;
            actions[4] = 0;
            results[4] = 0;
            states[4] = 0;
            pending[4] = 0;
            frames[4] = zero;
            dists[4] = neg1;
            counts[4] = 0;
            handles[4] = 0;
            marks[4] = 0;
            flagsB[5] = 0;
            flagsA[5] = 0;
            modes[5] = 0;
            actions[5] = 0;
            results[5] = 0;
            states[5] = 0;
            pending[5] = 0;
            frames[5] = zero;
            dists[5] = neg1;
            counts[5] = 0;
            handles[5] = 0;
            marks[5] = 0;
            flagsB[6] = 0;
            flagsA[6] = 0;
            modes[6] = 0;
            actions[6] = 0;
            results[6] = 0;
            states[6] = 0;
            pending[6] = 0;
            frames[6] = zero;
            dists[6] = neg1;
            counts[6] = 0;
            handles[6] = 0;
            marks[6] = 0;
            flagsB[7] = 0;
            flagsA[7] = 0;
            modes[7] = 0;
            actions[7] = 0;
            results[7] = 0;
            states[7] = 0;
            pending[7] = 0;
            frames[7] = zero;
            dists[7] = neg1;
            counts[7] = 0;
            handles[7] = 0;
            marks[7] = 0;
            flagsB += 8;
            flagsA += 8;
            modes += 8;
            actions += 8;
            results += 8;
            states += 8;
            pending += 8;
            frames += 8;
            dists += 8;
            counts += 8;
            handles += 8;
            marks += 8;
        }
    }

    {
        marks = base + i;
        modes = (s16*)(base + i * 2);
        modes += 0x3a98 / 2;
        handles = (int*)(base + i * 4);
        handles += 0x33e4 / 4;
        marks += 0x338c;
        zero = 0.0f;
        neg1 = -1.0f;
        while (i < 85)
        {
            frames = (f32*)(handles + 300);
            dists = (f32*)(handles + 215);
            flagsA = marks + 0x810;
            flagsB = marks + 0x7b8;
            actions = marks + 0x8c0;
            results = marks + 0x868;
            states = marks + 0x6b4;
            pending = marks + 0x65c;
            counts = marks + 0x204;
            *flagsA++ = 0;
            *flagsB++ = 0;
            modes[0] = 0;
            *actions++ = 0;
            *results++ = 0;
            *states++ = 0;
            *pending++ = 0;
            *frames++ = zero;
            *dists++ = neg1;
            *counts++ = 0;
            handles[0] = 0;
            marks[0] = 0;
            marks[0] = 0;
            modes++;
            handles++;
            marks++;
            i++;
        }
    }

    gObjSeqPreemptCount = 0;
    gObjSeqCamMode = 0;
    gObjSeqCameraActive = 0;
    lbl_803DD0DC = 0.0f;
    gObjSeqCameraSourceObj = NULL;
    gObjSeqCameraOverrideActive = 0;
    gObjSeqBgCmdCount = 0;
}


void ObjSeq_release(void)
{
    mm_free(gObjSeqAnimLookup);
}

void ObjSeq_initialise(void)
{
    gObjSeqAnimLookup = mmAlloc(0x10, 0x11, 0);
    ObjSeq_onMapSetup();
    gObjSeqCamModeArgB = 1;
    gObjSeqCamModeArgD = 0x5a;
    gObjSeqCamMode = 0x42;
    seqPairTablePrepare(gObjSeqStreamTableA, 5);
}

void ObjSeq_copyDefaultColor(GXColor* out)
{
    GXColor* src;

    out->r = gObjSeqDefaultColor.r;
    src = &gObjSeqDefaultColor;
    out->g = src->g;
    out->b = src->b;
    out->a = src->a;
}

