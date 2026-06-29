#ifndef MAIN_ENGINE_SHARED_H_
#define MAIN_ENGINE_SHARED_H_

#include "ghidra_import.h"
#include "main/audio/inp_midi.h"
#include "main/audio/snd_core.h"
#include "main/effect_interfaces.h"
#include "main/newclouds.h"
#include "main/sky_interface.h"

#define SFX_LOOPED_OBJECT_SOUND_COUNT 0x80
#define SFX_OBJECT_CHANNEL_COUNT 56
#define SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE 1
#define SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN 2
#define SFX_LOOPED_OBJECT_STOP_FLAG 0x40
#define MODEL_DECODE_NIBBLE(nibExpr)                                           \
    {                                                                          \
        u8 nib = (nibExpr);                                                    \
        int base = lbl_802C18C0[idx];                                          \
        int delta = 0;                                                         \
        if (nib & 1) {                                                         \
            delta = base >> 2;                                                 \
        }                                                                      \
        if (nib & 2) {                                                         \
            delta += base >> 1;                                                \
        }                                                                      \
        if (nib & 4) {                                                         \
            delta += base;                                                     \
        }                                                                      \
        if (nib & 8) {                                                         \
            delta = -delta;                                                    \
        }                                                                      \
        acc += delta;                                                          \
        idx += lbl_802C1A24[nib];                                              \
        if (idx < 0) {                                                         \
            idx = 0;                                                           \
        } else if (idx > 0x58) {                                               \
            idx = 0x58;                                                        \
        }                                                                      \
        {                                                                      \
            u32 packed = (u32)(acc & 0xffff);                                 \
            int curBit = state->bit;                                           \
            int bo = curBit >> 3;                                              \
            packed <<= ((8 - (curBit & 7)) + sh16);                            \
            ((u8 *)state->instrs)[bo] |= (packed >> 16) & 0xff;                \
            ((u8 *)state->instrs)[bo + 1] |= (packed >> 8) & 0xff;             \
            ((u8 *)state->instrs)[bo + 2] |= packed & 0xff;                    \
            state->bit += bitWidth;                                            \
            state->bit += gap;                                                 \
        }                                                                      \
    }

/* Same as MODEL_DECODE_NIBBLE but the final (odd-count) nibble does not
   advance the bit cursor by the inter-instruction gap. */
#define MODEL_DECODE_NIBBLE_TAIL(nibExpr)                                      \
    {                                                                          \
        u8 nib = (nibExpr);                                                    \
        int base = lbl_802C18C0[idx];                                          \
        int delta = 0;                                                         \
        if (nib & 1) {                                                         \
            delta = base >> 2;                                                 \
        }                                                                      \
        if (nib & 2) {                                                         \
            delta += base >> 1;                                                \
        }                                                                      \
        if (nib & 4) {                                                         \
            delta += base;                                                     \
        }                                                                      \
        if (nib & 8) {                                                         \
            delta = -delta;                                                    \
        }                                                                      \
        acc += delta;                                                          \
        idx += lbl_802C1A24[nib];                                              \
        if (idx < 0) {                                                         \
            idx = 0;                                                           \
        } else if (idx > 0x58) {                                               \
            idx = 0x58;                                                        \
        }                                                                      \
        {                                                                      \
            u32 packed = (u32)(acc & 0xffff);                                 \
            int curBit = state->bit;                                           \
            int bo = curBit >> 3;                                              \
            packed <<= ((8 - (curBit & 7)) + sh16);                            \
            ((u8 *)state->instrs)[bo] |= (packed >> 16) & 0xff;                \
            ((u8 *)state->instrs)[bo + 1] |= (packed >> 8) & 0xff;             \
            ((u8 *)state->instrs)[bo + 2] |= packed & 0xff;                    \
            state->bit += bitWidth;                                            \
        }                                                                      \
    }

typedef struct SfxLoopedObjectSoundTable {
    u8 flags[0x80];
    u16 ids[0x80];
    u32 objects[0x80];
} SfxLoopedObjectSoundTable;
typedef struct SfxObjectChannel {
    u32 handle;
    u8 hasPosition;
    u8 tracksObjectPosition;
    u8 paused;
    u8 volume;
    s16 field08;
    u8 pad0a[0x02];
    f32 x;
    f32 y;
    f32 z;
    u32 object;
    u16 channelMask;
    u16 sfxId;
    f32 field20;
    f32 field24;
    u8 globalCtrlDisabled;
    u8 pad29[0x07];
    u64 age;
} SfxObjectChannel;
typedef struct ObjMatrixBuildTransform {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjMatrixBuildTransform;
typedef struct EnvfxActEntry {
    u8 pad0[0x2a];
    u16 field_2a;
    u8 pad1[0x30];
    u8 kind;
    u8 pad2[3];
} EnvfxActEntry;
typedef struct ModelRenderInstrsState {
    void* instrs;
    s32 byteCount;
    s32 bitCount;
    s32 fieldC;
    s32 bit;
} ModelRenderInstrsState;
typedef struct MusicSeqStartParams {
    u32 flags;
    u8 pad4[8];
    u16 field_c;
    u16 field_e;
    u8 field_10;
    u8 pad11[0xf];
} MusicSeqStartParams;
typedef struct MusicChannel {
    u32 field_0;
    u32 seqHandle;
    void *bankData;
    int status;
    u8 voiceId;
    u8 pad11;
    u16 field_12;
    u8 pad14[0xc];
    f32 field_20;
} MusicChannel;
typedef struct MusicTrigParam {
    u8 pad0[2];
    u16 field_2;
    u8 pad4[2];
    u16 field_6;
    u8 pad8[4];
    u8 field_c;
} MusicTrigParam;
typedef struct MusicBank {
    u8 pad0[2];
    u8 field_2;
} MusicBank;
typedef struct SfxTriggerFull {
    u16 id;
    u8 volBase;
    u8 volRand;
    u8 pitchBase;
    u8 pitchRand;
    u16 field_6;
    u16 field_8;
    u16 sfxIds[6];
    u8 weights[6];
    u16 selectRange;
    u8 e_tableIdx : 4;
    u8 e_bit3 : 1;
    u8 e_pad : 2;
    u8 e_bit0 : 1;
    u8 f_count : 4;
    u8 f_curIdx : 4;
} SfxTriggerFull;
typedef struct SfxTrigger {
    u16 id;
    u8 pad[0x1e];
} SfxTrigger;
typedef struct SfxTriggerCacheEntry {
    u16 key;
    u16 index;
} SfxTriggerCacheEntry;
#ifndef MAIN_CURVE_TYPES_DEFINED
#define MAIN_CURVE_TYPES_DEFINED
typedef f32 (*CurveEvalFn)(f32 t, f32 *values, f32 *outTangent);
typedef void (*CurveCoeffFn)(f32 *values, f32 *coeffs);
typedef struct Curve {
    f32 t;
    f32 segmentDistance;
    f32 pathDistance;
    f32 pathLength;
    int idx;
    f32 totalLen;
    f32 segLen[20];
    f32 sample[3];
    f32 tangent[3];
    int dir;
    f32 *px;
    f32 *py;
    f32 *pz;
    int count;
    CurveEvalFn eval;
    CurveCoeffFn coeffFn;
} Curve;
#endif /* MAIN_CURVE_TYPES_DEFINED */
typedef struct CameraRenderMode {
    u32 viTVMode;
    u16 fbWidth;
    u16 efbHeight;
    u16 xfbHeight;
    u8 pad0A[0x0E];
    u8 useViewportJitter;
} CameraRenderMode;
typedef struct CameraViewSlot {
    s16 pitch;
    s16 yaw;
    s16 roll;
    u8 pad06[6];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x14];
    f32 shakeMagnitude;
    f32 shakeMagnitudeTarget;
    f32 shakeDuration;
    f32 shakeTimer;
    f32 shakeFalloff;
    u8 pad40[0x1C];
    s8 shakeFlipTimer;
    s8 shakeActive;
    u8 pad5E[2];
} CameraViewSlot;
typedef struct CameraMatrixTransform {
    s16 pitch;
    s16 yaw;
    s16 roll;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CameraMatrixTransform;
typedef struct CurveHeapNode {
    u16 priority;
    u16 value;
} CurveHeapNode;
typedef struct RingBufferQueue {
    s16 count;
    s16 capacity;
    s16 elemSize;
    s16 unused;
    s16 writeIndex;
    s16 readIndex;
    void* data;
} RingBufferQueue;
typedef struct ObjLinkedList {
    s16 count;
    s16 nextOffset;
    int head;
} ObjLinkedList;
typedef struct ModelList {
    s16* entries;
    s16* end;
    s16* capacityEnd;
    u8 dataSize;
    u8 strideShorts;
    u8 pad0E[6];
} ModelList;
typedef struct ResourceDescriptor {
    u8 pad00[0x10];
    void (*acquire)(struct ResourceDescriptor* descriptor);
    void (*release)(void);
    u8 data[0];
} ResourceDescriptor;
typedef struct UiDllVTable {
    void* field0;
    int (*frameStart)(void);
    void (*frameEnd)(void);
    void (*draw)(void);
} UiDllVTable;
typedef struct PadStatusLite {
    u16 buttons;
    s8 stickX;
    s8 stickY;
    s8 substickX;
    s8 substickY;
    u8 triggerLeft;
    u8 triggerRight;
    u8 analogA;
    u8 analogB;
    s8 error;
} PadStatusLite;
typedef struct {
    u8 pad[0x20];
    void (*fn)(int, int, int);
    int a;
    int b;
    int c;
} TextCallbackEntry;
typedef struct {
    u16 a;
    u16 b;
    u16 key;
} TaskTextEntry;
typedef struct MusicTrackSlot {
    s16 id;
    u8 pad2[6];
    int offset;
    int size;
} MusicTrackSlot;
typedef struct {
    u16 id;          // 0x0
    u8 fadeBits;     // 0x2
    u8 volBits;      // 0x3
    u16 lengthRaw;   // 0x4
    char name[0xF];  // 0x6
    u8 flag;         // 0x15
} StreamEntry;
typedef struct {
    u16 id;
    u16 track;
    u8 pad[0xc];
} MusicTrigger;
/* Partial view of the synth sequence-player record; the FULL layout is
 * src/main/audio/synth_internal.h's SynthVoice (sizeof 0x1868 and state
 * @0x08 probe-verified against it; the two headers are never co-included,
 * recipe-#57 per-TU view). NOT the 0x404 per-voice record - that is
 * McmdVoiceState (mcmd.h). */
typedef struct SynthVoice {
    u8 pad0[8]; /* next/prev */
    u8 state;   /* 0x08 */
    u8 pad9[0x1868 - 9];
} SynthVoice;
typedef struct {
    u16 gridX;
    u16 gridZ;
} VoxMapSlotOrigin;
typedef struct {
    VoxMapSlotOrigin slotOrigin[6];
    int timer[6];
    int blockId[6];
    int blockOriginWorldX;
    int blockOriginWorldZ;
    int blockOriginGridX;
    int blockOriginGridZ;
    int f58;
    void* mapBuffer[6];
} VoxMaps;
typedef struct {
    s16 x;
    s16 y;
    s16 z;
} VoxPos;
typedef struct {
    u8 pad0[6];
    s16 f6;
    s8 f8;
    s8 f9;
} VoxBlock;
typedef struct {
    u8 pad00[4];
    int minY;
    u8 pad08[4];
    int maxY;
    u8 pad10[4];
    int *nodeBase;
    u8 pad18[4];
    u8 *header;
    u8 pad20[4];
    u8 *bitmap;
} VoxActiveMap;
typedef struct {
    int unk00;
    int unk04;
    int originX;
    int originZ;
    VoxActiveMap *activeMap;
} VoxState;
typedef struct {
    u8 pad00[0x14];
    int f14;
    int f18;
    int f1c;
    int f20;
    int f24;
    int f28;
} VoxMapFile;
typedef struct {
    s16 x;
    s16 z;
    s16 y;
    s16 pad6;
    u16 cost;
} VoxBoxArg;
struct RouteState;
typedef struct {
    s16 x;
    s16 z;
    s16 y;
    u16 hCost;
    u16 gCost;
    u8 parentDir;
    u8 parentIdx;
    u8 flag;
    u8 unkD;
} RouteNode;
typedef struct RouteState {
    RouteNode *nodes;
    CurveHeapNode *queue;
    f32 *pathPoints;
    s16 tgtX;
    s16 tgtZ;
    s16 tgtY;
    s16 startX;
    s16 startZ;
    s16 startY;
    int cur;
    s16 nodeCount;
    s16 queueCount;
    s16 pathCount;
    s16 pad22;
    s16 minHCost;
    u8 mode26;
    u8 pad27;
} RouteState;
typedef struct {
    f32 destPos[3];
    f32 curPos[3];
    f32 tgtPos[3];
    u8 navState;
    u8 flag25;
    u8 maxIters;
    u8 budget;
} RouteNav;
typedef struct {
    u16 id;
    u8 pad[0xa];
} GlyphEntry;
typedef struct {
    int field0;
    GlyphEntry* entries;
    int field8;
    int count;
    u8 pad[0xc];
    int mode;
} GameTextFont;
typedef struct {
    u8 pad0[2];
    u16 count;
    u8 slotHint;
    u8 f5;
    u8 f6;
    u8 pad7;
    char **strings;
} GameTextDef;
typedef struct {
    u8 pad0[8];
    u16 f08;
    u16 f0a;
    f32 f0c;
    u8 f10;
    u8 f11;
    u8 f12;
    u8 pad13;
    s16 f14;
    s16 f16;
    s16 f18;
    s16 f1a;
    u8 pad1c[4];
} TextSlot;
typedef struct {
    u8 pad0[4];
    u8 sizeIdx;
    u8 pad5[3];
} LanguageName;
typedef struct {
    u8 pad0[0xa];
    u16 lineHeight;
    u8 padc[4];
} FontSizeEntry;
typedef struct {
    u32 key;
    u8 pad4[4];
    s8 f8;
    s8 f9;
    u8 padA[2];
    u8 fC;
    u8 padD;
    u8 lang;
    u8 padF;
} MeasGlyph;
typedef struct {
    u32 key;
    u32 val;
} SpecialGlyph;
typedef struct {
    int active;
    int charIndex;
    int f8;
    int fC;
    int f10;
} TextDisplayState;

extern void Movie_SetVolumeFade();
extern u32 gAudioResetting;
extern u32 gAudioManagedChannelMask;
extern u32 gAudioActiveChannelMask;
extern u8 gAudioInitStarted;
extern s32 gAttractMovieState;
extern u8 gAudioStreamDefaultVolume;
extern u8 gAudioStreamVolumeLeft;
extern u8 gAudioStreamVolumeRight;
extern u8 gAudioStreamDvdState;
extern u8 gAudioStreamPlaying;
extern u32 gAudioStreamMusicFadeFlagA;
extern u32 gAudioStreamMusicFadeFlagB;
extern void (*gAudioStreamPreparedCallback)(void);
extern s32 gAudioStreamCurrentId;
extern s32 gAudioStreamStartWhenPrepared;
extern s32 gAudioStreamPreparingId;
extern s32 gAudioStreamPreparedId;
extern u32 gAudioStreamPlayAddrCallbackResult;
extern u8 gAudioStreamPlayAddrCallbackDone;
extern f32 gAudioStreamEndPos;
extern f32 gAudioStreamPos;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DE5D0;
extern f32 gAudioStreamFramesPerSecond;
extern f32 lbl_803DE5F0;
extern f32 gCameraShakeMagnitudeDecay;
extern f32 gCameraPi;
extern f32 lbl_803DE5FC;
extern f32 lbl_803DE600;
extern f32 gCameraShakeStopThreshold;
extern f32 gCameraShakeStopThresholdNeg;
extern f32 lbl_803DE610;
extern f32 gCameraDepth24BitMax;
extern f32 lbl_803DE624;
extern s8 gObjTransformMatrixSlot;
extern u8 gAudioStreamDvdBlockCurrent[];
extern u8 gAudioStreamDvdBlockPrepared[];
extern char sDvdCancelStreamWarning[];
extern f32 gObjInverseYawTransformMatrices[][16];
extern f32 gObjYawTransformMatrices[][16];
extern SfxLoopedObjectSoundTable gSfxLoopedObjectSoundFlags;
extern u16 gSfxLoopedObjectSoundCount;
extern SfxObjectChannel gSfxObjectChannels[];
extern u8 gSfxGlobalCtrlLevel;
extern u32 gSfxObjectChannelMatchCount;
extern u32 gSfxObjectChannelAgeHi;
extern u32 gSfxObjectChannelAgeLo;
extern void AIReset(void);
extern int sndFXKeyOff(u32 handle);
extern int sndFXCheck(u32 handle);
extern int sndFXCtrl(u32 handle, u32 ctrl, u32 value);
extern int sndFXCtrl14(u32 handle, u32 ctrl, u32 value);
extern void Music_Update(void);
extern void Sfx_UpdateObjectSounds(void);
extern void Sfx_StopAllObjectSounds(void);
extern void AudioStream_UpdateFadeTimer(void);
extern void AudioStream_StopCurrent(void);
extern void AudioStream_CancelPrepared(void);
extern void streamFn_8000a380(int mask, int mode, int time);
extern void Movie_SetVolumeFade(u32 volume, u32 fadeMs);
extern void AISetStreamPlayState(u32 state);
extern void AISetStreamVolLeft(u8 volume);
extern void AISetStreamVolRight(u8 volume);
extern s32 DVDCancelStreamAsync(void *streamInfo, void *callback);
extern void OSReport(char *message, ...);
extern s32 getGameState(void);
extern u32 GameBit_Get(u32 bit);
extern void AudioStream_CancelCallback(s32 result);
extern void fn_8000D0B4(void);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);
extern s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);
extern void Sfx_StopFromObject(u32 obj, u32 sfxId);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode);
extern void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, u16 sfxId);
extern void Sfx_UpdateObjectChannel3D(SfxObjectChannel* objectChannel);
extern f32 lbl_803DE570;
extern f32 lbl_803DE574;
extern f32 lbl_803DE578;
extern f32 lbl_803DE598;
extern f32 lbl_803DE59C;
extern f32 lbl_803DE5A0;
extern f32 gSfxPanCenter;
extern f32 gSfxPanScale;
extern void *Camera_GetCurrentViewSlot(void);
extern void Matrix_TransformVector(f32 *matrix, f32 *in, f32 *out);
extern void Matrix_TransformPoint(f32 *matrix, f64 x, f64 y, f64 z, f32 *outX, f32 *outY, f32 *outZ);
extern void setMatrixFromObjectPos(f32 *matrix, void *obj);
extern void mtx44ScaleRow1(f32 *matrix, f32 scale);
extern void mtx44_multSafe(f32 *dst, f32 *src, f32 *out);
extern void mtxRotateByVec3s(f32 *matrix, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void PSMTXCopy(f32 *src, f32 *dst);
extern void PSMTXMultVec(f32 *matrix, f32 *in, f32 *out);
extern void PSVECNormalize(f32 *in, f32 *out);
extern void PSVECScale(f32 *in, f32 *out, f32 scale);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void GXLoadPosMtxImm(f32 *matrix, s32 slot);
extern void C_MTXOrtho(f32* matrix, f32 top, f32 bottom, f32 left, f32 right, f32 nearPlane, f32 farPlane);
extern void C_MTXPerspective(f32* matrix, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane);
extern void C_MTXLightPerspective(f32* matrix, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);
extern void GXSetProjection(f32* matrix, s32 projectionMode);
extern void GXSetViewport(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane);
extern void GXSetViewportJitter(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane, u32 field);
extern u8 pauseMenuGetState(void);
extern void matrixFn_8006ff0c(f32* matrix, s16* out, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane, f32 scale);
extern void copyMatrix44(f32* src, f32* dst);
extern void *memmove(void *dest, const void *src, u32 count);
extern void mm_free(void *ptr);
extern void *mmAlloc(u32 size, u32 tag, void *name);
extern void getTabEntry(void* dst, int kind, int offset, int size);
s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state);
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit);
extern int lbl_802C18C0[];
extern int lbl_802C1A24[];
extern MusicSeqStartParams gMusicSeqStartParamsDefault;
extern f32 lbl_803DE560;
extern int sndSeqPlayEx(int a, int b, void *bank, MusicSeqStartParams *params, int e);
extern void sndSeqVolume(int voice, int a, int handle, int b);
extern int synthResolveHandle(int handle);
extern int randomGetRange(int min, int max);
extern u8 gSfxTriggerExtraTable;
extern void *gSfxTriggersData;
extern int gSfxTriggersCount;
extern SfxTriggerCacheEntry gSfxTriggerLookupCache[];
extern int sndFXStartEx(s16 a, int b, int c, int d);
extern f32 lbl_803DE590;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 gAudioPi;
extern f32 gAudioAngleToRadDivisor;
extern void *Obj_GetPlayerObject(void);
extern int Obj_IsLoadingLocked(void);
extern int getCurSeqNo(void);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern f32 PSVECMag(f32 *v);
extern f32 lbl_803DE5B4;
extern f32 lbl_803DE5B8;
extern double lbl_803DE5C0;
extern double lbl_803DE5C8;
extern void Curve_SampleSegmentPoints(f32 *px, f32 *py, f32 *pz, f32 *outX, f32 *outY, f32 *outZ, int count, void (*evalFn)(f32 *ch, f32 *buf));
extern f32 sqrtf(f32 x);
extern f32 lbl_803DE658;
extern f32 lbl_803DE674;
extern f32 gCurveSegmentCount;
extern f32 lbl_803DE67C;
extern f32 lbl_803DE660;
extern f32 lbl_803DE680;
extern f32 gCurveForwardDiffStep;
extern int gCurveCachedSampleCount;
extern f32 gCurveForwardDiffCoeffs[];
extern f32 Curve_EvalBezier(f32 t, f32 *values, f32 *outTangent);
extern f32 Curve_EvalHermite(f32 t, f32 *values, f32 *outTangent);
extern void debugPrintf(char *message, ...);
extern char sCurvesSetupMoveNetworkCurveTooFewControlPoints[];
extern char sCurvesSetupMoveNetworkCurveBadControlPointCount[];
int Curve_AdvanceAlongPath(Curve *curve, f32 dt);
void Curve_BuildSegmentLengthTable(Curve *curve, int count);
extern char sCurvesMoveTooFewControlPoints[];
extern char sCurvesMoveBadControlPointCount[];
extern u8 gDvdErrorPauseActive;
extern u8 gDvdCoverOpenErrorActive;
extern int gDvdLastDriveStatus;
extern u8 lbl_80339950[];
extern void stopRumble2(void);
extern void gameTextShow(int a);
extern int DVDGetDriveStatus(void);
extern int DVDCheckDisk(void);
extern void DVDGetStreamPlayAddrAsync(void *buf, void *callback);
extern void setTimeStop(int frames);
extern void cutsceneFadeInOut(int mode);
extern int getLoadedFileFlags(int slot);
extern int gameTextGetCharset(void);
extern void gameTextSetCharset(int a, int b);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void Sfx_SetObjectSoundsPaused(s32 paused);
extern s32 gMusicActivePriority;
extern f32 gCameraViewRotationMatrix[16];
extern f32 gCameraInverseViewRotationMatrix[16];
extern f32 gCameraViewMatrix[16];
extern f32 gCameraInverseViewMatrix[16];
extern u8 gCameraCurrentViewIndex;
extern u8 cameraViewYOffsetEnabled;
extern s16 cameraViewportYOffset;
extern s16 gCameraViewportYOffset;
extern f32 gCameraProjectionMatrix[16];
extern f32 gCameraFarPlane;
extern f32 gCameraNearPlane;
extern f32 gCameraAspectRatio;
extern f32 gCameraFovY;
extern s32 gCameraProjectionMode;
extern s16 gCameraFarPlaneTransitionFramesLeft;
extern s16 gCameraFarPlaneTransitionFrames;
extern f32 gCameraFarPlaneTransitionTarget;
extern f32 gCameraFarPlaneTransitionStart;
extern f32 gCameraOrthoRight;
extern f32 gCameraOrthoLeft;
extern f32 gCameraOrthoBottom;
extern f32 gCameraOrthoTop;
extern f32 lbl_803DE60C;
extern f32 lbl_803DE628;
extern f32 lbl_803DE62C;
extern f32 lbl_803DE630;
extern f32 lbl_803DE640;
extern f32 lbl_803DE644;
extern f32 lbl_803DE648;
extern f32 gCameraDefaultFarPlane;
extern f32 gCameraDefaultPosition;
extern f32 lbl_803DE65C;
extern f32 lbl_803DE664;
extern f32 lbl_803DE668;
extern f32 lbl_803DE66C;
extern f32 lbl_803DE670;
extern f32 lbl_803DE678;
extern f32 lbl_803DE694;
extern f32 lbl_803DE698;
extern f32 lbl_803DB26C;
extern CameraViewSlot gCameraShakeSlots[];
extern f32 fabsf(f32 x);
extern u32 getScreenResolution(void);
extern void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
extern u8 lbl_80338090[];
extern f32 gCameraDefaultModelMatrix[16];
extern f32 lbl_803967C0[12];
extern f32 lbl_803967F0[12];
extern f32 lbl_80396820[12];
extern f32 lbl_80396850[12];
extern s16 gCameraViewportScreenParams[];
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern CameraRenderMode* gRenderModeObj;
extern u32 lbl_803DCCBC;
extern s16 lbl_803DC88A;
void Camera_ApplyCurrentViewport(void* viewportArg);
extern u8 gCameraViewportEntries[];
extern int Sfx_ResolveObjectSfxId(int *outChannel, u16 *sfxId);
extern int memcmp(const void* lhs, const void* rhs, u32 size);
extern void* memcpy(void* dst, const void* src, u32 size);
extern void* memset(void* dst, int value, u32 size);
extern ResourceDescriptor* gResourceDescriptors[];
extern void* gResourceLoadedHandles[];
extern u16 gResourceRefCounts[];
extern u8 gModelEngineTimerState;
extern s8 gModelEngineTimerFlags;
extern UiDllVTable** gModelEngineCurUiDllRes;
extern int gModelEnginePendingUiDll;
extern int curUiDll;
extern int gModelEnginePrevUiDll;
extern f32 gModelEngineTimerDuration;
extern f32 gModelEngineTimerValue;
extern f32 gRumbleTimer;
extern u8 joypadDisabled;
extern u8 rumbleEnabled;
extern u32 gPadResetMask;
extern u8 gPadStickRepeatDelay;
extern s32 gModelEngineHudNumber;
extern s32 lbl_803DB28C;
extern char lbl_803DB290;
extern char gModelEngineTextBuf[];
extern u32 gPadButtonMask[];
extern u8 gPadAnalogY;
extern u8 gPadAnalogX;
extern u8 gPadRepeatY;
extern u8 gPadRepeatX;
extern u8 gPadPrevStickY;
extern u8 gPadPrevStickX;
extern u16 gPadPrevTriggers;
extern u16 gPadTriggers;
extern u16 gPadTriggersReleased;
extern u16 gPadTriggersPressed;
extern u8 gPadStatusToggle;
extern u32 gPadStateBlock[];
extern u32 gPadButtonsHeld[];
extern u32 lbl_803398D0[];
extern u32 gPadButtonsJustPressed[];
extern u8 gPadStatuses[];
extern s32 gModelEngineUiDllResourceIds[];
extern u8 gTextBoxes[];
extern void* gFileInfo;
extern volatile int gDvdReadCallbackResult;
extern void* gCurTextBox;
extern f32 lbl_803DE6B8;
extern f32 lbl_803DE6D4;
extern f32 lbl_803DE6E0;
extern f32 lbl_803DE6E8;
extern volatile int gAudioArqRequestDone;
extern int gAudioArqRequestIndex;
extern int gRenderMode;
extern int lbl_803DC9C8;
extern u8 lbl_8033A540[];
extern void ARQPostRequest(void* req, u32 owner, u32 type, u32 prio, u32 src, u32 dst, u32 size, void (*cb)(void*));
extern int sprintf(char* buf, const char* fmt, ...);
extern char* strcpy(char* dst, const char* src);
extern char* strcat(char* dst, const char* src);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);
extern void PADControlMotor(s32 chan, u32 command);
extern int PADInit(void);
extern int PADRecalibrate(u32 mask);
extern int PADReset(u32 mask);
extern u32 PADRead(struct PadStatusLite *status);
extern void PADClamp(struct PadStatusLite *status);
extern u8 lbl_803DCCA5;
extern void* gameTextDrawFunc;
extern char* lbl_803DC9C4;
extern char* gameStrcpy(char* dst, char* src);
extern void gameTextFn_8001658c(int a, int b, int c);
extern TextCallbackEntry gAudioArqRequests[];
extern TaskTextEntry gTaskTextTable[];
extern void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag);
extern u32 gAudioPendingLoadFlags;
extern volatile u32 gAudioCompletedLoadFlags;
extern char sMidiWadLoadedCallbackLoadError[];
extern void gameTextRenderStrs(char* str, int arg2);
extern u8 gMidiWadLoadStarted;
extern MusicChannel gMusicChannels[];
extern int gMusicChannelCounterA;
extern int gMusicChannelCounterB;
extern int gMidiWadLoadedSize;
extern void *gMidiWadFileData;
extern void *gMidiWadPayloadStart;
extern int gMidiWadPayloadSize;
extern int gMidiWadArenaSize;
extern char sMidiWadPath[];
extern u32 mmSetFreeDelay(u32 delay);
extern u8 testAndSet_onlyUseHeap3(int arg);
extern void *loadFileByPathAsync(char *path, int *outSize, int unused, void (*cb)(void *));
extern void fn_80008F38(void *addr, u32 dest, u32 size);
extern s16 sMusicTrackTable[];
extern char sPoolDataMLoadedCallbackLoadError[];
extern char sPoolDataSLoadedCallbackLoadError[];
extern char sProjectDataMLoadedCallbackLoadError[];
extern char sProjectDataSLoadedCallbackLoadError[];
extern char sSampleBufferMLoadedCallbackLoadError[];
extern char sSampleBufferSLoadedCallbackLoadError[];
extern char sSampleDirectoryMLoadedCallbackLoadError[];
extern char sSampleDirectorySLoadedCallbackLoadError[];
extern char sSfxTriggersLoadedCallbackLoadError[];
extern char sMusicTriggersLoadedCallbackLoadError[];
extern char sStreamsLoadedCallbackLoadError[];
extern StreamEntry* gStreamsData;
extern int gStreamsCount;
extern int gVoxMapsSlotTimers[];
extern u32 gVoxMapsTransformObj;
extern void Music_Trigger(int id, int arg);
extern f32 lbl_803DE6B0;
extern int lbl_803DC9AC;
extern int lbl_803DC9B0;
extern int lbl_803DC9B4;
extern int lbl_803DC9B8;
extern int lbl_803DC9BC;
extern int DVDRead(void* fileInfo, void* buf, int size, int offset);
extern int DVDOpen(char* path, void* fileInfo);
extern void DVDSetAutoInvalidation(int autoInval);
extern void DCStoreRange(void* addr, u32 nBytes);
extern int DVDReadAsyncPrio(void* fileInfo, void* buf, int size, int offset, void (*cb)(void*), int prio);
extern void checkReset(void);
extern void waitNextFrame(void);
extern void mmFreeTick(int arg);
extern void GXFlush_(int a, int b);
extern void padUpdate(void);
extern void dvdCheckError(void);
extern void gameTextRun(void);
extern int gAudioStreamFadeTable[];
extern f32 lbl_803DE5D4;
extern f32 gAudioStreamEndPosInfinite;
extern int DVDPrepareStreamAsync(void* fileInfo, int a, int b, void (*cb)(void));
extern int DVDStopStreamAtEndAsync(void* fileInfo, int a);
extern f32 lbl_803DE6BC;
extern f32 lbl_803DE6C0;
extern f32 lbl_803DE6C4;
extern f32 lbl_803DE6C8;
extern f32 lbl_803DE6CC;
extern f32 lbl_803DE6D0;
extern char lbl_803DB294;
extern char lbl_803DB29C;
extern char lbl_803DB2A0;
extern int lbl_803DB27C;
extern int lbl_803DB280;
extern int lbl_803DB284;
extern int lbl_803DB288;
extern u8 pauseMenuState;
extern int getHudHiddenFrameCount(void);
extern int getMinimapY(void);
extern void drawHudBox(int a, s16 b, int c, int d, int e, int f);
extern MusicTrigger* gMusicTriggersData;
extern int gMusicTriggersCount;
extern void Music_LoadChannelForTrigger(MusicTrigger *trigger);
extern f32 gAudioFramesPerSecond;
extern f32 lbl_803DE568;
extern void sndSeqStop(int handle);
extern void sndSeqMute(int handle, int a, int b);
extern void sndSeqContinue(int handle);
extern SynthVoice gSynthVoices[];
extern VoxMaps gVoxMaps;
extern u8 gVoxMapsSlotInUse[8];
extern int *gVoxMapsMapList;
extern int gVoxMapsMaxMapIndex;
extern void *gVoxMapsScratchBuffer;
extern void *gVoxMapsScratchBufferPtr;
extern void *gVoxMapsLargeTextures[2];
extern void *gVoxMapsSmallTextures[2];
extern void loadAssetFileById(void **out, int id);
extern void *textureAlloc(int w, int h, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern int lbl_803DCDC8;
extern int lbl_803DCDCC;
extern f32 gVoxMapsBlockWorldSize;
extern f32 fastFloorf(f32 v);
extern void *mapGetBlockAtPos(int x, int y, int z);
extern void *fn_80059334(int a, int b);
extern void *voxLoadVoxMapActual(int mapArg, int slot, int b9, int b8);
extern VoxState gVoxMapsRouteState;
extern char sVoxmapsRouteNodesListOverflow[];
extern int getTableFileEntry(int fileId, int index, int *out);
extern void loadVoxMaps(int handle, int *outCount, int *outSize);
extern int loadAndDecompressDataFile(int id, void *buf, int blockOff, int len, int a, int b, int c);
extern s8 gAudioSoundMode;
extern void sndOutputMode(int mode);
extern u32 OSGetSoundMode(void);
extern void OSSetSoundMode(int mode);
extern u8 gUtf8CharClassTable[];
extern int gUtf8ClassOffsetTable[];
extern int getControlCharLen(u32 c);
extern void voxmapsFn_80010ff4(struct RouteState *state, VoxBoxArg* a2, int a3, u16 count, s16* box);
extern f32 gVoxMapsHCostScale;
extern char sVoxMapsDebugStrings[];
extern int fn_800119FC(s16 *dest, s16 *start, s16 *out);
extern int fn_80011EB0(RouteState *state, int a);
extern GameTextFont* gameTextFonts;
extern GameTextDef *gameTextGet(int id);
extern void gameTextDrawBox(GameTextDef *def, int a, TextSlot *slot);
extern u8 lbl_803DC9A4;
extern u8 lbl_803DC9A5;
extern u8 lbl_803DC9A6;
extern u8 lbl_803DC9A7;
extern int lbl_803DC9C0;
extern char **textMeasureFn_80016c9c(char *str, f32 width, f32 height, int *outCount, f32 *outLineH);
extern void textRenderStr(char *str, TextSlot *slot, f32 x, f32 y, f32 lineH, int flag);
extern int gameTextCharset;
extern int curLanguage;
extern LanguageName sLanguageNameTable[];
extern FontSizeEntry lbl_802C8680[];
extern u16 lbl_803DC9AA;
extern u16 lbl_803DC9A8;
extern void *lbl_803DB378;
extern f32 lbl_803DE704;
extern f32 lbl_803DE708;
extern void *mmAllocateFromFBMemoryStore(void *store);
extern SpecialGlyph lbl_802C86F0[];
extern int lbl_803DC984;
extern f32 lbl_803DC9A0;
extern u8 lbl_803DC990;
extern u8 lbl_803DC991;
extern u8 lbl_803DC992;
extern u8 lbl_803399C0[];
extern f32 lbl_803DC994;
extern int lbl_803DC998;
extern int lbl_803DC99C;
extern f32 lbl_803DE700;
extern f32 lbl_803DB3D0;
extern void* gSfxTriggersData;
extern u8 gAudioHardwareInitialized;
extern u8 gAudioMusicGroupReady;
extern u8 gAudioSfxGroupsReady;
extern u8 gAudioReady;
extern void *gAudioStarfoxMPoolDataHandle;
extern void *gAudioStarfoxMProjectDataHandle;
extern void *gAudioStarfoxMSampleDirectoryHandle;
extern void *gAudioStarfoxMSampleBufferHandle;
extern void *gAudioStarfoxSPoolDataHandle;
extern void *gAudioStarfoxSProjectDataHandle;
extern void *gAudioStarfoxSSampleDirectoryHandle;
extern void *gAudioStarfoxSSampleBufferHandle;
extern int gAudioMemAllocHook;
extern int gAudioMemFreeHook;
extern f32 lbl_803DE550;
extern f32 lbl_803DE554;
extern f32 lbl_803DE558;
extern f32 lbl_803DE55C;
extern u8 gAudioReverbSettings[];
extern u8 gAudioAramBlock[];
extern void ARInit(void *arena, int count);
extern void ARQInit(void);
extern void AIInit(int arg);
extern void AISetDSPSampleRate(int rate);
extern void sndSetHooks(int *hooks);
extern void sndInit(int a, int b, int c, int d, int e, int f);
extern void sndAuxCallbackUpdateSettingsReverbSTD(void *settings);
extern void sndAuxCallbackReverbSTD(void);
extern void sndSetAuxProcessingCallbacks(int a, void *cb, void *settings, int d, int e, int f, int g, int h, int i);
extern void sndVolume(int a, int b, int c);
extern int sndPushGroup(void *project, u16 group, void *sampleBuffer, void *sampleDir, void *pool);

int getLActions(int a, int b, u16 idx);
void render_copyPackedU64Tail(u64 *dst, u32 packed);
void render_copyPackedU64Head(u64 *dst, u32 packed);
int getEnvfxActImmediately(int a, int b, u16 idx, int d);
int getEnvfxAct(int a, int b, u16 idx, int d);
u8 *modelRenderFn_80006744(u8 *p, int count, ModelRenderInstrsState *state, int stride, u8 bitWidth);
int fn_80006B1C(ModelRenderInstrsState *src, ModelRenderInstrsState *dst, int count, int gap, u8 bitWidth);
void audioStopByMask(int mask);
void audioReset(void);
int audioIsResetting(void);
void audioStopAll(void);
void audioUpdate(void);
u32 audioFlagFn_8000a188(u32 mask);
void audioFree(void *ptr);
void *_audioAlloc(u32 size);
void Music_ChannelLoadedCallback(MusicBank *bank, MusicChannel *channel, MusicTrigParam *trigger);
int Sfx_ReadTriggerParams(SfxTriggerFull *trigger, u16 *outSfxId, u8 *outVol, f32 *outF6, f32 *outF7, f32 *outF8, int *outI9, int *outI10, int *outI11);
SfxTrigger *Sfx_FindTrigger(u16 id);
SfxObjectChannel *Sfx_AllocObjectChannel(int a, int b, double pitch, int c, int d);
void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, f32 *v);
f32 Sfx_GetListenerRelativeDistance(f32 *soundPos, f32 *outDelta);
void AudioStream_StopAll(void);
u32 AudioStream_GetMusicFadeFlagA(void);
u32 AudioStream_GetMusicFadeFlagB(void);
u32 AudioStream_GetCurrentId(void);
u8 AudioStream_IsPreparing(void);
void AudioStream_SetVolume(u8 volume);
void AudioStream_CancelCallback(s32 result);
void AudioStream_StopCurrent(void);
void fn_8000D0B4(void);
void AudioStream_CancelPrepared(void);
void AudioStream_StartPrepared(void);
void AudioStream_UpdateFadeTimer(void);
void AudioStream_SetDefaultVolume(u8 volume);
void AudioStream_Init(void);
void AudioStream_PrepareCallback(void);
void AudioStream_PlayAddrCallback(u32 result);
void Sfx_ClearLoopedObjectSounds(void);
void Sfx_UpdateLoopedObjectSounds(void);
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);
void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj);
void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId);
void Sfx_AddLoopedObjectSound(u32 obj, u16 sfxId);
void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, s8 yawIndex);
void Obj_UpdateWorldTransform(s16 *obj);
s32 Angle_AddWrappedS16(s32 angle, s16 *delta);
s32 Angle_SubWrappedS16(s32 angle, s16 *delta);
void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_GetWorldPosition(u32 obj, f32 *outX, f32 *outY, f32 *outZ);
void Obj_BuildTransformMatricesForYaw(u32 obj, s32 yawIndex);
void Obj_BuildTransformMatrices(u32 obj);
s32 Obj_BuildTransformMatrixSlot(u32 obj);
void Curve_SampleSegmentPoints(f32 *px, f32 *py, f32 *pz, f32 *outX, f32 *outY, f32 *outZ, int count, void (*evalFn)(f32 *ch, f32 *buf));
void Curve_BuildSegmentLengthTable(Curve *curve, int count);
int Curve_AdvanceAlongPath(Curve *curve, f32 dt);
void curvesSetupMoveNetworkCurve(Curve *curve);
void curvesMove(Curve *curve);
int *voxmaps_getRouteNode(u8 *header, int *nodeBase, u8 *bitmap, int d, int e, int f);
void dvdCheckError(void);
int return0xFFFF_80008B6C(void);
int return0x64_8000A378(void);
void doNothing_8000CF54(void);
void doNothing_endOfFrame(void);
s32 Music_GetActivePriority(void);
s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel);
s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);
void Sfx_StopAllObjectSounds(void);
void audioFn_8000b694(u32 value);
void Sfx_SetObjectSoundsPaused(s32 paused);
void Sfx_StopObjectChannel(u32 obj, u32 channel);
void Sfx_StopFromObject(u32 obj, u32 sfxId);
void Sfx_SetObjectChannelVolume(u32 obj, u32 channel, u8 volume, f32 volumeScale);
void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);
void Sfx_UpdateObjectChannel3D(SfxObjectChannel *objectChannel);
void Sfx_PlayFromObjectEx(u32 obj, f32 *pos, u32 channel, u16 sfxId);
void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u16 sfxId);
void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u16 sfxId);
void Sfx_PlayFromObject(u32 obj, u16 sfxId);
void Sfx_UpdateObjectSounds(void);
void Sfx_InitObjectChannels(void);
SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode);
f32* Camera_GetViewRotationMatrix(void);
f32* Camera_GetInverseViewRotationMatrix(void);
f32* Camera_GetViewMatrix(void);
f32* Camera_GetInverseViewMatrix(void);
void* Camera_GetCurrentViewSlot(void);
u8 CameraShake_IsActive(void);
void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
void CameraShake_SetAllMagnitudes(f32 magnitude);
void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude);
void* fn_8000E814(void);
void Camera_LoadModelViewMatrix(void* unused0, void* unused1, CameraViewSlot* transform, f32 scale, f32* matrix);
void Camera_NdcToScreen(f32 ndcX, f32 ndcY, f32 ndcZ, s32* outX, s32* outY, s32* outZ);
void screenFn_8000e944(void* viewportArg);
void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, f32* outViewZ);
void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ);
void Camera_ProjectWorldSphere( f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX, f32* outRadiusY, f32* outRadiusZ);
void viewportEffectFn_8000e380(void);
void Camera_ApplyCurrentViewport(void* viewportArg);
void Camera_UpdateProjection(void* viewportArg);
void Camera_GetCurrentViewport(s32* outX, s32* outY, u32* outHeight, s32* outWidth);
void Camera_SetCurrentViewIndex(int index);
f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll);
void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_UpdateViewMatrices(void);
void Camera_ApplyFullViewport(void);
void fn_8000F83C(void);
void fn_8000F8F8(void);
void fn_8000F9B4(void);
u16 fn_8000FA70(void);
u16 fn_8000FA90(void);
u8 Camera_IsViewYOffsetEnabled(void);
void Camera_DisableViewYOffset(void);
void Camera_EnableViewYOffset(void);
s16 Camera_GetViewportYOffset(void);
void Camera_SetViewportYOffset(s16 yOffset);
f32* Camera_GetProjectionMatrix(void);
void Camera_RebuildProjectionMatrix(void);
f32 Camera_GetFarPlane(void);
void Camera_SetFarPlane(f32 farPlane, int transitionFrames);
f32 Camera_GetNearPlane(void);
f32 Camera_GetAspectRatio(void);
void Camera_SetAspectRatio(f32 aspectRatio);
f32 Camera_GetFovY(void);
void Camera_SetFovY(f32 fovY);
void Camera_InitState(void);
f32 Curve_EvalLinear(f32 t, f32* values);
f32 Curve_EvalCatmullRom(f32 t, f32* values, f32* outTangent);
f32 Curve_EvalBezier(f32 t, f32* values, f32* outTangent);
void Curve_BuildHermiteCoeffs(f32* values, f32* coefficients);
f32 Curve_EvalHermite(f32 t, f32* values, f32* outTangent);
void Curve_BuildBSplineCoeffs(f32* values, f32* coefficients);
f32 Curve_EvalBSpline(f32 t, f32* values, f32* outTangent);
void CurveHeap_SiftDown(CurveHeapNode* heap, s32 count, s32 index);
s16 Queue_GetCount(RingBufferQueue* queue);
BOOL Queue_IsEmpty(RingBufferQueue* queue);
void Queue_Peek(RingBufferQueue* queue, void* dst);
void Queue_Pop(RingBufferQueue* queue, void* dst);
void Queue_Push(RingBufferQueue* queue, void* src);
void Queue_Init(RingBufferQueue* queue, void* data, int capacity, int elemSize);
BOOL Stack_IsEmpty(RingBufferQueue* stack);
BOOL Stack_IsFull(RingBufferQueue* stack);
void Stack_Pop(RingBufferQueue* stack, void* dst);
void Stack_Push(RingBufferQueue* stack, void* src);
void Stack_Free(RingBufferQueue* stack);
RingBufferQueue* allocModelStruct_800139e8(int capacity, int elemSize);
s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state);
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit);
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC);
void objList_remove(ObjLinkedList* list, int item);
void objListAdd(ObjLinkedList* list, int prev, int item);
void fn_80013B6C(ObjLinkedList* list, s16 nextOffset);
BOOL model_findIdxInModelList(ModelList* list, void* header, int* outIndex);
BOOL ModelList_getHeader(ModelList* list, int index, void* outHeader);
void model_adjustModelList(ModelList* list, int index);
void modelInitModelList(ModelList* list, s16 index, void* header);
ModelList* allocModelStruct(int capacity, int dataSize);
BOOL Resource_Release(void* handleSlot);
void* Resource_Acquire(u32 id, int unused);
void Resource_ResetRefCounts(void);
int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third);
void fn_8001404C(s32 value);
u32 gameTimerIsRunning(void);
void hudNumberFn_80014060(void);
void set_hudNumber_803db278(s32 value);
u32 isGameTimerDisabled(void);
void gameTimerStop(void);
f32 fn_8001461C(void);
f32 fn_80014668(void);
void timerSetToCountUp(void);
void gameTimerInit(s8 flags, int minutes);
void curUiDllDraw(int a, int b, int c, int d);
void uiDll_runFrameEndAndLoadNext(void);
int uiDll_runFrameStartAndLoadNext(void);
void set_uiDllIdx_803dc8f0(int idx);
int getUiDllFn_80014930(void);
int getCurUiDll(void);
void* getDLL16(void);
void loadUiDll(int index);
void initGameTimer(void);
void setJoypadDisabled(void);
void padFn_80014b18(int value);
u32 buttonGetDisabled(int port);
void buttonDisable(int port, u32 mask);
void padClearAnalogInputY(int port);
void padClearAnalogInputX(int port);
void stopRumble2(void);
void stopRumble(void);
void doRumble(f32 duration);
void setRumbleEnabled(u8 enabled);
void fileReadCb_80015954(void* result);
void setFileInfo(void* fileInfo);
int isSpace(u32 c);
void padGetAnalogInput(int port, u8* x, u8* y);
u8 padGetCY(int port);
u8 padGetCX(int port);
u8 padGetStickY(int port);
u8 padGetStickX(int port);
u8 padGetLTrigger(int port);
u8 padGetRTrigger(int port);
u16 getPadFn_80014d9c(int port);
u16 getButtons_80014dd8(int port);
u32 getButtonsJustPressedIfNotBusy(int port);
u32 getButtonsJustPressed(int port);
u32 getNewInputs(int port);
u32 getButtonsHeld(int port);
int initControllers(void);
void padUpdate(void);
void* gameTextGetBox(int box);
void* gameTextGetCurBox(void);
void fn_80009008(void);
s16 renderModeSetOrGet(int mode);
void gameTextFn_80016c18(int a, int b);
void voxmaps_freeRouteWork(void** p);
void voxmaps_allocRouteWork(void** p);
void gameTextFreePhrase(int* p);
void fn_80008EDC(TextCallbackEntry* p);
void gameTextFn_80016810(int a, int b, int c);
int gameTextGetTaskText(int id, int* outA, int* outB);
void gameTextShowTimeStr(char* str);
void gameTextShow(int a);
void gameTextShowStr(char *text, int box, int arg2, int arg3);
void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag);
void MIDIWADLoadedCallback(int status, void* fileInfo);
int musicInitMidiWad(void);
void gameTextAppendStr(char* str, int arg2);
void poolDataMLoadedCallback(int status, void* fileInfo);
void poolDataSLoadedCallback(int status, void* fileInfo);
void projectDataMLoadedCallback(int status, void* fileInfo);
void projectDataSLoadedCallback(int status, void* fileInfo);
void sampleBufferMLoadedCallback(int status, void* fileInfo);
void sampleBufferSLoadedCallback(int status, void* fileInfo);
void sampleDirectoryMLoadedCallback(int status, void* fileInfo);
void sampleDirectorySLoadedCallback(int status, void* fileInfo);
void sfxTriggersLoadedCallback(int status, void* fileInfo);
void musicTriggersLoadedCallback(int status, void* fileInfo);
void streamsLoadedCallback(int status, void* fileInfo);
void voxmaps_updateTimers(void);
void voxmaps_gridToWorld(f32* out, s16* grid);
void fn_80008F38(void* addr, u32 dest, u32 size);
void audioAllocFn_80008df4(void* source, u32 size, void** outBuf, u32 cb, u32 p5, u32 p6, u32 p7);
int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId);
void voxmaps_worldToGrid(f32* in, s16* out);
void gameTextBoxFn_800164b0(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit);
void* loadFileByPath(char* path, int* outSize);
int AudioStream_Play(int id, void (*preparedCallback)(void));
void gameTimerRun(void);
int DVDRead(void* fileInfo, void* buf, int size, int offset);
void Music_Trigger(int id, int arg);
void streamFn_8000a380(int mask, int mode, int time);
void Music_Update(void);
void Music_LoadChannelForTrigger(MusicTrigger *trigger);
void Music_PlayTrackByIndex(int index);
void voxmaps_resetLoadedMaps(void);
void voxmaps_initialise(void);
int *voxmaps_updateActiveMap(VoxPos *obj);
int voxmaps_traceLine(VoxPos *start, VoxPos *end, VoxPos *coordOut, u8 *occOut, u8 skipFirst);
void *voxLoadVoxMapActual(int mapArg, int slot, int b9, int b8);
void audioSetSoundMode(int mode, u8 forceFlag);
int utf8GetNextChar(u8* str, int* outLen);
char *gameStrcpy(char *dst, char *src);
void fn_800118EC(int a1, VoxBoxArg* a2, int a3);
void voxmapsFn_80010ff4(struct RouteState *state, VoxBoxArg *a2, int a3, u16 count, s16 *box);
int voxmaps_processRouteQueue(RouteState *state, int count);
int voxmaps_updateRoutePath(RouteNav *nav, RouteState *state);
int fn_800119FC(s16 *dest, s16 *start, s16 *out);
int fn_80011EB0(RouteState *state, int count);
void gameTextFn_8001628c(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
char **textMeasureFn_80016c9c(char *str, f32 width, f32 height, int *outCount, f32 *outLineH);
void gameTextRenderStrs(char *str, int boxIdx);
void textDisplayFn_800168dc(int textId, TextDisplayState *state);
void gameTextFn_8001658c(int a, int b, int c);
void* loadFileByPathAsync(char* path, int* outSize, int unused, void (*cb)(void*));
void audioLoadTriggerData(void);
int audioInit(void);

#endif
