#ifndef MAIN_AUDIO_SND3D_H_
#define MAIN_AUDIO_SND3D_H_

#include "ghidra_import.h"

#define S3D_EMITTER_FLAG_POSITIONAL 0x00000001
#define S3D_EMITTER_FLAG_RESTART_ON_STOP 0x00000002
#define S3D_EMITTER_FLAG_STOP_AT_ORIGIN 0x00000004
#define S3D_EMITTER_FLAG_USE_AUX_STUDIO 0x00000010
#define S3D_EMITTER_FLAG_REMOVE_AT_ORIGIN 0x00000040
#define S3D_EMITTER_FLAG_PLAYING 0x00020000
#define S3D_EMITTER_FLAG_REMOVE 0x00040000
#define S3D_EMITTER_FLAG_WAITING_FOR_ROOM 0x00080000
#define S3D_EMITTER_FLAG_AGE_OUT 0x00100000
#define S3D_INVALID_FX_HANDLE 0xffffffff

#define S3D_UPDATE_SKIP_TICKS 3
#define S3D_DEFAULT_FX_VOLUME 0x7f
#define S3D_DEFAULT_FX_PAN 0x40
#define S3D_INIT_STEREO_FLAG 0x2
#define S3D_BASE_STUDIO 1
#define S3D_MAX_STUDIOS 3
#define SND_MAX_VOICES 0x40
#define SND_MAX_STUDIOS 8
#define SND_DEFAULT_SAMPLE_RATE 0x7d00

typedef struct SndSpatialEntry {
    struct SndSpatialEntry *next;
    u8 pad04[4];
    u32 flags;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 averageDistanceSq;
    u8 assignedVoice;
    u8 pad1d[3];
    void (*activateCallback)(u8 voice, u32 user);
    void (*evictCallback)(u8 voice);
    u32 callbackUser;
    u32 fade;
} SndSpatialEntry;

typedef struct SndSpatialListener {
    struct SndSpatialListener *next;
    u8 pad04[4];
    SndSpatialEntry *entry;
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
} SndSpatialListener;

typedef struct SndStudioInputLink {
    struct SndStudioInputLink *next;
    u8 pad04[0x10];
    f32 inputScale;
    u8 pad18[4];
    u8 sendLevel;
    s8 activeInput;
    u8 pad1e[2];
    SndSpatialEntry *source;
    SndSpatialEntry *target;
    u32 flags;
    u8 pad2c[8];
    u8 studioInput[4];
} SndStudioInputLink;

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

typedef struct Snd3DEmitter {
    struct Snd3DEmitter *next;
    struct Snd3DEmitter *prev;
    SndSpatialEntry *entry;
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
} Snd3DEmitter;

void s3dHandle(void);
void s3dInit(u32 flags);
void s3dExit(void);
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, void *data);

#endif /* MAIN_AUDIO_SND3D_H_ */
