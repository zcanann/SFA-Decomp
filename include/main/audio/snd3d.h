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
    u8 pad04[0x18];
    s8 assignedVoice;
} SndSpatialEntry;

typedef struct Snd3DEmitter {
    struct Snd3DEmitter *next;
    struct Snd3DEmitter *prev;
    SndSpatialEntry *entry;
    u8 pad0c[4];
    u32 flags;
    u8 pad14[0x3c - 0x14];
    u32 handle;
    u8 pad40[4];
    u16 fxId;
    u8 studio;
    u8 pad47[0x4c - 0x47];
    f32 age;
} Snd3DEmitter;

void s3dHandle(void);
void s3dInit(u32 flags);
void s3dExit(void);
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, void *data);

#endif /* MAIN_AUDIO_SND3D_H_ */
