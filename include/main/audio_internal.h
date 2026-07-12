#ifndef MAIN_AUDIO_INTERNAL_H_
#define MAIN_AUDIO_INTERNAL_H_

#include "global.h"
#include "dolphin/ar.h"
#include "dolphin/dvd.h"

#define SFX_OBJECT_CHANNEL_COUNT 56
#define SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE 1
#define SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN 2
#define SFX_LOOPED_OBJECT_STOP_FLAG 0x40

#define STREAM_FADEBITS_FLAGA_SHIFT 6
#define STREAM_FADEBITS_FLAGB_SHIFT 4
#define STREAM_FADEBITS_STOPSFX_SHIFT 2
#define STREAM_VOLBITS_CHANMASK_BIT 7
#define STREAM_VOLBITS_VOLUME_MASK 0x7F

typedef struct AudioArqRequestEntry {
    ARQRequest request;
    void (*callback)(int, int, int);
    int callbackArg1;
    int callbackArg2;
    int callbackArg3;
} AudioArqRequestEntry;

STATIC_ASSERT(sizeof(AudioArqRequestEntry) == 0x30);

typedef struct AudioDvdStreamContext {
    DVDCommandBlock preparedCommand;
    DVDCommandBlock stopAtEndCommand;
    DVDFileInfo fileInfo;
    u8 pad9C[4];
} AudioDvdStreamContext;

STATIC_ASSERT(sizeof(AudioDvdStreamContext) == 0xA0);
STATIC_ASSERT(offsetof(AudioDvdStreamContext, preparedCommand) == 0x00);
STATIC_ASSERT(offsetof(AudioDvdStreamContext, stopAtEndCommand) == 0x30);
STATIC_ASSERT(offsetof(AudioDvdStreamContext, fileInfo) == 0x60);

typedef struct AudioDvdStreamStorage {
    DVDCommandBlock currentCommand;
    AudioDvdStreamContext prepared;
} AudioDvdStreamStorage;

STATIC_ASSERT(sizeof(AudioDvdStreamStorage) == 0xD0);
STATIC_ASSERT(offsetof(AudioDvdStreamStorage, prepared) == 0x30);

typedef struct MusicTrackSlot {
    s16 id;
    u8 unk2;
    u8 unk3;
    char* name;
    int offset;
    int size;
} MusicTrackSlot;

typedef struct StreamEntry {
    u16 id;
    u8 fadeBits;
    u8 volBits;
    u16 lengthRaw;
    char name[0xF];
    u8 flag;
} StreamEntry;

typedef struct MusicTrigger {
    u16 id;
    u16 track;
    u8 pad[0xc];
} MusicTrigger;

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
    f32 nearDistance;
    f32 farDistance;
    u8 globalCtrlDisabled;
    u8 pad29[0x07];
    u64 age;
} SfxObjectChannel;

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
    void* bankData;
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
    u16 nearDistanceRaw;
    u16 farDistanceRaw;
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

extern SfxLoopedObjectSoundTable gSfxLoopedObjectSoundFlags;
extern u16 gSfxLoopedObjectSoundCount;
extern SfxObjectChannel gSfxObjectChannels[];
extern u8 gSfxGlobalCtrlLevel;
extern u32 gSfxObjectChannelMatchCount;
extern u64 gSfxObjectChannelAge;
extern MusicSeqStartParams gMusicSeqStartParamsDefault;
extern u8 gSfxTriggerExtraTable;
extern void* gSfxTriggersData;
extern int gSfxTriggersCount;
extern SfxTriggerCacheEntry gSfxTriggerLookupCache[];
extern MusicChannel gMusicChannels[];
extern int gMusicChannelCounterA;
extern int gMusicChannelCounterB;
extern s32 gMusicActivePriority;
extern u32 gAudioResetting;
extern u32 gAudioManagedChannelMask;
extern u32 gAudioActiveChannelMask;
extern u8 gAudioInitStarted;
extern u8 gAudioStreamDefaultVolume;
extern u8 gAudioStreamVolumeLeft;
extern u8 gAudioStreamVolumeRight;
extern u32 gAudioStreamMusicFadeFlagA;
extern u32 gAudioStreamMusicFadeFlagB;
extern void (*gAudioStreamPreparedCallback)(void);
extern s32 gAudioStreamStartWhenPrepared;
extern s32 gAudioStreamPreparingId;
extern s32 gAudioStreamPreparedId;
extern f32 gAudioStreamEndPos;
extern f32 gAudioStreamPos;
extern f32 gAudioStreamFramesPerSecond;
extern u8 gAudioStreamDvdBlockCurrent[];
extern u8 gAudioStreamDvdBlockPrepared[];
extern char sDvdCancelStreamWarning[];
extern f32 gSfxPanCenter;
extern f32 gSfxPanScale;
extern f32 gAudioPi;
extern f32 gAudioAngleToRadDivisor;
extern f32 lbl_803DE5D0;
extern f32 lbl_803DE570;
extern f32 lbl_803DE574;
extern f32 lbl_803DE578;
extern f32 lbl_803DE598;
extern f32 lbl_803DE59C;
extern f32 lbl_803DE5A0;
extern f32 lbl_803DE560;
extern f32 lbl_803DE590;
extern f32 lbl_803DE5B4;
extern f32 lbl_803DE5B8;
extern double lbl_803DE5C0;
extern double lbl_803DE5C8;
extern volatile int gAudioArqRequestDone;
extern int gAudioArqRequestIndex;
extern AudioArqRequestEntry gAudioArqRequests[];
extern u32 gAudioPendingLoadFlags;
extern volatile u32 gAudioCompletedLoadFlags;
extern char sMidiWadLoadedCallbackLoadError[];
extern u8 gMidiWadLoadStarted;
extern int gMidiWadLoadedSize;
extern void* gMidiWadFileData;
extern void* gMidiWadPayloadStart;
extern int gMidiWadPayloadSize;
extern int gMidiWadArenaSize;
extern char sMidiWadPath[];
extern MusicTrackSlot sMusicTrackTable[];
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
extern int gAudioStreamFadeTable[];
extern f32 gAudioStreamEndPosInfinite;
extern MusicTrigger* gMusicTriggersData;
extern int gMusicTriggersCount;
extern f32 gAudioFramesPerSecond;
extern s8 gAudioSoundMode;
extern u8 gAudioHardwareInitialized;
extern u8 gAudioMusicGroupReady;
extern u8 gAudioSfxGroupsReady;
extern u8 gAudioReady;
extern void* gAudioStarfoxMPoolDataHandle;
extern void* gAudioStarfoxMProjectDataHandle;
extern void* gAudioStarfoxMSampleDirectoryHandle;
extern void* gAudioStarfoxMSampleBufferHandle;
extern void* gAudioStarfoxSPoolDataHandle;
extern void* gAudioStarfoxSProjectDataHandle;
extern void* gAudioStarfoxSSampleDirectoryHandle;
extern void* gAudioStarfoxSSampleBufferHandle;
extern int gAudioMemAllocHook;
extern int gAudioMemFreeHook;
extern u8 gAudioReverbSettings[];
extern u32 gAudioAramBlock[0x2C / sizeof(u32)];

int sndSeqPlayEx(int a, int b, void* bank, MusicSeqStartParams* params, int e);
SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode);
void Sfx_UpdateObjectChannel3D(SfxObjectChannel* objectChannel);
void Music_Update(void);
void Sfx_UpdateObjectSounds(void);
void Sfx_StopAllObjectSounds(void);
void AudioStream_UpdateFadeTimer(void);
void AudioStream_CancelCallback(s32 result, DVDCommandBlock* block);
void fn_8000D0B4(s32 result, DVDCommandBlock* block);
void fn_80008EDC(u32 request);
void Music_LoadChannelForTrigger(MusicTrigger* trigger);

#endif /* MAIN_AUDIO_INTERNAL_H_ */
