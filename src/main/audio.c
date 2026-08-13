#include "main/audio/music_api.h"
#include "musyx/hw_samplemem.h"
#include "main/audio_internal.h"
#include "musyx/snd_groups.h"
#include "main/attract_movie_api.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "dolphin/ai.h"
#include "dolphin/ar.h"
#include "dolphin/dvd.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/os/OSRtc.h"
#include "src/musyx/runtime/synth_internal.h"
#include "main/gamebits_api.h"
#include "main/audio/sfx_object_system_api.h"
#include "main/audio/stream_api.h"
#include "musyx/snd3d.h"
#include "musyx/snd_core.h"

/* Local prototypes: this TU declares sndMasterVolume with int volume/time,
   which disagrees with the musyx definition -- retail calls it directly with
   both unnarrowed, which only that declaration produces. */
void sndMasterVolume(int volume, int time, u8 musicFlag, u8 fxFlag);
void sndSeqVolume(u8 volume, u16 time, u32 seqId, u8 mode);
void sndVolume(u8 volume, u16 time, u8 group);
void sndOutputMode(int mode);
#define SYNTH_INTERNAL_USE_PROJECT_TYPES

const MusicSeqStartParams gMusicSeqStartParamsDefault = {
    4, {0xFFFFFFFF, 0xFFFFFFFF}, 0x100, {0, 0x7F}, 0, NULL, 0, NULL};

s8 gAudioSoundMode = -1;
s32 lbl_803DB1EC[1] = {0};
char sMusicTrackNameBarren[] = "barren";
char sMusicTrackNameBarrels[] = "barrels";
char sMusicTrackNameBloop[] = "bloop";
char sMusicTrackNameDIMDay[] = "DIM_Day";
char sMusicTrackNameDrako1[] = "drako_1";
char sMusicTrackNameDrako2[] = "drako_2";
char sMusicTrackNameDrako3[] = "drako_3";
char sMusicTrackNameKptext[] = "kptext";
char sMusicTrackNameKpwin[] = "kpwin";
char sMusicTrackNameSlope[] = "slope";
char sMusicTrackNameTrex2a[] = "trex_2a";

u32 sAudioUnused1;
void* gMidiWadFileData;
int gMidiWadArenaSize;
int gMidiWadPayloadSize;
void* gMidiWadPayloadStart;
int gMusicChannelCounterB;
int gMusicChannelCounterA;
s32 gMusicActivePriority;
int gMidiWadLoadedSize;
u8 gMidiWadLoadStarted;
int gMusicTriggersCount;
MusicTrigger* gMusicTriggersData;
u32 sAudioUnused0;
u32 gAudioPendingLoadFlags;
volatile u32 gAudioCompletedLoadFlags;
void* gAudioStarfoxMPoolDataHandle;
void* gAudioStarfoxMProjectDataHandle;
void* gAudioStarfoxMSampleDirectoryHandle;
void* gAudioStarfoxMSampleBufferHandle;
void* gAudioStarfoxSPoolDataHandle;
void* gAudioStarfoxSProjectDataHandle;
void* gAudioStarfoxSSampleBufferHandle;
void* gAudioStarfoxSSampleDirectoryHandle;
u8 gAudioHardwareInitialized;
u8 gAudioReady;
u8 gAudioSfxGroupsReady;
u8 gAudioMusicGroupReady;
u8 gAudioInitStarted;
u32 gAudioActiveChannelMask;
u32 gAudioManagedChannelMask;
u32 gAudioResetting;
volatile int gAudioArqRequestDone;
int gAudioArqRequestIndex;

/* gAudioPendingLoadFlags / gAudioCompletedLoadFlags: one bit per async
 * resource load, set when enqueued and cleared/mirrored when the load
 * callback fires. */
#define AUDIO_LOAD_MUSIC_TRIGGERS 0x1   /* music trigger table */
#define AUDIO_LOAD_SFX_TRIGGERS   0x2   /* sfx trigger table */
#define AUDIO_LOAD_STREAMS        0x4   /* stream table */
#define AUDIO_LOAD_M_POOL         0x8   /* music group: pool data */
#define AUDIO_LOAD_M_PROJECT      0x10  /* music group: project data */
#define AUDIO_LOAD_M_SAMPLE_DIR   0x20  /* music group: sample directory */
#define AUDIO_LOAD_M_SAMPLE_BUF   0x40  /* music group: sample buffer */
#define AUDIO_LOAD_S_POOL         0x80  /* sfx group: pool data */
#define AUDIO_LOAD_S_PROJECT      0x100 /* sfx group: project data */
#define AUDIO_LOAD_S_SAMPLE_DIR   0x200 /* sfx group: sample directory */
#define AUDIO_LOAD_S_SAMPLE_BUF   0x400 /* sfx group: sample buffer */
#define AUDIO_LOAD_MIDI_WAD       0x800 /* MIDI WAD */

AudioArqRequestEntry gAudioArqRequests[0x300 / sizeof(AudioArqRequestEntry)];
ReverbState gAudioReverbSettings;

const SalHooks gAudioMemHooks = {_audioAlloc, audioFree};

void AudioAramReadAllocAsync(void* source, u32 size, void** outBuf, AudioArqRequestCallback callback,
                             MusicTrackSlot* callbackArg1, MusicChannel* callbackArg2,
                             MusicTrigger* callbackArg3)
{
    int idx;
    void* buf;
    AudioArqRequestEntry* entry;
    idx = gAudioArqRequestIndex;
    gAudioArqRequestIndex = idx + 1;
    entry = &gAudioArqRequests[idx];
    if (idx + 1 >= 0x10)
    {
        gAudioArqRequestIndex = 0;
    }
    if ((size & 0x1f) != 0)
    {
        size = (size | 0x1f) + 1;
    }
    buf = mmAlloc(size, 0, 0);
    *outBuf = buf;
    entry->callback = callback;
    entry->callbackArg1 = callbackArg1;
    entry->callbackArg2 = callbackArg2;
    entry->callbackArg3 = callbackArg3;
    DCFlushRange(buf, size);
    gAudioArqRequestDone = 0;
    ARQPostRequest(&entry->request, 0x64, 1, 1, (u32)source, (u32)buf, size,
                   AudioAramReadCompleteCallback);
}
static inline void Music_FreeChannel(MusicChannel* ch)
{
    sndSeqStop(ch->seqHandle);
    mm_free(ch->bankData);
    ch->trackId = -1;
    ch->seqHandle = -1;
    ch->bankData = NULL;
    ch->voiceId = 0xff;
    ch->status = 0;
    ch->priority = 0;
    ch->fadeTimer = 0.0f;
}

static inline int Music_IsTriggerExcluded(int id)
{
    switch (id)
    {
    case 0x2b:
    case 0xbd:
    case 0xeb:
        return 1;
    }
    return 0;
}

static inline MusicTrigger* Music_FindTriggerById(int id)
{
    int i = gMusicTriggersCount;
    MusicTrigger* trigger = gMusicTriggersData;
    while (i != 0)
    {
        if ((int)trigger->id == id)
        {
            return trigger;
        }
        trigger++;
        i--;
    }
    return NULL;
}

static inline MusicChannel* Music_FindFreeChannel(void)
{
    MusicChannel* channel = gMusicChannels;
    int i;
    for (i = 15; i >= 0; i--)
    {
        if (channel->status == 0)
        {
            return channel;
        }
        channel++;
    }
    return NULL;
}

static inline MusicTrackSlot* Music_FindTrackSlot(int track)
{
    MusicTrackSlot* slot = (MusicTrackSlot*)sMusicTrackTable;
    int i;
    for (i = 99; i >= 0; i--)
    {
        if (slot->id == track)
        {
            return slot;
        }
        slot++;
    }
    return NULL;
}

static inline MusicChannel* Music_FindActiveChannelForTrack(int track)
{
    int i;
    MusicChannel* ch = (MusicChannel*)(int)gMusicChannels;
    for (i = 15; i >= 0; i--)
    {
        if (ch->trackId == track)
        {
            if (ch->status == 0)
            {
            }
            else if (ch->status == 2)
            {
            }
            else
            {
                switch (ch->status)
                {
                case 5:
                    break;
                default:
                    return ch;
                }
            }
        }
        ch++;
    }
    return NULL;
}



void AudioAramReadCompleteCallback(u32 request)
{
    int i;
    AudioArqRequestEntry* p = (AudioArqRequestEntry*)request;
    AudioArqRequestEntry* e = gAudioArqRequests;
    for (i = 0; i < 16; i++)
    {
        if (p == e)
        {
            e->callback(e->callbackArg1, e->callbackArg2, e->callbackArg3);
            return;
        }
        e++;
    }
}

void AudioAramWriteSync(void* addr, u32 dest, u32 size)
{
    int idx;
    AudioArqRequestEntry* entry;
    idx = gAudioArqRequestIndex;
    gAudioArqRequestIndex = idx + 1;
    entry = &gAudioArqRequests[idx];
    if (idx + 1 >= 0x10)
    {
        gAudioArqRequestIndex = 0;
    }
    if ((size & 0x1f) != 0)
    {
        size = (size | 0x1f) + 1;
    }
    DCFlushRange(addr, size);
    gAudioArqRequestDone = 0;
    ARQPostRequest(&entry->request, 0x64, 0, 1, (u32)addr, dest, size,
                   AudioAramWriteCompleteCallback);
    while (gAudioArqRequestDone == 0)
    {
    }
}


void AudioAramWriteCompleteCallback(u32 request)
{
    (void)request;
    gAudioArqRequestDone = 1;
}

void sampleBufferSLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleBufferSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_S_SAMPLE_BUF;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_S_SAMPLE_BUF;
    }
}

void sampleDirectorySLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleDirectorySLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_S_SAMPLE_DIR;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_S_SAMPLE_DIR;
    }
}

void projectDataSLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sProjectDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_S_PROJECT;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_S_PROJECT;
    }
}

void poolDataSLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sPoolDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_S_POOL;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_S_POOL;
    }
}

void sampleBufferMLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleBufferMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_M_SAMPLE_BUF;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_M_SAMPLE_BUF;
    }
}

void sampleDirectoryMLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleDirectoryMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_M_SAMPLE_DIR;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_M_SAMPLE_DIR;
    }
}

void projectDataMLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sProjectDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_M_PROJECT;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_M_PROJECT;
    }
}


void poolDataMLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sPoolDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_M_POOL;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_M_POOL;
    }
}

void streamsLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sStreamsLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        StreamEntry* stream;
        int i;
        int streamCount;
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_STREAMS;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_STREAMS;
        stream = gStreamsData;
        streamCount = gStreamsCount;
        for (i = 0; i != streamCount; i++)
        {
            stream->flag = 0;
            stream++;
        }
    }
}


void sfxTriggersLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSfxTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_SFX_TRIGGERS;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_SFX_TRIGGERS;
    }
}

void musicTriggersLoadedCallback(s32 status, DVDFileInfo* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sMusicTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_MUSIC_TRIGGERS;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_MUSIC_TRIGGERS;
    }
}

void audioLoadTriggerData(void)
{
    char* base = sSampleBufferSLoadedCallbackLoadError;
    int info;
    int delay;
    if (gMusicTriggersData != NULL)
    {
        delay = mmSetFreeDelay(0);
        mm_free(gMusicTriggersData);
        mm_free(gSfxTriggersData);
        mm_free(gStreamsData);
        mmSetFreeDelay(delay);
    }
    gAudioPendingLoadFlags |= AUDIO_LOAD_MUSIC_TRIGGERS;
    gMusicTriggersData = loadFileByPathAsync(base + 0x1b4, &info, 1, musicTriggersLoadedCallback);
    gMusicTriggersCount = (u32)info >> 4;
    gAudioPendingLoadFlags |= AUDIO_LOAD_SFX_TRIGGERS;
    gSfxTriggersData = loadFileByPathAsync(base + 0x1cc, &info, 1, sfxTriggersLoadedCallback);
    gSfxTriggersCount = (u32)info >> 5;
    gAudioPendingLoadFlags |= AUDIO_LOAD_STREAMS;
    gStreamsData = loadFileByPathAsync(base + 0x1e0, &info, 1, streamsLoadedCallback);
    gStreamsCount = info / sizeof(StreamEntry);
}


void audioSetSoundMode(int mode, u8 forceFlag)
{
    if (forceFlag == 0)
    {
        if (OSGetSoundMode() != 1)
        {
            return;
        }
    }
    if ((u8)mode != gAudioSoundMode)
    {
        switch ((u8)mode)
        {
        case 0:
            sndOutputMode(1);
            break;
        case 1:
            sndOutputMode(2);
            break;
        case 2:
            sndOutputMode(0);
            break;
        case 3:
            sndOutputMode(1);
            break;
        }
    }
    if ((((u8)mode == 2) && (gAudioSoundMode != 2)) || (((u8)mode != 2) && (gAudioSoundMode == 2)))
    {
        if ((u8)mode == 2)
        {
            OSSetSoundMode(0);
        }
        else
        {
            OSSetSoundMode(1);
        }
    }
    gAudioSoundMode = mode;
}

void audioSetVolumes(int volume, int time, int musicFlag, int fxFlag, int streamFlag)
{
    if (musicFlag != 0 || fxFlag != 0)
    {
        sndMasterVolume(volume, time, musicFlag, fxFlag);
    }
    if (streamFlag != 0)
    {
        AudioStream_SetVolume(volume);
        AudioStream_SetDefaultVolume(volume);
    }
}

void audioStopByMask(int mask)
{
    if ((mask & 4) != 0)
    {
        Sfx_StopAllObjectSounds();
    }
    if ((mask & 1) != 0)
    {
        Music_StopChannelsByPriorityGroup(1, MUSIC_CHANNEL_STOP_DEFAULT, 0);
    }
    if ((mask & 2) != 0)
    {
        Music_StopChannelsByPriorityGroup(2, MUSIC_CHANNEL_STOP_DEFAULT, 0);
    }
    if ((mask & 8) != 0)
    {
        AudioStream_StopCurrent();
    }
}

void audioReset(void)
{
    if (gAudioInitStarted != 0)
    {
        sndQuit();
    }
    AIReset();
}

int audioIsResetting(void)
{
    return gAudioResetting;
}

void audioStopAll(void)
{
    gAudioResetting = 1;
    Sfx_StopAllObjectSounds();
    Music_StopChannelsByPriorityGroup(1, MUSIC_CHANNEL_STOP_DEFAULT, 0);
    Music_StopChannelsByPriorityGroup(2, MUSIC_CHANNEL_STOP_DEFAULT, 0);
    AudioStream_StopCurrent();
    gAudioManagedChannelMask &= ~0xfU;
    gAudioResetting = 1;
    if ((gAttractMovieState == 2) || (gAttractMovieState == 3))
    {
        Movie_SetVolumeFade(0, 500);
    }
    AudioStream_CancelPrepared();
}

void audioUpdate(void)
{
    Music_Update();
    Sfx_UpdateObjectSounds();
    AudioStream_UpdateFadeTimer();
}

int audioInit(void)
{
    char* base = sSampleBufferSLoadedCallbackLoadError;
    SalHooks hooks;
    int reverbWork;
    int delay;
    int group;

    hooks = gAudioMemHooks;
    if (!gAudioInitStarted)
    {
        gAudioInitStarted = 1;
        gAudioPendingLoadFlags = 0;
        gAudioCompletedLoadFlags = 0;
        mmSetDelay(1);
        if (gAudioHardwareInitialized)
        {
            return 1;
        }
        gAudioHardwareInitialized = 1;
        ARInit(gAudioAramBlock, 0xa);
        ARQInit();
        AIInit(0);
        AISetDSPSampleRate(0);
        sndSetHooks(&hooks);
        sndInit(0x30, 0x30, 0x18, 1, 1, 0x1000000);
        sndSetMaxVoices(0x30, 0x18);
        if (OSGetSoundMode() == 0)
        {
            gAudioSoundMode = 2;
            sndOutputMode(0);
        }
        else
        {
            gAudioSoundMode = 0;
            sndOutputMode(1);
        }
        gAudioReverbSettings.tempDisableFX = 0;
        gAudioReverbSettings.time = 3.0f;
        gAudioReverbSettings.preDelay = 0.033f;
        gAudioReverbSettings.damping = 0.5f;
        gAudioReverbSettings.coloration = 0.5f;
        gAudioReverbSettings.mix = 0.9f;
        sndAuxCallbackUpdateSettingsReverbSTD(&gAudioReverbSettings);
        reverbWork = 0;
        sndSetAuxProcessingCallbacks(0, sndAuxCallbackReverbSTD, &gAudioReverbSettings, 0xff, 0, 0, 0, 0xff,
                                     (void*)reverbWork);
        {
            if (!sndIsInstalled())
            {
                OSReport(base + 0x1f8);
                return 0xff;
            }
        }
        sndVolume(0x7f, 0, 0xff);
        sndMasterVolume(0x7f, 0x64, 1, 1);
        Sfx_InitObjectChannels();
        AudioStream_Init();
        audioLoadTriggerData();
        mmSetDelay(1);
        gAudioPendingLoadFlags |= AUDIO_LOAD_M_POOL;
        gAudioStarfoxMPoolDataHandle =
            loadFileByPathAsync(base + 0x228, NULL, 0, poolDataMLoadedCallback);
        gAudioPendingLoadFlags |= AUDIO_LOAD_M_PROJECT;
        gAudioStarfoxMProjectDataHandle =
            loadFileByPathAsync(base + 0x23c, NULL, 0, projectDataMLoadedCallback);
        gAudioPendingLoadFlags |= AUDIO_LOAD_M_SAMPLE_DIR;
        gAudioStarfoxMSampleDirectoryHandle =
            loadFileByPathAsync(base + 0x250, NULL, 0, sampleDirectoryMLoadedCallback);
        mmSetDelay(0);
        gAudioPendingLoadFlags |= AUDIO_LOAD_M_SAMPLE_BUF;
        gAudioStarfoxMSampleBufferHandle =
            loadFileByPathAsync(base + 0x264, NULL, 0, sampleBufferMLoadedCallback);
        if (gAudioStarfoxMPoolDataHandle == NULL || gAudioStarfoxMProjectDataHandle == NULL ||
            gAudioStarfoxMSampleDirectoryHandle == NULL || gAudioStarfoxMSampleBufferHandle == NULL)
        {
            return 0xff;
        }
        mmSetDelay(0);
    }
    if (!gAudioMusicGroupReady && (gAudioCompletedLoadFlags & AUDIO_LOAD_M_POOL) &&
        (gAudioCompletedLoadFlags & AUDIO_LOAD_M_PROJECT) && (gAudioCompletedLoadFlags & AUDIO_LOAD_M_POOL) &&
        (gAudioCompletedLoadFlags & AUDIO_LOAD_M_SAMPLE_DIR) && (gAudioCompletedLoadFlags & AUDIO_LOAD_M_SAMPLE_BUF))
    {
        sndPushGroup(gAudioStarfoxMProjectDataHandle, 0, gAudioStarfoxMSampleBufferHandle,
                     gAudioStarfoxMSampleDirectoryHandle, gAudioStarfoxMPoolDataHandle);
        delay = mmSetFreeDelay(0);
        mm_free(gAudioStarfoxMSampleBufferHandle);
        mmSetFreeDelay(delay);
        gAudioMusicGroupReady = 1;
        mmSetDelay(1);
        gAudioPendingLoadFlags |= AUDIO_LOAD_S_POOL;
        gAudioStarfoxSPoolDataHandle =
            loadFileByPathAsync(base + 0x278, NULL, 0, poolDataSLoadedCallback);
        gAudioPendingLoadFlags |= AUDIO_LOAD_S_PROJECT;
        gAudioStarfoxSProjectDataHandle =
            loadFileByPathAsync(base + 0x28c, NULL, 0, projectDataSLoadedCallback);
        gAudioPendingLoadFlags |= AUDIO_LOAD_S_SAMPLE_DIR;
        gAudioStarfoxSSampleDirectoryHandle =
            loadFileByPathAsync(base + 0x2a0, NULL, 0, sampleDirectorySLoadedCallback);
        mmSetDelay(0);
        gAudioPendingLoadFlags |= AUDIO_LOAD_S_SAMPLE_BUF;
        gAudioStarfoxSSampleBufferHandle =
            loadFileByPathAsync(base + 0x2b4, NULL, 0, sampleBufferSLoadedCallback);
        if (gAudioStarfoxSPoolDataHandle == NULL || gAudioStarfoxSProjectDataHandle == NULL ||
            gAudioStarfoxSSampleDirectoryHandle == NULL || gAudioStarfoxSSampleBufferHandle == NULL)
        {
            return 0xff;
        }
    }
    if (!gAudioSfxGroupsReady && (gAudioCompletedLoadFlags & AUDIO_LOAD_S_POOL) &&
        (gAudioCompletedLoadFlags & AUDIO_LOAD_S_PROJECT) && (gAudioCompletedLoadFlags & AUDIO_LOAD_S_POOL) &&
        (gAudioCompletedLoadFlags & AUDIO_LOAD_S_SAMPLE_DIR) && (gAudioCompletedLoadFlags & AUDIO_LOAD_S_SAMPLE_BUF))
    {
        for (group = 1; group <= 0x37; group++)
        {
            if (sndPushGroup(gAudioStarfoxSProjectDataHandle, group, gAudioStarfoxSSampleBufferHandle,
                             gAudioStarfoxSSampleDirectoryHandle, gAudioStarfoxSPoolDataHandle) == 0)
            {
                OSReport(base + 0x2c8, group);
            }
        }
        delay = mmSetFreeDelay(0);
        mm_free(gAudioStarfoxSSampleBufferHandle);
        mmSetFreeDelay(delay);
        gAudioSfxGroupsReady = 1;
    }
    if (!gAudioReady && gAudioMusicGroupReady && gAudioSfxGroupsReady)
    {
        gAudioReady = musicInitMidiWad();
    }
    if (gAudioReady && gAudioMusicGroupReady && gAudioSfxGroupsReady &&

        (gAudioCompletedLoadFlags & AUDIO_LOAD_MUSIC_TRIGGERS) &&
        (gAudioCompletedLoadFlags & AUDIO_LOAD_SFX_TRIGGERS) && (gAudioCompletedLoadFlags & AUDIO_LOAD_STREAMS))
    {
        gAudioResetting = 0;
        gAudioManagedChannelMask = 0x1f;
        gAudioActiveChannelMask = 0;
        return 1;
    }
    return 0;
}

u32 audioIsChannelUnavailable(u32 mask)
{
    s32 managed = gAudioManagedChannelMask & mask;
    if (managed == 0)
    {
        return 1;
    }
    return (gAudioActiveChannelMask & mask) != 0;
}


void audioFree(void* ptr)
{
    mm_free(ptr);
}

void* _audioAlloc(u32 size)
{
    return mmAlloc(size, 0xb, 0);
}

int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third)
{
    strcpy(dst, first);
    strcat(dst, second);
    strcat(dst, third);
    return 1;
}

static void MIDIWADLoadedCallback(s32 status, DVDFileInfo* fileInfo) {
    if (status == -1) {
        OSReport(sMidiWadLoadedCallbackLoadError);
        DVDClose(fileInfo);
        mm_free(fileInfo);
    } else {
        DVDClose(fileInfo);
        mm_free(fileInfo);
        gAudioPendingLoadFlags &= ~AUDIO_LOAD_MIDI_WAD;
        gAudioCompletedLoadFlags |= AUDIO_LOAD_MIDI_WAD;
    }
}

void Music_PlayTrackByIndex(int index)
{
    MusicTrigger* trigger = Music_FindTriggerById(MUSICTRIG_dark_ice_boss_1_ec);
    Music_StopChannelsByPriorityGroup(3, MUSIC_CHANNEL_STOP_DEFAULT, 0);
    trigger->track = sMusicTrackTable[index].id;
    Music_Trigger(MUSICTRIG_dark_ice_boss_1_ec, 1);
}

int Music_GetTrackCount(void)
{
    return 0x64;
}
void Music_StopChannelsByPriorityGroup(int priorityGroupMask, MusicChannelStopMode mode, int fadeTime)
{
    MusicChannel* ch = (MusicChannel*)(int)gMusicChannels;
    int i = 15;
    do
    {
        if (ch->status != 0 && ((ch->priorityGroup + 1) & priorityGroupMask) != 0)
        {
            switch (mode)
            {
            case MUSIC_CHANNEL_STOP_DEFAULT:
                if (audioIsResetting() == 0)
                {
                    if (ch->status != 2)
                    {
                        if (ch->status == 4 || ch->status == 5)
                        {
                            ch->status = 5;
                        }
                        else
                        {
                            sndSeqVolume(0, 250, ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                }
                else if (ch->status == 4 || ch->status == 5)
                {
                    ch->status = 5;
                }
                else
                {
                    Music_FreeChannel(ch);
                }
                break;
            case MUSIC_CHANNEL_STOP_FADE:
                if (ch->status != 2)
                {
                    if (ch->status == 4 || ch->status == 5)
                    {
                        ch->status = 5;
                    }
                    else
                    {
                        sndSeqVolume(0, (fadeTime < 500 ? 500 : fadeTime), ch->seqHandle, 1);
                        ch->status = 2;
                    }
                }
                break;
            }
        }
        ch++;
    } while (i-- != 0);
}

void Music_Trigger(int id, int arg)
{
    MusicTrigger* trigger;
    MusicChannel* channel;
    int i;
    int track;

    if (arg != 1 && arg != 0)
    {
        return;
    }
    trigger = Music_FindTriggerById(id);
    if (trigger == NULL)
    {
        return;
    }
    if (id == 0xeb && arg == 1)
    {
        MusicChannel* ch = Music_FindActiveChannelForTrack(0x5e);
        if (ch != NULL || mainGetBit(GAMEBIT_WMRelated0A7F) != 0u)
        {
            return;
        }
    }
    track = trigger->track;
    channel = Music_FindActiveChannelForTrack(track);
    if (arg == 1)
    {
        if (channel == NULL)
        {
            Music_LoadChannelForTrigger(trigger);
            return;
        }
        if (channel->status != 1)
        {
            return;
        }
        sndSeqVolume(channel->volume, trigger->fadeTime, channel->seqHandle, 0);
    }
    else if (channel != NULL)
    {
        int st;
        i = trigger->fadeTime;
        st = channel->status;
        if (st == 2)
        {
            return;
        }
        if (st == 4 || st == 5)
        {
            channel->status = 5;
            return;
        }
        sndSeqVolume(0, (i < 0x1f4 ? 0x1f4 : i), channel->seqHandle, 1);
        channel->status = 2;
    }
}

void Music_Update(void)
{
    MusicChannel* ch;
    int i = 0;
    int lowPriority = 0x7fff;
    u32 bestActive18 = 0;
    u32 bestLow18 = 0;
    int activeVol = 0x1f4;
    int lowVol = 0x1f4;
    int s2VolA = 0x1f4;
    int s2VolB = 0x1f4;
    int found20 = 0;
    int found19 = 0;
    u32 fadeB = AudioStream_GetMusicFadeFlagB();
    u32 fadeA = AudioStream_GetMusicFadeFlagA();

    gMusicActivePriority = 0x7fff;

    ch = gMusicChannels;
    i = 0xf;
    do {
        int status = ch->status;
        if (status != 0 && status != 4)
        {
            if (seqInstance[ch->voiceId].state == 0)
            {
                if (status == 4 || status == 5)
                {
                    ch->status = 5;
                } else {
                    Music_FreeChannel(ch);
                }
            }
        }
        switch (ch->status)
        {
        case 1:
        case 3:
        case 4:
            if (!Music_IsTriggerExcluded(ch->trigger->id))
            {
                if (ch->priorityGroup != 0)
                {
                    gMusicActivePriority = ch->priority < gMusicActivePriority ? ch->priority : gMusicActivePriority;
                }
                else
                {
                    lowPriority = ch->priority < lowPriority ? ch->priority : lowPriority;
                }
            }
            break;
        case 2:
            ch->fadeTimer += timeDelta / 60.0f;
            if (ch->fadeTimer > 5.0f)
            {
                if (ch->status == 4 || ch->status == 5)
                {
                    ch->status = 5;
                }
                else
                {
                    Music_FreeChannel(ch);
                }
            }
            break;
        }
        ch++;
    } while (i-- != 0);

    ch = gMusicChannels;
    for (i = 0; i < 16; i++)
    {
        switch (ch->status)
        {
        case 1:
        case 3:
        case 4:
            if (!Music_IsTriggerExcluded(ch->trigger->id))
            {
                if (ch->priorityGroup != 0)
                {
                    if (ch->priority == gMusicActivePriority && ch->order > bestActive18)
                    {
                        bestActive18 = ch->order;
                        activeVol = ch->trigger->fadeTime;
                    }
                }
                else
                {
                    if (ch->priority == lowPriority && ch->order > bestLow18)
                    {
                        bestLow18 = ch->order;
                        lowVol = ch->trigger->fadeTime;
                        if (ch->status != 3)
                        {
                            found20 = 1;
                        }
                    }
                }
            }
            break;
        case 2:
            if (ch->priorityGroup != 0)
            {
                s2VolA = s2VolA > ch->trigger->fadeTime
                             ? s2VolA
                             : ch->trigger->fadeTime;
            }
            else
            {
                s2VolB = s2VolB > ch->trigger->fadeTime
                             ? s2VolB
                             : ch->trigger->fadeTime;
                found19 = 1;
            }
            break;
        }
        ch++;
    }

    if (found20)
    {
        activeVol = lowVol;
    }
    if (found19)
    {
        s2VolA = s2VolB;
    }
    if ((int)fadeB != 0)
    {
        activeVol = activeVol < 0x1f4 ? activeVol : 0x1f4;
    }
    if ((int)fadeA != 0)
    {
        lowVol = lowVol < 0x1f4 ? lowVol : 0x1f4;
    }

    ch = gMusicChannels;
    i = 0xf;
    do
    {
        switch (ch->status)
        {
        case 1:
        case 3:
            if (ch->priorityGroup != 0)
            {
                if (ch->priority == gMusicActivePriority && ch->order < bestActive18)
                {
                    if (ch->status != 2)
                    {
                        if (ch->status == 4 || ch->status == 5)
                        {
                            ch->status = 5;
                        }
                        else
                        {
                            sndSeqVolume(
                                0, (activeVol < 0x1f4 ? 0x1f4 : activeVol), ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                }
                else if (ch->priority > gMusicActivePriority || ch->priority > lowPriority || (int)fadeB != 0)
                {
                    if (ch->status != 3)
                    {
                        sndSeqVolume(
                            0, (activeVol < 0x1f4 ? 0x1f4 : activeVol), ch->seqHandle,
                            (ch->priorityGroup != 0 ? 0 : 2));
                        ch->status = 3;
                    }
                }
                else
                {
                    if (ch->status != 1)
                    {
                        sndSeqMute(ch->seqHandle, -1, -1);
                        sndSeqContinue(ch->seqHandle);
                        sndSeqVolume(
                            ch->volume, (s2VolA < 0x1f4 ? 0x1f4 : s2VolA),
                            ch->seqHandle, 0);
                        ch->status = 1;
                    }
                }
            }
            else
            {
                if (ch->priority == lowPriority && ch->order < bestLow18)
                {
                    if (ch->status != 2)
                    {
                        if (ch->status == 4 || ch->status == 5)
                        {
                            ch->status = 5;
                        }
                        else
                        {
                            sndSeqVolume(
                                0, (lowVol < 0x1f4 ? 0x1f4 : lowVol), ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                }
                else if (ch->priority > lowPriority || ch->priority > gMusicActivePriority || (int)fadeA != 0)
                {
                    if (ch->status != 3)
                    {
                        sndSeqVolume(
                            0, (lowVol < 0x1f4 ? 0x1f4 : lowVol), ch->seqHandle,
                            (ch->priorityGroup != 0 ? 0 : 2));
                        ch->status = 3;
                    }
                }
                else
                {
                    if (ch->status != 1)
                    {
                        sndSeqMute(ch->seqHandle, -1, -1);
                        sndSeqContinue(ch->seqHandle);
                        sndSeqVolume(
                            ch->volume, (s2VolB < 0x1f4 ? 0x1f4 : s2VolB),
                            ch->seqHandle, 0);
                        ch->status = 1;
                    }
                }
            }
            break;
        }
        ch++;
    } while (i-- != 0);
}

s32 Music_GetActivePriority(void)
{
    return gMusicActivePriority;
}

u8 musicInitMidiWad(void)
{
    int track;
    MusicChannel* ch;
    MusicTrackSlot* table;
    int j;
    MusicTrackSlot* found;
    u32 size;
    int arenaOffset;
    int saved;
    int i;

    if (!gMidiWadLoadStarted)
    {
        gMidiWadLoadStarted = 1;
        ch = gMusicChannels;
        for (i = 16; i != 0; i--)
        {
            ch->trackId = -1;
            ch->seqHandle = -1;
            ch->bankData = NULL;
            ch->voiceId = 0xff;
            ch->status = 0;
            ch->priority = 0;
            ch->order = 0;
            ch++;
        }
        gMusicChannelCounterA = 1;
        gMusicChannelCounterB = 1;
        gAudioPendingLoadFlags |= AUDIO_LOAD_MIDI_WAD;
        saved = mmSetDelay(0) & 0xff;
        gMidiWadFileData =
            loadFileByPathAsync(sMidiWadPath, &gMidiWadLoadedSize, 0, MIDIWADLoadedCallback);
        mmSetDelay(saved);
    }
    if (gAudioCompletedLoadFlags & AUDIO_LOAD_MIDI_WAD)
    {
        size = gMidiWadLoadedSize;
        if ((int)size & 0x1f)
        {
            size = (size | 0x1f) + 1;
        }
        gMidiWadPayloadStart = (u8*)gMidiWadFileData + 0x1a0;
        track = size - 0x1a0;
        gMidiWadPayloadSize = track;
        gMidiWadArenaSize = 0x1000000 - gMidiWadPayloadSize;
        arenaOffset = gMidiWadArenaSize;
        for (track = 0; track <= 0x63; track++)
        {
            found = NULL;
            for (j = 0, table = (MusicTrackSlot*)sMusicTrackTable; j < 0x64; table++, j++)
            {
                if (track == table->id)
                {
                    found = (MusicTrackSlot*)sMusicTrackTable + j;
                    break;
                }
            }
            if (found != NULL)
            {
                found->offset = arenaOffset;
                found->size = ((int*)gMidiWadFileData)[track];
            }
            {
                u32 size2 = found->size;
                if (size2 & 0x1f)
                {
                    size2 = (size2 | 0x1f) + 1;
                }
                arenaOffset += size2;
            }
        }
        AudioAramWriteSync(gMidiWadPayloadStart, gMidiWadArenaSize, gMidiWadPayloadSize);
        saved = mmSetFreeDelay(0);
        mm_free(gMidiWadFileData);
        mmSetFreeDelay(saved);
        return 1;
    }
    return 0;
}

void Music_LoadChannelForTrigger(MusicTrigger* trigger)
{
    MusicTrackSlot* slot;
    MusicChannel* channel;
    int counter;
    int track;

    if (trigger->priorityGroup)
    {
        if ((int)audioIsChannelUnavailable(2) != 0)
        {
            return;
        }
    }
    if (!(trigger->priorityGroup))
    {
        if ((int)audioIsChannelUnavailable(1) != 0)
        {
            return;
        }
    }
    track = trigger->track;
    slot = Music_FindTrackSlot(track);
    if (slot == NULL)
    {
        return;
    }
    channel = Music_FindFreeChannel();
    if (channel == NULL)
    {
        return;
    }
    channel->trackId = trigger->track;
    channel->volume = trigger->volume;
    channel->priorityGroup = trigger->priorityGroup;
    channel->status = 4;
    channel->priority = trigger->priority;
    if (channel->priorityGroup)
    {
        counter = gMusicChannelCounterA;
        gMusicChannelCounterA = counter + 1;
    }
    else
    {
        counter = gMusicChannelCounterB;
        gMusicChannelCounterB = counter + 1;
    }
    channel->order = counter;
    channel->trigger = trigger;
    channel->fadeTimer = 0.0f;
    AudioAramReadAllocAsync((void*)slot->offset, slot->size, &channel->bankData,
                            Music_ChannelLoadedCallback, slot, channel, trigger);
}

void Music_ChannelLoadedCallback(MusicTrackSlot* slot, MusicChannel* channel, MusicTrigger* trigger)
{
    MusicSeqStartParams params = gMusicSeqStartParamsDefault;

    if (channel != NULL)
    {
        if (channel->status == 5)
        {
            mm_free(channel->bankData);
            channel->trackId = -1;
            channel->seqHandle = -1;
            channel->bankData = NULL;
            channel->voiceId = 0xff;
            channel->status = 0;
            channel->priority = 0;
            channel->fadeTimer = 0.0f;
        }
        else
        {
            int seqHandle;
            u8 voice;
            if (trigger->speed != -1)
            {
                params.speed = trigger->speed;
                params.flags |= 2;
            }
            if (trigger->volume != -1)
            {
                voice = trigger->volume;
            }
            else
            {
                voice = 0x7f;
            }
            params.volume.target = 0;
            params.volume.time = 0;
            params.flags |= 4;
            seqHandle = sndSeqPlayEx(slot->groupId, trigger->track, channel->bankData, &params, 0);
            sndSeqVolume(voice, 0x1f4, seqHandle, 0);
            channel->status = 1;
            channel->seqHandle = seqHandle;
            channel->voiceId = seqGetPrivateId(seqHandle);
        }
    }
}


char sSampleBufferSLoadedCallbackLoadError[] = "sampleBufferSLoadedCallback load error\n";
char sSampleDirectorySLoadedCallbackLoadError[] = "sampleDirectorySLoadedCallback load error\n";
char sProjectDataSLoadedCallbackLoadError[] = "projectDataSLoadedCallback load error\n";
char sPoolDataSLoadedCallbackLoadError[] = "poolDataSLoadedCallback load error\n";
char sSampleBufferMLoadedCallbackLoadError[] = "sampleBufferMLoadedCallback load error\n";
char sSampleDirectoryMLoadedCallbackLoadError[] = "sampleDirectoryMLoadedCallback load error\n";
char sProjectDataMLoadedCallbackLoadError[] = "projectDataMLoadedCallback load error\n";
char sPoolDataMLoadedCallbackLoadError[] = "poolDataMLoadedCallback load error\n";
char sStreamsLoadedCallbackLoadError[] = "streamsLoadedCallback load error\n";
char sSfxTriggersLoadedCallbackLoadError[] = "sfxTriggersLoadedCallback load error\n";
char sMusicTriggersLoadedCallbackLoadError[356] =
    "musicTriggersLoadedCallback load "
    "error\n\0/audio/data/Music.bin\0\0\0/audio/data/Sfx.bin\0/audio/data/Streams.bin\0audioInit: sndIsInstalled() "
    "returned "
    "FALSE!\n\0\0\0\0/audio/starfoxm.poo\0/audio/starfoxm.pro\0/audio/starfoxm.sdi\0/audio/starfoxm.sam\0/audio/"
    "starfoxs.poo\0/audio/starfoxs.pro\0/audio/starfoxs.sdi\0/audio/starfoxs.sam\0sndPushGroup failed on group %d\n";

char sMusicTrackNameAmbIngaeRain[] = "amb_ingae_rain";
char sMusicTrackNameAmbMoonlink[] = "amb_moonlink";
char sMusicTrackNameAndrossTune[] = "Andross tune";
char sMusicTrackNameArwingCrash[] = "Arwing_Crash";
char sMusicTrackNameCCVisit1[] = "CC Visit1";
char sMusicTrackNameDIMCaves[] = "DIM Caves";
char sMusicTrackNameTTHFight[] = "TTH Fight";
char sMusicTrackNameCRFBridge[] = "CRF_Bridge";
char sMusicTrackNameCRFSuspense[] = "CRF_Suspense";
char sMusicTrackNameCRFSwim[] = "CRF_Swim";
char sMusicTrackNameCRFTreasure[] = "CRF_Treasure";
char sMusicTrackNameDarkIceLava[] = "Dark_Ice_Lava";
char sMusicTrackNameKrazoaDocks[] = "Krazoa_Docks";
char sMusicTrackNameKrazoaShrine[] = "Krazoa_Shrine";
char sMusicTrackNameLFVSwamp[] = "LFV_Swamp";
char sMusicTrackNameSlowMotion[] = "Slow_Motion";
char sMusicTrackNameAmbLavapits[] = "amb_lavapits";
char sMusicTrackNameBackOfCloudrunner[] = "back_of_cloudrunner";
char sMusicTrackNameBlizzard[] = "blizzard";
char sMusicTrackNameCapeclawSeaside[] = "capeclaw_seaside";
char sMusicTrackNameCaveTrade[] = "cave_trade";
char sMusicTrackNameCclawCaves[] = "cclaw_caves";
char sMusicTrackNameCclawGasroom[] = "cclaw_gasroom";
char sMusicTrackNameCitytombs[] = "citytombs";
char sMusicTrackNameCldRnrDungeon[] = "cldrnr_dungeon";
char sMusicTrackNameCldRnrTune1[] = "cldrnr_tune1";
char sMusicTrackNameCldRnrWalkabout[] = "cldrnr_walkabout";
char sMusicTrackNameCommunicator[] = "communicator";
char sMusicTrackNameCrunDungeon[] = "crun_dungeon";
char sMusicTrackNameDarkIceBoss1[] = "dark_ice_boss_1";
char sMusicTrackNameDIMCavern[] = "DIM_Cavern";
char sMusicTrackNameDIMMines[] = "DIM_Mines";
char sMusicTrackNameDIMSnow[] = "DIM_Snow";
char sMusicTrackNameDIMCnBlt[] = "DIM_Cn_Blt";
char sMusicTrackNameDownthewell[] = "downthewell";
char sMusicTrackNameEwtChase[] = "ewt_chase";
char sMusicTrackNameEwtLink[] = "ewt_link";
char sMusicTrackNameEwtOutside[] = "ewt_outside";
char sMusicTrackNameGalleonBattle[] = "galleon_battle";
char sMusicTrackNameGalleonDocks[] = "galleon_docks";
char sMusicTrackNameGalleonOutside[] = "galleon_outside";
char sMusicTrackNameGalleonStorm[] = "galleon_storm";
char sMusicTrackNameGreatfoxInt[] = "greatfox_int";
char sMusicTrackNameGuardTheme[] = "guard_theme";
char sMusicTrackNameIceWalkaround[] = "ice_walkaround";
char sMusicTrackNameInsideGalleon[] = "inside_galleon";
char sMusicTrackNameInsideWarlock[] = "inside_warlock";
char sMusicTrackNameKpanomaly[] = "kpanomaly";
char sMusicTrackNameLVFTracking[] = "LVF_Tracking";
char sMusicTrackNameMammothWalk[] = "mammoth_walk";
char sMusicTrackNameMenuPage[] = "menu_page";
char sMusicTrackNameMinecaves[] = "minecaves";
char sMusicTrackNameMmpassalien[] = "mmpassalien";
char sMusicTrackNameMoundMusic[] = "Mound_Music";
char sMusicTrackNameNewIceRace[] = "new_ice_race";
char sMusicTrackNameNewstorm[] = "newstorm";
char sMusicTrackNameNightjungle[] = "nightjungle";
char sMusicTrackNameOptionsPage[] = "options_page";
char sMusicTrackNamePU1Mysterious[] = "PU1_Mysterious";
char sMusicTrackNamePU2Heroic[] = "PU2_Heroic";
char sMusicTrackNamePU3Adventure[] = "PU3_Adventure";
char sMusicTrackNameSeqSwaphol1[] = "seq_swaphol1";
char sMusicTrackNameSforestday[] = "sforestday";
char sMusicTrackNameStarfoxArea6[] = "starfox_area_6";
char sMusicTrackNameStarfoxMap[] = "starfox_map";
char sMusicTrackNameStarfoxRwing1[] = "starfox_rwing_1";
char sMusicTrackNameSwapholNight[] = "swaphol_night";
char sMusicTrackNameSwapstoneCircle[] = "swapstone_circle";
char sMusicTrackNameTeleport[] = "teleport";
char sMusicTrackNameTestOfCombat[] = "test_of_combat";
char sMusicTrackNameTestOfFear[] = "test_of_fear";
char sMusicTrackNameTestOfMagic[] = "test_of_magic";
char sMusicTrackNameTestOfSacrifice[] = "test_of_sacrifice";
char sMusicTrackNameTestOfSkill[] = "test_of_skill";
char sMusicTrackNameTestOfStrength[] = "test_of_strength";
char sMusicTrackNameTrexChase[] = "trex_chase";
char sMusicTrackNameTrexHit[] = "trex_hit";
char sMusicTrackNameTTHNight[] = "TTH_Night";
char sMusicTrackNameUnderwater[] = "underwater";
char sMusicTrackNameVfpWalkabout[] = "vfp_walkabout";
char sMusicTrackNameVolcanoFp[] = "volcano_fp";
char sMusicTrackNameWarlockmagic[] = "warlockmagic";
char sMusicTrackNameWcityDay[] = "wcity_day";
char sMusicTrackNameWindydocks[] = "windydocks";
char sMusicTrackNameLFVStrength[] = "LFV_Strength";
char sMusicTrackNameWLCChase[] = "WLC_Chase";
char sMusicTrackNameWLCCorridors[] = "WLC_Corridors";
char sMusicTrackNameWLCPuzzle[] = "WLC_Puzzle";
char sMusicTrackNameWLCChambers[] = "WLC_Chambers";

MusicTrackSlot sMusicTrackTable[] = {
    {99, 54, 0, sMusicTrackNameAmbIngaeRain, 0, 0},
    {98, 53, 0, sMusicTrackNameAmbMoonlink, 0, 0},
    {72, 0, 0, sMusicTrackNameAndrossTune, 0, 0},
    {38, 0, 0, sMusicTrackNameArwingCrash, 0, 0},
    {53, 0, 0, sMusicTrackNameCCVisit1, 0, 0},
    {54, 0, 0, sMusicTrackNameDIMCaves, 0, 0},
    {55, 0, 0, sMusicTrackNameTTHFight, 0, 0},
    {42, 0, 0, sMusicTrackNameCRFBridge, 0, 0},
    {41, 0, 0, sMusicTrackNameCRFSuspense, 0, 0},
    {43, 0, 0, sMusicTrackNameCRFSwim, 0, 0},
    {45, 0, 0, sMusicTrackNameCRFTreasure, 0, 0},
    {37, 0, 0, sMusicTrackNameDarkIceLava, 0, 0},
    {39, 0, 0, sMusicTrackNameKrazoaDocks, 0, 0},
    {40, 0, 0, sMusicTrackNameKrazoaShrine, 0, 0},
    {44, 0, 0, sMusicTrackNameLFVSwamp, 0, 0},
    {46, 0, 0, sMusicTrackNameSlowMotion, 0, 0},
    {91, 42, 0, sMusicTrackNameAmbLavapits, 0, 0},
    {13, 0, 0, sMusicTrackNameBackOfCloudrunner, 0, 0},
    {81, 25, 0, sMusicTrackNameBarren, 0, 0},
    {65, 0, 0, sMusicTrackNameBarrels, 0, 0},
    {74, 18, 0, sMusicTrackNameBlizzard, 0, 0},
    {71, 0, 0, sMusicTrackNameBloop, 0, 0},
    {92, 43, 0, sMusicTrackNameCapeclawSeaside, 0, 0},
    {34, 0, 0, sMusicTrackNameCaveTrade, 0, 0},
    {96, 50, 0, sMusicTrackNameCclawCaves, 0, 0},
    {97, 51, 0, sMusicTrackNameCclawGasroom, 0, 0},
    {79, 23, 0, sMusicTrackNameCitytombs, 0, 0},
    {16, 0, 0, sMusicTrackNameCldRnrDungeon, 0, 0},
    {15, 0, 0, sMusicTrackNameCldRnrTune1, 0, 0},
    {14, 0, 0, sMusicTrackNameCldRnrWalkabout, 0, 0},
    {22, 0, 0, sMusicTrackNameCommunicator, 0, 0},
    {87, 31, 0, sMusicTrackNameCrunDungeon, 0, 0},
    {26, 0, 0, sMusicTrackNameDarkIceBoss1, 0, 0},
    {59, 0, 0, sMusicTrackNameDIMCavern, 0, 0},
    {69, 0, 0, sMusicTrackNameDIMDay, 0, 0},
    {64, 0, 0, sMusicTrackNameDIMMines, 0, 0},
    {52, 0, 0, sMusicTrackNameDIMSnow, 0, 0},
    {60, 0, 0, sMusicTrackNameDIMCnBlt, 0, 0},
    {85, 29, 0, sMusicTrackNameDownthewell, 0, 0},
    {25, 0, 0, sMusicTrackNameDrako1, 0, 0},
    {24, 0, 0, sMusicTrackNameDrako2, 0, 0},
    {23, 0, 0, sMusicTrackNameDrako3, 0, 0},
    {3, 0, 0, sMusicTrackNameEwtChase, 0, 0},
    {10, 0, 0, sMusicTrackNameEwtLink, 0, 0},
    {28, 0, 0, sMusicTrackNameEwtOutside, 0, 0},
    {33, 0, 0, sMusicTrackNameGalleonBattle, 0, 0},
    {11, 0, 0, sMusicTrackNameGalleonDocks, 0, 0},
    {94, 45, 0, sMusicTrackNameGalleonOutside, 0, 0},
    {89, 39, 0, sMusicTrackNameGalleonStorm, 0, 0},
    {95, 49, 0, sMusicTrackNameGreatfoxInt, 0, 0},
    {20, 0, 0, sMusicTrackNameGuardTheme, 0, 0},
    {17, 0, 0, sMusicTrackNameIceWalkaround, 0, 0},
    {93, 44, 0, sMusicTrackNameInsideGalleon, 0, 0},
    {12, 0, 0, sMusicTrackNameInsideWarlock, 0, 0},
    {73, 0, 0, sMusicTrackNameKpanomaly, 0, 0},
    {67, 0, 0, sMusicTrackNameKptext, 0, 0},
    {68, 0, 0, sMusicTrackNameKpwin, 0, 0},
    {56, 0, 0, sMusicTrackNameLVFTracking, 0, 0},
    {18, 0, 0, sMusicTrackNameMammothWalk, 0, 0},
    {19, 0, 0, sMusicTrackNameMenuPage, 0, 0},
    {75, 19, 0, sMusicTrackNameMinecaves, 0, 0},
    {80, 24, 0, sMusicTrackNameMmpassalien, 0, 0},
    {57, 0, 0, sMusicTrackNameMoundMusic, 0, 0},
    {36, 0, 0, sMusicTrackNameNewIceRace, 0, 0},
    {77, 21, 0, sMusicTrackNameNewstorm, 0, 0},
    {76, 20, 0, sMusicTrackNameNightjungle, 0, 0},
    {29, 0, 0, sMusicTrackNameOptionsPage, 0, 0},
    {61, 0, 0, sMusicTrackNamePU1Mysterious, 0, 0},
    {62, 0, 0, sMusicTrackNamePU2Heroic, 0, 0},
    {63, 0, 0, sMusicTrackNamePU3Adventure, 0, 0},
    {88, 32, 0, sMusicTrackNameSeqSwaphol1, 0, 0},
    {84, 28, 0, sMusicTrackNameSforestday, 0, 0},
    {66, 0, 0, sMusicTrackNameSlope, 0, 0},
    {2, 0, 0, sMusicTrackNameStarfoxArea6, 0, 0},
    {0, 0, 0, sMusicTrackNameStarfoxMap, 0, 0},
    {1, 0, 0, sMusicTrackNameStarfoxRwing1, 0, 0},
    {90, 40, 0, sMusicTrackNameSwapholNight, 0, 0},
    {21, 0, 0, sMusicTrackNameSwapstoneCircle, 0, 0},
    {70, 0, 0, sMusicTrackNameTeleport, 0, 0},
    {4, 0, 0, sMusicTrackNameTestOfCombat, 0, 0},
    {5, 0, 0, sMusicTrackNameTestOfFear, 0, 0},
    {6, 0, 0, sMusicTrackNameTestOfMagic, 0, 0},
    {7, 0, 0, sMusicTrackNameTestOfSacrifice, 0, 0},
    {8, 0, 0, sMusicTrackNameTestOfSkill, 0, 0},
    {9, 0, 0, sMusicTrackNameTestOfStrength, 0, 0},
    {30, 0, 0, sMusicTrackNameTrex2a, 0, 0},
    {32, 0, 0, sMusicTrackNameTrexChase, 0, 0},
    {31, 0, 0, sMusicTrackNameTrexHit, 0, 0},
    {58, 0, 0, sMusicTrackNameTTHNight, 0, 0},
    {86, 30, 0, sMusicTrackNameUnderwater, 0, 0},
    {27, 0, 0, sMusicTrackNameVfpWalkabout, 0, 0},
    {35, 0, 0, sMusicTrackNameVolcanoFp, 0, 0},
    {78, 22, 0, sMusicTrackNameWarlockmagic, 0, 0},
    {82, 26, 0, sMusicTrackNameWcityDay, 0, 0},
    {83, 27, 0, sMusicTrackNameWindydocks, 0, 0},
    {47, 0, 0, sMusicTrackNameLFVStrength, 0, 0},
    {48, 0, 0, sMusicTrackNameWLCChase, 0, 0},
    {49, 0, 0, sMusicTrackNameWLCCorridors, 0, 0},
    {50, 0, 0, sMusicTrackNameWLCPuzzle, 0, 0},
    {51, 0, 0, sMusicTrackNameWLCChambers, 0, 0},
};

char sMidiWadLoadedCallbackLoadError[] = "MIDIWADLoadedCallback load error\n";
char sMidiWadPath[] = "audio/midi.wad";

MusicChannel gMusicChannels[0x240 / sizeof(MusicChannel)];
u32 gAudioAramBlock[0x2C / sizeof(u32)];
