#include "global.h"
#include "main/audio/synth_voice.h"
#include "main/audio/synth_job_queue.h"
#include "main/audio/synth_config.h"
#include "main/audio/mcmd.h"
#include "main/dll/synthfade_struct.h"
#include "util/carry.h"
#include "main/audio/synth_channel.h"
#include "main/audio/hw_samplemem.h"
#include "main/audio/voice_id.h"
#include "main/audio/synth_queue.h"
#include "main/audio/hw_init.h"
#include "main/audio/hw_voice_params.h"
#include "main/audio/hw_voice_start.h"
#include "main/audio/data_tables.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/vid_init.h"

#pragma exceptions on

struct SynthDelayedNode
{
    struct SynthDelayedNode* next;
    struct SynthDelayedNode* prev;
    u8 voiceIndex;
    u8 bucketIndex;
    u8 pad[2];
};

typedef void (*SynthDelayedBucketCallback)(int voiceIndex);

/*
 * Overlay for the 64-bit update-time stamps that live past the embedded
 * SynthDelayedNode header inside a voice handle (fn_802712C8 writes these
 * back-to-back as two hi/lo pairs).
 */
typedef struct SynthVoiceTimers
{
    u8 pad00[0x24];
    int updateTimeHi0;
    int updateTimeLo0;
    int updateTimeHi1;
    int updateTimeLo1;
} SynthVoiceTimers;

typedef struct SynthTables
{
    u32 ticksPerSecond[9][16];
    SynthJobTab jobs[32];
} SynthTables;

STATIC_ASSERT(offsetof(SynthVoiceTimers, updateTimeHi0) == 0x24);
STATIC_ASSERT(offsetof(SynthVoiceTimers, updateTimeLo0) == 0x28);
STATIC_ASSERT(offsetof(SynthVoiceTimers, updateTimeHi1) == 0x2c);
STATIC_ASSERT(offsetof(SynthVoiceTimers, updateTimeLo1) == 0x30);

#define SYNTH_FADE_COUNT                     0x20
#define SYNTH_FADE_TABLE_OFFSET              0x5d4
#define SYNTH_FADE_DELAY_ACTION_FREE_HANDLE  1
#define SYNTH_FADE_DELAY_ACTION_QUEUE_HANDLE 2
#define SYNTH_FADE_DELAY_ACTION_CLEAR_MIX    3
#define SYNTH_FADE_ACTION_DISABLED           4
#define SYNTH_INVALID_LINK_ID                0xffffffff
#define SYNTH_VOICE_SLOT_SIZE                0x404
#define SYNTH_VOICE_STRIDE                   0x404
#define SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET   0x11c

extern u8 gSynthDelayBucketCursor;
extern u8 gSynthInitialized;

extern void macHandle(u32 delta);
extern void voiceRegister(McmdVoiceState* state);
extern void voiceKill(u32 voice);
extern void voiceInitPriorityTables(void);
extern void voiceInitRegistrationTables(void);
extern void inpSetMidiLastNote(u8 channel, u8 set, u8 note);

extern u32 synthMasterFaderPauseActiveFlags;
extern u32 synthMasterFaderActiveFlags;
extern u8 synthAuxBMIDISet[8];
extern u8 synthAuxBMIDI[8];
extern u8 synthAuxAMIDISet[8];
extern u8 synthAuxAMIDI[8];
extern u64 synthRealTime;

typedef struct SynthAuxInfo
{
    union
    {
        struct
        {
            s32* left;
            s32* right;
            s32* surround;
        } bufferUpdate;
        struct
        {
            u16 para[4];
        } parameterUpdate;
    } data;
} SynthAuxInfo;

typedef void (*SynthAuxCallback)(u8 reason, SynthAuxInfo* info, void* user);

extern u16 inpGetVolume(McmdVoiceState* state);
extern u16 inpGetPanning(McmdVoiceState* state);
extern int inpGetSurPanning(McmdVoiceState* state);
extern u16 inpGetPitchBend(McmdVoiceState* state);
extern int inpGetMidiCtrl(u8 controller, u8 slot, u8 key);
extern u16 inpGetDoppler(McmdVoiceState* state);
extern u16 inpGetModulation(McmdVoiceState* state);
extern u16 inpGetPedal(McmdVoiceState* state);
extern u16 inpGetPreAuxA(McmdVoiceState* state);
extern u16 inpGetReverb(McmdVoiceState* state);
extern u16 inpGetPreAuxB(McmdVoiceState* state);
extern u16 inpGetPostAuxB(McmdVoiceState* state);
extern u16 inpGetTremolo(McmdVoiceState* state);
extern u16 inpGetAuxA(u8 studio, u8 channel, u8 auxIndex, u8 handleIndex);
extern u16 inpGetAuxB(u8 studio, u8 channel, u8 auxIndex, u8 handleIndex);
extern s16 sndSin(u32 packed);

extern u32 audioFn_8026f630(u8 key, u8 midi, u8 midiSet, u32 vidFlag, u32* rejected);
extern u32 audioLayerFn_8026f8b8(u16 id, s16 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 pan, u8 midi,
                                 u8 midiSet, u8 section, u16 step, u16 trackid, u32 vidFlag, u8 vGroup, u8 studio,
                                 u32 itd);
extern u32 macStart(u16 id, u8 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 pan, u8 midi, u8 midiSet,
                    u8 section, u16 step, u16 trackid, u8 vidFlag, u8 vGroup, u8 studio, u32 itd);

typedef struct SynthVoiceLfo
{
    s32 time;
    u32 period;
    s16 value;
    s16 lastValue;
} SynthVoiceLfo;

typedef struct SynthVoiceAdsr
{
    u8 unk00[8];
    s32 currentVolume;
    u8 unk0C[0x28 - 0x0C];
} SynthVoiceAdsr;

/* Hardware synth voice state (MusyX SYNTH_VOICE), one 0x404-byte slot per voice. */
typedef struct SynthHwVoice
{
    u8 unk000[0x24];
    u32 lastLowCallTimeHi;  /* 0x024 */
    u32 lastLowCallTimeLo;  /* 0x028 */
    u32 lastZeroCallTimeHi; /* 0x02C */
    u32 lastZeroCallTimeLo; /* 0x030 */
    u8* addr;               /* 0x034 */
    u8 unk038[0xA8 - 0x38];
    u8 timeUsedByInput; /* 0x0A8 */
    u8 unk0A9[0xEC - 0xA9];
    u32 child; /* 0x0EC */
    u8 unk0F0[0x10C - 0xF0];
    u8 prio; /* 0x10C */
    u8 unk10D;
    u16 ageSpeed;      /* 0x10E */
    u32 age;           /* 0x110 */
    u32 cFlagsHi;      /* 0x114 */
    u32 cFlagsLo;      /* 0x118 */
    u8 callbackActive; /* 0x11C */
    u8 fxFlag;         /* 0x11D */
    u8 vGroup;         /* 0x11E */
    u8 studio;         /* 0x11F */
    u8 track;          /* 0x120 */
    u8 midi;           /* 0x121 */
    u8 midiSet;        /* 0x122 */
    u8 unk123;
    u32 sInfo; /* 0x124 */
    u8 unk128[4];
    u16 curNote;  /* 0x12C */
    s8 curDetune; /* 0x12E */
    u8 unk12F;
    u8 lastNote;           /* 0x130 */
    u8 portType;           /* 0x131 */
    u16 portLastCtrlState; /* 0x132 */
    u32 portDuration;      /* 0x134 */
    u32 portCurPitch;      /* 0x138 */
    u32 portTime;          /* 0x13C */
    u8 vibKeyRange;        /* 0x140 */
    u8 vibCentRange;       /* 0x141 */
    u8 unk142[2];
    u32 vibPeriod;      /* 0x144 */
    u32 vibCurTime;     /* 0x148 */
    s32 vibCurOffset;   /* 0x14C */
    s16 vibModAddScale; /* 0x150 */
    u8 unk152[2];
    u32 volume; /* 0x154 */
    u8 unk158[4];
    f32 lastVolFaderScale; /* 0x15C */
    u32 lastPan;           /* 0x160 */
    u32 lastSPan;          /* 0x164 */
    f32 treCurScale;       /* 0x168 */
    u16 treScale;          /* 0x16C */
    u16 treModAddScale;    /* 0x16E */
    u32 panning[2];        /* 0x170 */
    u32 panDelta[2];       /* 0x178 */
    u32 panTarget[2];      /* 0x180 */
    u32 panTime[2];        /* 0x188 */
    u8 revVolScale;        /* 0x190 */
    u8 revVolOffset;       /* 0x191 */
    u8 volTable;           /* 0x192 */
    u8 unk193;
    s32 envDelta;    /* 0x194 */
    s32 envTarget;   /* 0x198 */
    s32 envCurrent;  /* 0x19C */
    s32 sweepOff[2]; /* 0x1A0 */
    s32 sweepAdd[2]; /* 0x1A8 */
    s32 sweepCnt[2]; /* 0x1B0 */
    u8 sweepNum[2];  /* 0x1B8 */
    u8 unk1BA[2];
    SynthVoiceLfo lfo[2]; /* 0x1BC */
    u8 lfoUsedByInput[2]; /* 0x1D4 */
    u8 pbLowerKeyRange;   /* 0x1D6 */
    u8 pbUpperKeyRange;   /* 0x1D7 */
    u16 pbLast;           /* 0x1D8 */
    u8 unk1DA[2];
    SynthVoiceAdsr pitchADSR; /* 0x1DC */
    s16 pitchADSRRange;       /* 0x204 */
    u16 curPitch;             /* 0x206 */
    u8 unk208[0x214 - 0x208];
    u32 midiDirtyFlags; /* 0x214 */
    u8 unk218[0x400 - 0x218];
    u16 curOutputVolume; /* 0x400 */
    u8 unk402[2];
} SynthHwVoice;

#define HWVOICE(i)        ((SynthHwVoice*)((u8*)synthVoice + (i) * 0x404))
#define HWVOICE_FLAGS(sv) (*(u64*)&(sv)->cFlagsHi)

typedef struct SynthMasterFader
{
    f32 volume;
    f32 target;
    f32 start;
    f32 time;
    f32 deltaTime;
    f32 pauseVol;
    f32 pauseTarget;
    f32 pauseStart;
    f32 pauseTime;
    f32 pauseDeltaTime;
    u32 handle;
    u8 delayAction;
    u8 type;
    u8 pad[2];
} SynthMasterFader;

typedef struct SynthState
{
    u32 ticksPerSecond[9][16];
    SynthJobTab jobTable[32];
    SynthInfo info;
    SynthMasterFader masterFader[32];
    u8 trackVolume[64];
    void* auxAUser[8];
    SynthAuxCallback auxACallback[8];
    void* auxBUser[8];
    SynthAuxCallback auxBCallback[8];
    u8 itdDefault[8][2];
    s32 globalVariable[16];
    u8 auxBInput[0x480];
    u8 auxAInput[0x480];
} SynthState;

STATIC_ASSERT(offsetof(SynthState, info) == 0x3c0);
STATIC_ASSERT(offsetof(SynthState, masterFader) == 0x5d4);
STATIC_ASSERT(offsetof(SynthState, trackVolume) == 0xbd4);
STATIC_ASSERT(offsetof(SynthState, auxAUser) == 0xc14);
STATIC_ASSERT(offsetof(SynthState, auxACallback) == 0xc34);
STATIC_ASSERT(offsetof(SynthState, auxBUser) == 0xc54);
STATIC_ASSERT(offsetof(SynthState, auxBCallback) == 0xc74);

static u32 synthTicksPerSecond[9][16];
static SynthJobTab synthJobTable[32];
u8 inpAuxA[0x480];
u8 inpAuxB[0x480];
s32 synthGlobalVariable[16];
u8 synthITDDefault[8][2];
SynthAuxCallback synthAuxBCallback[8];
void* synthAuxBUser[8];
SynthAuxCallback synthAuxACallback[8];
void* synthAuxAUser[8];
u8 synthTrackVolume[64];
SynthFade synthMasterFader[32];
SynthInfo synthInfo;

extern u32 voiceGetPitchRatio(u8 note, u32 sInfo);
extern u16 voiceScaleSampleRate(u32 rate);

extern void hwSetVolume(u32 voice, u8 table, f32 vol, u32 pan, u32 span, f32 auxa, f32 auxb);

extern void hwKeyOff(u32 voice);
extern void macSetPedalState(SynthHwVoice* sv, u32 state);
extern u32 adsrHandleLowPrecision(SynthVoiceAdsr* adsr, u16* start, u16* delta);
extern u32 adsrRelease(SynthVoiceAdsr* adsr);
extern u32 synthFlags;

typedef struct LAYER
{
    u16 id;
    u8 keyLow;
    u8 keyHigh;
    s8 transpose;
    u8 volume;
    s16 prioOffset;
    u8 panning;
    u8 reserved[3];
} LAYER;

u32 StartKeymap(u16 id, s16 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 pan, u8 midi, u8 midiSet,
                u8 section, u16 step, u16 trackid, u32 vidFlag, u8 vGroup, u8 studio, u32 itd);

/*
 * Set one studio/channel scale entry.
 */
void synthSetStudioChannelScale(int value, u8 bank, u8 key)
{
    if (bank == 0xff)
    {
        bank = 8;
    }
    synthTicksPerSecond[bank][key] = (u32)((value << 3) * 0x600) / 0xf0;
}

/*
 * Look up an int from a 2D table indexed by state's ID bytes.
 */
int synthGetVoiceSlotChannelScale(McmdVoiceState* state)
{
    McmdVoiceState* v = state;
    u32 bank;
    int key;
    if ((bank = v->midiEvent) == 0xff)
        bank = 8;
    key = v->midiLayer;
    return synthTicksPerSecond[bank][key];
}

/*
 * Flag-check and conditional store.
 */
void fn_8026F5B8(int state)
{
    McmdVoiceState* v = (McmdVoiceState*)state;
    u64 flags;

    flags = *(u64*)&v->inputFlags;
    if ((flags & 0x20000) != 0)
    {
        return;
    }
    if (v->portamentoMode == 1)
    {
        if ((flags & 0x1000) == 0)
        {
            v->portamentoTime = 0;
        }
        else
        {
            v->portamentoTime = v->portamentoDuration;
        }
    }
    else
    {
        v->portamentoTime = v->portamentoDuration;
    }
    v->portamentoCurPitch = v->registeredKey << 0x10;
}

/*
 * Reuse an active voice matching the requested MIDI slot/channel.
 */
u32 audioFn_8026f630(u8 key, u8 slot, u8 channel, u32 voiceGroup, u32* outFlags)
{
    u32 i;
    u32 result;
    u32 previousId;
    McmdVoiceState* voice;
    McmdVoiceState* selectedVoice;
    u32 sawHeldVoice;

    sawHeldVoice = 0;
    result = -1;
    for (i = 0, voice = (McmdVoiceState*)synthVoice; i < SYNTH_CONFIGURATION->voiceCount; ++i, ++voice)
    {
        if (voice->macroAllocating == 0 && voice->voiceHandle != 0xffffffff && voice->midiSlot == slot &&
            voice->midiEvent == channel)
        {
            if ((*(u64*)&voice->inputFlags & 2) != 0)
            {
                sawHeldVoice = 1;
            }
            if ((*(u64*)&voice->inputFlags & 0x10) != 0 && (*(u64*)&voice->inputFlags & 0x10000000008) != 8 &&
                hwIsActive(i) != 0)
            {
                if (result == 0xffffffff && (*(u64*)&voice->inputFlags & 0x20002) == 0x20002)
                {
                    *outFlags = 1;
                    return -1;
                }

                selectedVoice = voice;
                voice->portamentoCurPitch = ((u32)voice->key << 16) + ((s32)voice->fineTune << 16) / 100;
                voice->registeredKey = voice->key;
                voice->key = key + ((voice->key & 0xff) - voice->keyBase);
                voice->keyBase = key;
                voice->fineTune = 0;
                voice->portamentoTime = 0;
                voice->outputFlags = voice->outputFlags | 0x20000LL;
                vidRemoveVoice(&synthVoice[i]);
                if (result == 0xffffffff)
                {
                    voice->voiceNextHandle = 0xffffffff;
                    voice->voicePrevHandle = 0xffffffff;
                    result = vidMakeNew(&synthVoice[i], voiceGroup);
                    previousId = voice->voiceHandle;
                }
                else
                {
                    ((McmdVoiceState*)synthVoice)[previousId & 0xff].voiceNextHandle = voice->voiceHandle;
                    voice->voicePrevHandle = previousId;
                    previousId = voice->voiceHandle;
                    vidMakeNew(&synthVoice[i], 0);
                }
            }
        }
    }

    if (result != 0xffffffff)
    {
        voiceRegister(selectedVoice);
        inpSetMidiLastNote(selectedVoice->midiSlot, selectedVoice->midiEvent, selectedVoice->key & 0xff);
        *outFlags = 0;
    }
    else
    {
        *outFlags = sawHeldVoice;
    }
    return result;
}

u32 audioLayerFn_8026f8b8(u16 layerID, s16 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 panning, u8 midi,
                          u8 midiSet, u8 section, u16 step, u16 trackid, u32 vidFlag, u8 vGroup, u8 studio, u32 itd)
{
    u16 count;
    u32 vid;
    u32 new_id;
    u32 id;
    LAYER* l;
    s32 pan;
    s32 note;
    u8 scaledVol;
    u8 mKey;

    vid = 0xFFFFFFFF;
    if ((l = dataGetLayer(layerID, &count)) == NULL)
    {
        goto end;
    }

    mKey = key & 0x7f;
    for (; count != 0; --count, l++)
    {
        if (l->id == 0xffff || l->keyLow > mKey || l->keyHigh < mKey)
        {
            continue;
        }

        note = mKey + l->transpose;
        note = note > 127 ? 127 : note < 0 ? 0 : note;

        if ((l->id & 0xC000) == 0)
        {
            u32 rejected;
            u32 ok;
            if ((u16)inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, midi, midiSet) > 8064)
            {
                new_id = audioFn_8026f630(note & 0x7f, midi, midiSet, 0, &rejected);
                ok = !rejected;
            }
            else
            {
                new_id = 0xFFFFFFFF;
                ok = 1;
            }
            if (!ok)
            {
                continue;
            }
            if (new_id != 0xFFFFFFFF)
            {
                goto apply_new_id;
            }
        }

        if ((l->panning & 0x80) == 0)
        {
            pan = l->panning - 0x40;
            pan += panning;
            pan = pan < 0 ? 0 : pan > 0x7f ? 0x7f : pan;
        }
        else
        {
            pan = 0x80;
        }

        scaledVol = (vol * l->volume) / 0x7f;
        prio += l->prioOffset;
        prio = prio > 0xff ? 0xff : prio < 0 ? 0 : prio;

        switch (l->id & 0xC000)
        {
        case 0:
            new_id = macStart(l->id, prio, maxVoices, allocId, note | (key & 0x80), scaledVol, pan, midi, midiSet,
                              section, step, trackid, 0, vGroup, studio, itd);
            break;
        case 0x4000:
            new_id = StartKeymap(l->id, prio, maxVoices, allocId, note | (key & 0x80), scaledVol, pan, midi, midiSet,
                                 section, step, trackid, 0, vGroup, studio, itd);
            break;
        case 0x8000:
            new_id = audioLayerFn_8026f8b8(l->id, prio, maxVoices, allocId, note | (key & 0x80), scaledVol, pan, midi,
                                           midiSet, section, step, trackid, 0, vGroup, studio, itd);
            break;
        }

        if (new_id != 0xFFFFFFFF)
        {
        apply_new_id:
            if (vid == 0xFFFFFFFF)
            {
                if (vidFlag != 0)
                {
                    vid = vidMakeRoot(&synthVoice[new_id & 0xff]);
                }
                else
                {
                    vid = new_id;
                }
            }
            else
            {
                synthVoice[id & 0xff].child = new_id;
                synthVoice[new_id & 0xff].parent = id;
            }
            id = new_id;
            while (synthVoice[id & 0xff].child != 0xFFFFFFFF)
            {
                synthVoice[id & 0xff].block = 1;
                id = synthVoice[id & 0xff].child;
            }
            synthVoice[id & 0xff].block = 1;
        }
    }

end:
    return vid;
}


typedef struct KeymapEntry
{
    u16 id;         /* 0x0 */
    s8 transpose;   /* 0x2 */
    u8 panning;     /* 0x3 */
    s16 prioOffset; /* 0x4 */
    u8 reserved[2]; /* 0x6 */
} KeymapEntry;      /* size 0x8, MP4 musyx/synthdata.h KEYMAP */

static inline u32 check_portamento(u8 key, u8 midi, u8 midiSet, u32 newVID, u32* vid)
{
    u32 rejected;

    if ((u16)inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, midi, midiSet) > 0x1F80)
    {
        *vid = audioFn_8026f630(key & 0x7F, midi, midiSet, newVID, &rejected);
        return !rejected;
    }
    *vid = 0xFFFFFFFF;
    return 1;
}

/*
 * Resolve an indirection-table sample entry, then dispatch the resolved
 * sample or nested sample group.
 */
u32 StartKeymap(u16 id, s16 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 pan, u8 midi, u8 midiSet, u8 section,
                u16 step, u16 trackid, u32 vidFlag, u8 vGroup, u8 studio, u32 itd)
{
    u8 o;
    KeymapEntry* keymap;
    s32 p;
    s32 k;
    u32 handle;

    if ((keymap = (KeymapEntry*)dataGetKeymap(id)) != 0)
    {
        o = key & 0x7F;
        if (keymap[o].id != 0xFFFF)
        {
            if ((keymap[o].id & 0xC000) != 0x4000)
            {
                if ((keymap[o].panning & 0x80) == 0)
                {
                    p = keymap[key].panning - 0x40;
                    p += pan;
                    if (p < 0)
                    {
                        pan = 0;
                    }
                    else if (p > 0x7F)
                    {
                        pan = 0x7F;
                    }
                    else
                    {
                        pan = p;
                    }
                }
                else
                {
                    pan = 0x80;
                }

                k = (key & 0x7F) + keymap[o].transpose;
                k = k > 0x7F ? 0x7F : k < 0 ? 0 : k;

                prio += keymap[o].prioOffset;
                prio = prio > 0xFF ? 0xFF : prio < 0 ? 0 : prio;

                if ((keymap[o].id & 0xC000) == 0)
                {
                    if (!check_portamento(k & 0xFF, midi, midiSet, vidFlag, &handle))
                    {
                        return -1;
                    }
                    if (handle != 0xFFFFFFFF)
                    {
                        return handle;
                    }
                    return macStart(keymap[o].id, prio, maxVoices, allocId, k | (key & 0x80),
                                    vol, pan, midi, midiSet, section, step, trackid, vidFlag, vGroup, studio, itd);
                }
                return audioLayerFn_8026f8b8(keymap[o].id, prio, maxVoices, allocId, k | (key & 0x80), vol, pan, midi,
                                             midiSet, section, step, trackid,
                                             vidFlag & 0xff, vGroup, studio, itd);
            }
        }
    }
    return -1;
}

/*
 * Start a sample/FX id, handling direct samples, table-expanded sample
 * groups, and already-linked voice chains.
 */
static inline void unblockAllAllocatedVoices(u32 vid)
{
    u32 vi;

    vi = vidGetInternalId(vid);
    while (vi != 0xFFFFFFFF)
    {
        HWVOICE(vi & 0xFF)->callbackActive = 0;
        vi = HWVOICE(vi & 0xFF)->child;
    }
}

u32 synthStartSound(u16 id, u8 prio, u8 maxVoices, u8 key, u8 vol, u8 pan, u8 midi, u8 midiSet, u8 section, u16 step,
                    u16 trackid, u8 vGroup, s16 prioOffset, u8 studio, u32 itd)
{
    prio += prioOffset;
    prio = prio > 0xFF ? 0xFF : prio;

    switch (id & 0xC000)
    {
    case 0:
    {
        u32 handle;
        if (!check_portamento(key, midi, midiSet, 1, &handle))
        {
            return -1;
        }
        if (handle != 0xFFFFFFFF)
        {
            return handle;
        }
        return macStart(id, prio, maxVoices, id, key, vol, pan, midi, midiSet, section, step, trackid, 1, vGroup, studio,
                        itd);
    }
    case 0x4000:
    {
        u32 vid = StartKeymap(id, prio, maxVoices, id, key, vol, pan, midi, midiSet, section, step, trackid, 1, vGroup,
                              studio, itd);
        if (vid != 0xFFFFFFFF)
        {
            unblockAllAllocatedVoices(vid);
        }
        return vid;
    }
    case 0x8000:
    {
        u32 vid = audioLayerFn_8026f8b8(id, prio, maxVoices, id, key, vol, pan, midi, midiSet, section, step, trackid,
                                        1, vGroup, studio, itd);
        if (vid != 0xFFFFFFFF)
        {
            unblockAllAllocatedVoices(vid);
        }
        return vid;
    }
    }
    return -1;
}

/*
 * Low-precision per-voice update: LFOs, vibrato, pitch sweeps, pan ramps,
 * pitch bend/portamento and final pitch computation.
 */
static inline u32 apply_portamento(SynthHwVoice* svoice, u32 ccents, u32 deltaTime)
{
    u32 old_portCurPitch;

    if ((HWVOICE_FLAGS(svoice) & 0x400) != 0 && (s32)((svoice->portDuration - svoice->portTime) >> 8) > 0)
    {
        old_portCurPitch = svoice->portCurPitch;
        svoice->portCurPitch += (s32)deltaTime * ((s32)(ccents - svoice->portCurPitch) >> 8) /
                                (s32)((svoice->portDuration - svoice->portTime) >> 8);
        if ((old_portCurPitch < ccents && svoice->portCurPitch < ccents) ||
            (old_portCurPitch > ccents && svoice->portCurPitch > ccents))
        {
            ccents = svoice->portCurPitch;
            svoice->portTime += deltaTime;
        }
        else
        {
            svoice->portTime = svoice->portDuration;
        }
    }
    return ccents;
}

static inline u32 convert_cents(SynthHwVoice* svoice, u32 ccents)
{
    u32 curDetune;
    u32 cpitch;

    cpitch = voiceGetPitchRatio(ccents >> 16, svoice->sInfo) << 16;
    if ((curDetune = ccents & 0xFFFF) != 0)
    {
        cpitch += curDetune * (voiceScaleSampleRate(cpitch >> 16) - (cpitch >> 16));
    }
    return cpitch;
}

static inline void UpdateTimeMIDICtrl(SynthHwVoice* sv)
{
    if (sv->timeUsedByInput != 0)
    {
        sv->timeUsedByInput = 0;
        sv->midiDirtyFlags = 0x1FFF;
    }
}

void LowPrecisionHandler(int voice)
{
    u32 j;
    s32 pbend;
    u32 ccents;
    u32 cpitch;
    u16 Modulation;
    s32 portamentoRaw;
    u32 lowDeltaTime;
    SynthHwVoice* sv;
    u32 cntDelta;
    u32 addFactor;
    u16 adsr_start;
    u16 adsr_delta;
    s32 vrange;
    s32 voff;
    sv = HWVOICE(voice);
    if (!hwIsActive(voice) && sv->addr == 0)
    {
        goto end;
    }

    lowDeltaTime = (u32)(synthRealTime - *(u64*)&sv->lastLowCallTimeHi);
    *(u64*)&sv->lastLowCallTimeHi = synthRealTime;

    for (j = 0; j < 2; ++j)
    {
        if (sv->lfo[j].period == 0)
        {
            continue;
        }
        sv->lfo[j].time += lowDeltaTime;
        sv->lfo[j].value = sndSin((u16)((sv->lfo[j].time % sv->lfo[j].period * 16) / (sv->lfo[j].period / 256)));
        if (sv->lfo[j].value != sv->lfo[j].lastValue)
        {
            sv->lfo[j].lastValue = sv->lfo[j].value;
            if (sv->lfoUsedByInput[j])
            {
                sv->lfoUsedByInput[j] = 0;
                sv->midiDirtyFlags |= 0x1FFF;
            }
        }
    }

    if ((HWVOICE_FLAGS(sv) & 0x2000) != 0)
    {
        sv->vibCurTime += lowDeltaTime;
        sv->vibCurOffset = sndSin((u16)((sv->vibCurTime % sv->vibPeriod * 16) / (sv->vibPeriod / 256)));
    }

    if (sv->sweepNum[0] | sv->sweepNum[1])
    {
        cntDelta = (lowDeltaTime << 8) >> 4;
        addFactor = (lowDeltaTime << 4) >> 4;
        for (j = 0; j < 2; ++j)
        {
            if (sv->sweepNum[j] == 0)
            {
                continue;
            }
            sv->sweepCnt[j] -= cntDelta;
            if (sv->sweepCnt[j] <= 0)
            {
                sv->sweepCnt[j] = sv->sweepNum[j] << 16;
                sv->sweepOff[j] = 0;
            }
            else
            {
                sv->sweepOff[j] += (sv->sweepAdd[j] >> 12) * addFactor;
            }
        }
    }

    for (j = 0; j < 2; ++j)
    {
        u32 panVal;
        if (sv->panning[j] == sv->panTarget[j])
        {
            continue;
        }
        sv->panTime[j] -= lowDeltaTime;
        if ((s32)sv->panTime[j] <= 0)
        {
            sv->panning[j] = sv->panTarget[j];
            sv->panTime[j] = 0;
        }
        else
        {
            sv->panning[j] = sv->panTarget[j] - (sv->panTime[j] / 256) * sv->panDelta[j];
            panVal = sv->panning[j];
            sv->panning[j] = (s32)panVal < 0 ? 0 : panVal > 0x7F0000 ? 0x7F0000 : panVal;
        }
        HWVOICE_FLAGS(sv) |= 0x200000000000ULL;
    }

    if ((HWVOICE_FLAGS(sv) & 0x20000000000ULL) != 0 && adsrHandleLowPrecision(&sv->pitchADSR, &adsr_start, &adsr_delta))
    {
        HWVOICE_FLAGS(sv) &= ~0x20000000000ULL;
    }

    ccents = (sv->curNote << 16) + (sv->curDetune * 0x10000) / 100;
    if ((HWVOICE_FLAGS(sv) & 0x10030) != 0)
    {
        if (sv->midi != 0xFF)
        {
            pbend = inpGetPitchBend((McmdVoiceState*)sv);
            sv->pbLast = pbend;
            goto pbend_adjust;
        }
    }
    else
    {
        pbend = sv->pbLast;
    pbend_adjust:
        if (pbend != 0x2000)
        {
            pbend -= 0x2000;
            if (pbend < 0)
            {
                ccents += sv->pbLowerKeyRange * pbend * 8;
            }
            else
            {
                ccents += sv->pbUpperKeyRange * pbend * 8;
            }
        }
    }

    if ((HWVOICE_FLAGS(sv) & 0x2000) != 0)
    {
        Modulation = inpGetModulation((McmdVoiceState*)sv);
        vrange = sv->vibKeyRange * 256 + (sv->vibCentRange * 256) / 100;
        if (sv->vibModAddScale != 0)
        {
            vrange += (sv->vibModAddScale * ((Modulation >> 7) & 0x1FF)) >> 7;
        }
        if ((HWVOICE_FLAGS(sv) & 0x4000) != 0)
        {
            voff = (sv->vibCurOffset * ((Modulation >> 7) & 0x1FF)) >> 7;
        }
        else
        {
            voff = sv->vibCurOffset;
        }
        ccents += (vrange * voff) >> 4;
    }

    if (sv->midi != 0xFF)
    {
        portamentoRaw = inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, sv->midi, sv->midiSet);
        if ((u16)portamentoRaw != sv->portLastCtrlState || (HWVOICE_FLAGS(sv) & 0x21000) == 0x20000)
        {
            if ((u16)portamentoRaw <= 0x1F80)
            {
                HWVOICE_FLAGS(sv) &= ~0x400;
            }
            else
            {
                if ((HWVOICE_FLAGS(sv) & 0x400) == 0)
                {
                    if ((HWVOICE_FLAGS(sv) & 0x20000) == 0)
                    {
                        if (sv->portType == 1)
                        {
                            if ((HWVOICE_FLAGS(sv) & 0x1000) == 0)
                            {
                                sv->portTime = 0;
                            }
                            else
                            {
                                sv->portTime = sv->portDuration;
                            }
                        }
                        else
                        {
                            sv->portTime = sv->portDuration;
                        }
                        sv->portCurPitch = sv->lastNote << 16;
                    }
                }
                HWVOICE_FLAGS(sv) |= 0x400;
            }
            HWVOICE_FLAGS(sv) |= 0x1000;
            sv->portLastCtrlState = portamentoRaw;
        }
    }

    ccents = apply_portamento(sv, ccents, lowDeltaTime);

    if ((HWVOICE_FLAGS(sv) & 0x20000000000ULL) != 0)
    {
        ccents += sv->pitchADSRRange * (sv->pitchADSR.currentVolume >> 16) >> 7;
    }

    cpitch = convert_cents(sv, ccents);
    cpitch += sv->sweepOff[0] + sv->sweepOff[1];
    hwSetPitch(voice, sv->curPitch = ((cpitch >> 16) * inpGetDoppler((McmdVoiceState*)sv)) >> 13);
    synthQueueDelayedUpdate((SynthDelayedNode*)sv, 0, 0xF00);

end:
    UpdateTimeMIDICtrl(sv);
}

/*
 * Zero-offset per-voice update: volume envelope, tremolo, panning and final
 * volume/aux sends.
 */
#pragma fp_contract off
void ZeroOffsetHandler(int voice)
{
    SynthHwVoice* sv;
    u32 lowDeltaTime;
    u16 Modulation;
    f32 vol;
    f32 auxa;
    f32 auxb;
    f32 faderVol;
    f32 voiceVol;
    u32 volUpdate;
    f32 lfo;
    f32 scale;
    s32 pan;
    f32 preVol;
    f32 postVol;

    sv = HWVOICE(voice);
    if (!hwIsActive(voice) && sv->addr == 0)
    {
        goto end;
    }

    lowDeltaTime = (u32)(synthRealTime - *(u64*)&sv->lastZeroCallTimeHi);
    *(u64*)&sv->lastZeroCallTimeHi = synthRealTime;

    if ((HWVOICE_FLAGS(sv) & 0x8000) != 0)
    {
        sv->envCurrent += sv->envDelta * (lowDeltaTime >> 8);
        if (sv->envDelta < 0)
        {
            if (sv->envTarget >= sv->envCurrent)
            {
                sv->envCurrent = sv->envTarget;
                HWVOICE_FLAGS(sv) &= ~0x8000;
            }
        }
        else if (sv->envTarget <= sv->envCurrent)
        {
            sv->envCurrent = sv->envTarget;
            HWVOICE_FLAGS(sv) &= ~0x8000;
        }
        sv->volume = sv->envCurrent;
        volUpdate = 1;
    }
    else
    {
        volUpdate = (HWVOICE_FLAGS(sv) & 0x100000000000ULL) != 0;
    }

    HWVOICE_FLAGS(sv) &= ~0x100000000000ULL;

    faderVol = synthMasterFader[sv->vGroup].auxCurrent * synthMasterFader[sv->vGroup].current *
               synthMasterFader[sv->fxFlag ? 22 : 21].current;

    if (sv->track != 0xFF)
    {
        vol = (1.f / 127.f) * (faderVol * (f32)synthTrackVolume[sv->track]);
    }
    else
    {
        vol = faderVol;
    }

    if (vol != sv->lastVolFaderScale)
    {
        sv->lastVolFaderScale = vol;
        volUpdate = 1;
    }

    voiceVol = (1.f / (8192.f * 1016.f)) * (f32)sv->volume;

    if ((sv->treScale | sv->treModAddScale) != 0)
    {
        Modulation = inpGetModulation((McmdVoiceState*)sv);
        lfo = (1.f / 8192.f) *
              (f32)(0x2000 - ((0x2000 - ((s16)inpGetTremolo((McmdVoiceState*)sv) - 0x2000)) >> 1));
        {
            f32 modScale = 1.490207e-08f * ((f32)Modulation * (f32)(0x1000 - sv->treModAddScale));
            scale = (1.f / 4096.f) * ((f32)sv->treScale * (1.f - modScale));
        }
        if (sv->treCurScale < scale)
        {
            if ((sv->treCurScale += 0.2f) > scale)
            {
                sv->treCurScale = scale;
            }
        }
        else if (sv->treCurScale > scale)
        {
            if ((sv->treCurScale -= 0.2f) < scale)
            {
                sv->treCurScale = scale;
            }
        }
        {
            f32 tmp = lfo * (1.f - sv->treCurScale);
            voiceVol = voiceVol * (1.f - tmp);
        }
        volUpdate = 1;
    }

    if ((synthFlags & 1) == 0)
    {
        if ((HWVOICE_FLAGS(sv) & 0x200000000000ULL) != 0 || (sv->midiDirtyFlags & 0x6) != 0)
        {
            HWVOICE_FLAGS(sv) &= ~0x200000000000ULL;
            pan = sv->panning[0] + (inpGetPanning((McmdVoiceState*)sv) - 0x2000) * 0x200;
            sv->lastPan = pan < 0 ? 0 : (pan > 0x7F0000 ? 0x7F0000 : pan);

            if ((synthFlags & 2) != 0)
            {
                if ((sv->lastSPan = sv->panning[1] + (u16)inpGetSurPanning((McmdVoiceState*)sv) * 0x200) > 0x7F0000)
                {
                    sv->lastSPan = 0x7F0000;
                }
            }
            else
            {
                sv->lastSPan = 0;
            }
            volUpdate = 1;
        }
        else if ((synthFlags & 2) == 0)
        {
            sv->lastSPan = 0;
        }
    }
    else
    {
        sv->lastPan = 0x400000;
        sv->lastSPan = 0;
        volUpdate |= (HWVOICE_FLAGS(sv) & 0x200000000000ULL) != 0;
        HWVOICE_FLAGS(sv) &= ~0x200000000000ULL;
    }

    if (volUpdate || (sv->midiDirtyFlags & 0xF01) != 0)
    {
        preVol = voiceVol;
        postVol = (1.f / 16383.f) * (voiceVol * vol * (f32)inpGetVolume((McmdVoiceState*)sv));
        auxa = (1.f / 127.f) * (f32)sv->revVolOffset +
               ((1.f / 16383.f) * (preVol * (f32)inpGetPreAuxA((McmdVoiceState*)sv)) +
                (1.f / 127.f) *
                    ((f32)sv->revVolScale *
                     ((1.f / 16383.f) * (postVol * (f32)inpGetReverb((McmdVoiceState*)sv)))));
        auxb = (1.f / 16383.f) * (preVol * (f32)inpGetPreAuxB((McmdVoiceState*)sv)) +
               (1.f / 16383.f) * (postVol * (f32)inpGetPostAuxB((McmdVoiceState*)sv));
        sv->curOutputVolume = (u16)(32767.f * postVol);
        hwSetVolume(voice, sv->volTable, postVol, sv->lastPan, sv->lastSPan, auxa, auxb);
    }

    if (sv->age != 0)
    {
        if ((s32)(sv->age -= sv->ageSpeed * lowDeltaTime) < 0)
        {
            sv->age = 0;
        }
        hwSetPriority(voice, sv->prio << 24 | sv->age >> 15);
    }

    synthQueueDelayedUpdate((SynthDelayedNode*)sv, 1, (5 - hwGetTimeOffset()) * 256);

end:
    UpdateTimeMIDICtrl(sv);
}
#pragma fp_contract reset

/*
 * Event per-voice update: pedal state, deferred hardware start and key-off.
 */
void EventHandler(int voice)
{
    SynthHwVoice* sv;

    sv = HWVOICE(voice);
    if (!hwIsActive(voice) && sv->addr == 0)
    {
        goto end;
    }

    macSetPedalState(sv, inpGetPedal((McmdVoiceState*)sv) > 0x1F80);

    if ((HWVOICE_FLAGS(sv) & 0x20) != 0)
    {
        HWVOICE_FLAGS(sv) &= ~0x20;
        HWVOICE_FLAGS(sv) |= 0x10;
        hwStart(voice, sv->studio);
    }

    if ((HWVOICE_FLAGS(sv) & 0x10000000090ULL) == 0x90)
    {
        HWVOICE_FLAGS(sv) &= ~0x90;
        hwKeyOff(voice);
        if ((HWVOICE_FLAGS(sv) & 0x20000000000ULL) != 0 && adsrRelease(&sv->pitchADSR))
        {
            HWVOICE_FLAGS(sv) &= ~0x20000000000ULL;
        }
    }

end:
    UpdateTimeMIDICtrl(sv);
}

/*
 * Queue one of a fade's embedded delayed-action nodes into the 32-bucket
 * scheduler ring.
 */
void synthQueueDelayedUpdate(SynthDelayedNode* fade, int mode, u32 delay)
{
    SynthDelayedNode* newJq;
    SynthDelayedNode** root;
    u8 jobTabIndex;
    SynthJobTab* jobTab;
    SynthTables* tables = (SynthTables*)synthTicksPerSecond;

    jobTabIndex = ((delay / 256) + gSynthDelayBucketCursor) & 0x1F;
    jobTab = &tables->jobs[jobTabIndex];

    switch (mode)
    {
    case 0:
        newJq = fade;
        if (newJq->bucketIndex != 0xFF)
        {
            if (newJq->bucketIndex == jobTabIndex)
            {
                return;
            }
            if (newJq->next != 0)
            {
                newJq->next->prev = newJq->prev;
            }
            if (newJq->prev != 0)
            {
                newJq->prev->next = newJq->next;
            }
            else
            {
                tables->jobs[newJq->bucketIndex].lowPrecision = newJq->next;
            }
        }
        root = &jobTab->lowPrecision;
        break;
    case 1:
        newJq = fade + 1;
        if (newJq->bucketIndex != 0xFF)
        {
            if (newJq->bucketIndex == jobTabIndex)
            {
                return;
            }
            if (newJq->next != 0)
            {
                newJq->next->prev = newJq->prev;
            }
            if (newJq->prev != 0)
            {
                newJq->prev->next = newJq->next;
            }
            else
            {
                tables->jobs[newJq->bucketIndex].zeroOffset = newJq->next;
            }
        }
        root = &jobTab->zeroOffset;
        break;
    case 2:
        newJq = fade + 2;
        if (newJq->bucketIndex != 0xFF)
        {
            return;
        }
        root = &jobTab->event;
        break;
    default:
        break;
    }

    newJq->bucketIndex = jobTabIndex;
    if ((newJq->next = *root) != 0)
    {
        (*root)->prev = newJq;
    }
    newJq->prev = 0;
    *root = newJq;
}

/*
 * Reset four pos/timer fields on the handle, then advance both
 * channels (modes 0 and 1).
 */
void fn_802712C8(SynthDelayedNode* fade)
{
    SynthVoiceTimers* timers = (SynthVoiceTimers*)fade;

    *(u64*)&timers->updateTimeHi0 = synthRealTime;
    *(u64*)&timers->updateTimeHi1 = synthRealTime;
    synthQueueDelayedUpdate(fade, 0, 0);
    synthQueueDelayedUpdate(fade, 1, 0);
}

/*
 * Advance both channels (modes 0 and 1) of the handle.
 */
void synthQueueVoicePrimaryUpdates(SynthDelayedNode* fade)
{
    synthQueueDelayedUpdate(fade, 0, 0);
    synthQueueDelayedUpdate(fade, 1, 0);
}

/*
 * Wrapper for synthQueueDelayedUpdate(handle, 2, 0).
 */
void synthQueueVoiceInputUpdate(SynthDelayedNode* fade)
{
    synthQueueDelayedUpdate(fade, 2, 0);
}

/*
 * Walk a voice linked-list, marking each entry's slot 9 as 0xff and
 * invoking the callback for entries whose voice's 0x11c field is 0.
 */
#pragma dont_inline on
void synthDrainDelayedBucket(SynthDelayedNode** head, SynthDelayedBucketCallback callback)
{
    SynthDelayedNode* node = *head;
    while (node != 0)
    {
        SynthDelayedNode* next = node->next;
        node->bucketIndex = 0xff;
        {
            if (*(u8*)(node->voiceIndex * SYNTH_VOICE_SLOT_SIZE + (u8*)synthVoice + SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET) == 0)
            {
                callback(node->voiceIndex);
            }
        }
        node = next;
    }
    *head = 0;
}
#pragma dont_inline reset

static inline void HandleVoices(void)
{
    SynthJobTab* jobTab = &synthJobTable[gSynthDelayBucketCursor];
    synthDrainDelayedBucket(&jobTab->lowPrecision, LowPrecisionHandler);
    synthDrainDelayedBucket(&jobTab->event, EventHandler);
    synthDrainDelayedBucket(&jobTab->zeroOffset, ZeroOffsetHandler);
    gSynthDelayBucketCursor = (gSynthDelayBucketCursor + 1) & 0x1f;
}

/*
 * Dispatch a completed fade action based on its type byte.
 */
void synthDispatchFadeAction(SynthFade* fade)
{
    switch (fade->delayAction)
    {
    case SYNTH_FADE_DELAY_ACTION_FREE_HANDLE:
        synthFreeHandle(fade->handle);
        break;
    case SYNTH_FADE_DELAY_ACTION_QUEUE_HANDLE:
        synthQueueHandle(fade->handle);
        break;
    case SYNTH_FADE_DELAY_ACTION_CLEAR_MIX:
        synthSetHandleMixData(fade->handle, 0, 0);
        break;
    }
}

/*
 * Periodic synth tick: drains delayed-action buckets, advances fade ramps,
 * runs AUX callbacks, and advances the global synth timer.
 */
#pragma fp_contract off
void synthHandle(u32 deltaTime)
{
    u32 i;
    u32 s;
    SynthFade* fade;
    u32 mask;

    if (synthInfo.numSamples == 0)
    {
        return;
    }

    macHandle(deltaTime);
    HandleVoices();
    if (hwGetTimeOffset() == 0)
    {
        if ((synthMasterFaderActiveFlags | synthMasterFaderPauseActiveFlags) != 0)
        {
            for (i = 0, fade = synthMasterFader, mask = 1; i < SYNTH_FADE_COUNT; mask <<= 1, ++i, ++fade)
            {
                if ((synthMasterFaderActiveFlags & mask) != 0)
                {
                    fade->current = fade->target - fade->progress * (fade->target - fade->start);
                    if ((fade->progress -= fade->progressStep) <= 0.f)
                    {
                        fade->current = fade->target;
                        synthDispatchFadeAction(fade);
                        if (((synthMasterFaderActiveFlags &= ~mask) == 0) &&
                            (synthMasterFaderPauseActiveFlags == 0))
                        {
                            break;
                        }
                    }
                }
                if ((synthMasterFaderPauseActiveFlags & mask) != 0)
                {
                    fade->auxCurrent = fade->auxTarget - fade->auxProgress * (fade->auxTarget - fade->auxStart);
                    if ((fade->auxProgress -= fade->auxProgressStep) <= 0.f)
                    {
                        fade->auxCurrent = fade->auxTarget;
                        if (((synthMasterFaderPauseActiveFlags &= ~mask) == 0) &&
                            (synthMasterFaderActiveFlags == 0))
                        {
                            break;
                        }
                    }
                }
            }
        }
        for (s = 0; s < 8; ++s)
        {
            if (synthAuxAMIDI[s] != 0xff)
            {
                SynthAuxInfo info;
                for (i = 0; i < 4; ++i)
                {
                    info.data.parameterUpdate.para[i] = inpGetAuxA(s, i, synthAuxAMIDI[s], synthAuxAMIDISet[s]);
                }
                synthAuxACallback[s](1, &info, synthAuxAUser[s]);
            }
            if (synthAuxBMIDI[s] != 0xff)
            {
                SynthAuxInfo info;
                for (i = 0; i < 4; ++i)
                {
                    info.data.parameterUpdate.para[i] = inpGetAuxB(s, i, synthAuxBMIDI[s], synthAuxBMIDISet[s]);
                }
                synthAuxBCallback[s](1, &info, synthAuxBUser[s]);
            }
        }
    }
    hwFrameDone();
    synthRealTime += deltaTime;
}

/*
 * Start an FX sample by id, applying default volume/pan sentinels.
 */
typedef struct SynthFxSampleInfo
{
    u8 pad00[2];
    u16 sampleId;
    u8 velocity;
    u8 key;
    u8 defaultVolume;
    u8 defaultPan;
    u8 flags;
    u8 auxIndex;
} SynthFxSampleInfo;

extern SynthFxSampleInfo* dataGetFX(u32 fxId);

int synthFXStart(u32 fxId, u8 volume, u8 pan, u8 studio, u32 studioAux)
{
    SynthFxSampleInfo* sampleInfo;
    u32 handle;

    handle = 0xFFFFFFFF;
    sampleInfo = dataGetFX(fxId);
    if (sampleInfo != (SynthFxSampleInfo*)0x0)
    {
        if (volume == 0xff)
        {
            volume = sampleInfo->defaultVolume;
        }
        if (pan == 0xff)
        {
            pan = sampleInfo->defaultPan;
        }
        handle = synthStartSound(sampleInfo->sampleId, sampleInfo->key, sampleInfo->velocity, sampleInfo->flags | 0x80,
                                 volume, pan, 0xff, 0xff, 0, 0, 0xff, sampleInfo->auxIndex, 0, studio, studioAux);
    }
    return handle;
}

#define SYNTH_FADE_SELECTOR_ACTION_2      0xfa
#define SYNTH_FADE_SELECTOR_ACTION_2_OR_3 0xfc
#define SYNTH_FADE_SELECTOR_ACTION_3      0xfb
#define SYNTH_FADE_SELECTOR_ACTION_0      0xfd
#define SYNTH_FADE_SELECTOR_ACTION_1      0xfe
#define SYNTH_FADE_SELECTOR_ACTION_0_OR_1 0xff
#define SYNTH_FADE_TYPE_ACTION_0          0
#define SYNTH_FADE_TYPE_ACTION_1          1
#define SYNTH_FADE_TYPE_ACTION_2          2
#define SYNTH_FADE_TYPE_ACTION_3          3

extern void inpSetMidiCtrl(u8 ctrl, u8 channel, u8 set, u8 value);
extern void inpSetMidiCtrl14(u8 ctrl, u8 channel, u8 set, u16 value);
extern void inpFXCopyCtrl(u8 controller, u32 dstHandle, u32 srcHandle);
extern void macSetExternalKeyoff(McmdVoiceState* slot);
extern void macSampleEndNotify(void);
extern void memset(void* dst, int value, u32 size);
extern void inpInit(u32 unused);
extern void macInit(void);
extern u32 synthMessageCallback;

/*
 * synthFXSetCtrl - sndFXCtrl underlying impl.
 * Walks the handle's voice-slot chain, dispatching inpSetMidiCtrl per slot.
 */
u32 synthFXSetCtrl(u32 handle, u8 controller, u8 value)
{
    u32 found;
    u8 idx;
    McmdVoiceState* slot;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu)
    {
        idx = handle;
        if (handle == synthVoice[idx].voiceHandle)
        {
            slot = &synthVoice[idx];
            if ((*(u64*)&slot->inputFlags & 2) != 0)
            {
                inpSetMidiCtrl(controller, idx, slot->startupMidiEvent, value);
            }
            else
            {
                inpSetMidiCtrl(controller, idx, slot->midiEvent, value);
            }
            found = 1;
            handle = synthVoice[idx].voiceNextHandle;
        }
        else
        {
            return found;
        }
    }
    return found;
}

/*
 * synthFXSetCtrl14 - sndFXCtrl14 underlying impl.
 */
u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value)
{
    u32 found;
    u8 idx;
    McmdVoiceState* slot;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu)
    {
        idx = handle;
        if (handle == synthVoice[idx].voiceHandle)
        {
            slot = &synthVoice[idx];
            if ((*(u64*)&slot->inputFlags & 2) != 0)
            {
                inpSetMidiCtrl14(controller, idx, slot->startupMidiEvent, value);
            }
            else
            {
                inpSetMidiCtrl14(controller, idx, slot->midiEvent, value);
            }
            found = 1;
            handle = synthVoice[idx].voiceNextHandle;
        }
        else
        {
            return found;
        }
    }
    return found;
}

/*
 * synthFXCloneMidiSetup - copies the five FX-stage controllers
 * (volume, pan, expression, reverb, chorus) between two handles.
 */
void synthFXCloneMidiSetup(u32 dstHandle, u32 srcHandle)
{
    inpFXCopyCtrl(0x07, dstHandle, srcHandle);
    inpFXCopyCtrl(0x0A, dstHandle, srcHandle);
    inpFXCopyCtrl(0x5B, dstHandle, srcHandle);
    inpFXCopyCtrl(0x80, dstHandle, srcHandle);
    inpFXCopyCtrl(0x84, dstHandle, srcHandle);
}

/*
 * synthSendKeyOff - sndFXKeyOff underlying impl.
 * Walks the handle's voice-slot chain and signals key-off on each slot.
 */
u32 synthSendKeyOff(u32 handle)
{
    u32 found;
    u32 idx;

    found = 0;
    if (gSynthInitialized != 0)
    {
        handle = vidGetInternalId(handle);
        while (handle != 0xFFFFFFFFu)
        {
            idx = (u8)handle;
            if (handle == synthVoice[idx].voiceHandle)
            {
                macSetExternalKeyoff(&synthVoice[idx]);
                found = 1;
            }
            handle = synthVoice[idx].voiceNextHandle;
        }
    }
    return found;
}

/*
 * Route synth fade commands to one slot or to the broadcast pseudo-slots
 * 0xfa through 0xff.
 */
static inline void SetupFader(SynthFade* fade, u8 volume, u32 time, u8 action, u32 handle)
{
    fade->delayAction = action;
    fade->handle = handle;
    if (time != 0)
    {
        fade->start = fade->current;
        fade->target = (f32)volume * (1.f / 127.f);
        fade->progress = 1.f;
        fade->progressStep = 1280.f / (f32)time;
    }
    else
    {
        fade->current = fade->target = (f32)volume * (1.f / 127.f);
        if (fade->handle != SYNTH_INVALID_LINK_ID)
        {
            synthDispatchFadeAction(fade);
        }
    }
}

void synthVolume(u8 volume, u16 timeMs, u8 target, u8 action, u32 handle)
{
    u32 convertedTime;
    u32 i;
    u8 matchState;
    SynthFade* fade;

    if ((convertedTime = timeMs) != 0)
    {
        sndConvertMs(&convertedTime);
    }

    switch (target)
    {
    case SYNTH_FADE_SELECTOR_ACTION_0_OR_1:
        for (fade = synthMasterFader, i = 0; i < SYNTH_FADE_COUNT; ++i, ++fade)
        {
            if (fade->type == SYNTH_FADE_TYPE_ACTION_0 || fade->type == SYNTH_FADE_TYPE_ACTION_1)
            {
                SetupFader(fade, volume, convertedTime, action, SYNTH_INVALID_LINK_ID);
                synthMasterFaderActiveFlags |= 1U << i;
            }
        }
        return;

    case SYNTH_FADE_SELECTOR_ACTION_2_OR_3:
        for (fade = synthMasterFader, i = 0; i < SYNTH_FADE_COUNT; ++i, ++fade)
        {
            if (fade->type == SYNTH_FADE_TYPE_ACTION_2 || fade->type == SYNTH_FADE_TYPE_ACTION_3)
            {
                SetupFader(fade, volume, convertedTime, action, SYNTH_INVALID_LINK_ID);
                synthMasterFaderActiveFlags |= 1U << i;
            }
        }
        return;

    case SYNTH_FADE_SELECTOR_ACTION_2:
        matchState = SYNTH_FADE_TYPE_ACTION_2;
        goto setup_type;

    case SYNTH_FADE_SELECTOR_ACTION_3:
        matchState = SYNTH_FADE_TYPE_ACTION_3;
        goto setup_type;

    case SYNTH_FADE_SELECTOR_ACTION_0:
        matchState = SYNTH_FADE_TYPE_ACTION_0;
        goto setup_type;

    case SYNTH_FADE_SELECTOR_ACTION_1:
        matchState = SYNTH_FADE_TYPE_ACTION_1;

    setup_type:
        for (fade = synthMasterFader, i = 0; i < SYNTH_FADE_COUNT; ++i, ++fade)
        {
            if (fade->type == matchState)
            {
                SetupFader(fade, volume, convertedTime, action, SYNTH_INVALID_LINK_ID);
                synthMasterFaderActiveFlags |= 1U << i;
            }
        }
        return;

    default:
        SetupFader(&synthMasterFader[target], volume, convertedTime, action, handle);
        synthMasterFaderActiveFlags |= 1U << target;
        return;
    }
}
int synthIsFadeOutActive(u8 voiceIdx)
{
    u8* v = (u8*)synthTicksPerSecond + voiceIdx * sizeof(SynthFade);
    if (((v[SYNTH_FADE_TABLE_OFFSET + 0x2d] != SYNTH_FADE_ACTION_DISABLED) &&
         ((synthMasterFaderActiveFlags & (1U << voiceIdx)) != 0)) &&
        (*(f32*)(v + SYNTH_FADE_TABLE_OFFSET + 8) > *(f32*)(v + SYNTH_FADE_TABLE_OFFSET + 4)))
    {
        return 1;
    }
    return 0;
}

/*
 * Set a single byte field on a voice slot.
 */
void synthSetMusicVolumeType(u32 voiceIdx, u8 value)
{
    if (gSynthInitialized == 0)
    {
        return;
    }
    synthMasterFader[voiceIdx & 0xff].type = value;
}

/*
 * Voice command dispatcher: runs different actions per command code.
 *   0 -> validate current sample and mark the slot active
 *   1 -> voiceKill
 *   2 -> claim virtual sample slot
 *   3 -> simple vacate via hwGetVirtualSampleID + synthHandleVirtualSampleDone
 */
int synthHWMessageHandler(int mode, u32 arg)
{
    u32 result = 0;

    switch (mode)
    {
    case 0:
    {
        if (synthVoice[arg & 0xff].macroAllocating != 0)
        {
            break;
        }
        synthHandleVirtualSampleDone(hwGetVirtualSampleID(arg & 0xff));
        if (arg != synthVoice[arg & 0xff].voiceHandle)
        {
            break;
        }
        macSampleEndNotify();
        break;
    }
    case 1:
        voiceKill(arg & 0xff);
        break;
    case 2:
        result = synthClaimVirtualSampleSlot(arg & 0xff);
        break;
    case 3:
    {
        synthHandleVirtualSampleDone(hwGetVirtualSampleID(arg & 0xff));
        break;
    }
    }
    return result;
}

typedef struct SynthGlobalState
{
    u8 pad000[0x200];
    u32 dspDmaSize;
    u8 pad204[0x1bc];
    u32 sampleRate;
    u8 pad3c4[0x600];
    f32 auxMixA;
    u8 pad9c8[0x2c];
    f32 auxMixB;
    u8 pad9f8[0x1d9];
    u8 initialized;
    u8 padbd2[0xc34 - 0xbd2];
    u32 auxASend[8];
    u8 padc54[0xc74 - 0xc54];
    u32 auxBSend[8];
    u8 auxPairState[8][2];
    u32 auxMixSlot[16];
} SynthGlobalState;

typedef struct SynthJobEntry
{
    u32 lowPrecision;
    u32 event;
    u32 zeroOffset;
} SynthJobEntry;

static inline void synthInitJobQueue(u8* state)
{
    SynthJobEntry* jobTable = (SynthJobEntry*)(state + 0x240);
    u8 i;

    for (i = 0; i < 32; ++i)
    {
        jobTable[i].lowPrecision = 0;
        jobTable[i].event = 0;
        jobTable[i].zeroOffset = 0;
    }

    gSynthDelayBucketCursor = 0;
}

void synthInit(u32 sampleRate, u32 voiceCount)
{
    u8* state;
    u32 voiceIndex;
    u32 fadeIndex;
    u32 auxIndex;
    f32 unusedA[2];

    state = (u8*)synthTicksPerSecond;
    synthRealTime = 0;
    ((SynthGlobalState*)state)->sampleRate = sampleRate;
    ((SynthGlobalState*)state)->dspDmaSize = 0x1800;
    synthFlags = 0;
    synthMessageCallback = 0;

    synthVoice = salMalloc(voiceCount * SYNTH_VOICE_STRIDE);
    memset(synthVoice, 0, voiceCount * SYNTH_VOICE_STRIDE);

    for (voiceIndex = 0; voiceIndex < voiceCount; voiceIndex++)
    {
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0xF4) = SYNTH_INVALID_LINK_ID;
        *(u64*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x114) = 0;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x110) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x10C) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x121) = 0xFF;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x154) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x192) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x190) = 0x80;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x191) = 0;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x180) = 0x400000;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x170) = 0x400000;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x184) = 0;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x174) = 0;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1A0) = 0;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1A4) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1B8) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1B9) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x11C) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x11E) = 0x17;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x104) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x193) = 1;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1C0) = 0;
        *(u16*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1C4) = 0;
        *(u16*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1C6) = 0x7FFF;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1CC) = 0;
        *(u16*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1D0) = 0;
        *(u16*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x1D2) = 0x7FFF;
        *(u32*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x13C) = 0x6400;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x131) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x11F) = 0;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x08) = (u8)voiceIndex;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x09) = 0xFF;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x14) = (u8)voiceIndex;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x15) = 0xFF;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x20) = (u8)voiceIndex;
        *(u8*)((u8*)synthVoice + voiceIndex * SYNTH_VOICE_STRIDE + 0x21) = 0xFF;
    }

    {
        SynthFade* fade = (SynthFade*)(state + 0x5D4);
        u32 pass;

        for (pass = 0; pass < 2; pass++)
        {
            fade[0].current = 0.f;
            fade[0].auxCurrent = 1.f;
            fade[0].type = SYNTH_FADE_ACTION_DISABLED;
            fade[1].current = 0.f;
            fade[1].auxCurrent = 1.f;
            fade[1].type = SYNTH_FADE_ACTION_DISABLED;
            fade[2].current = 0.f;
            fade[2].auxCurrent = 1.f;
            fade[2].type = SYNTH_FADE_ACTION_DISABLED;
            fade[3].current = 0.f;
            fade[3].auxCurrent = 1.f;
            fade[3].type = SYNTH_FADE_ACTION_DISABLED;
            fade[4].current = 0.f;
            fade[4].auxCurrent = 1.f;
            fade[4].type = SYNTH_FADE_ACTION_DISABLED;
            fade[5].current = 0.f;
            fade[5].auxCurrent = 1.f;
            fade[5].type = SYNTH_FADE_ACTION_DISABLED;
            fade[6].current = 0.f;
            fade[6].auxCurrent = 1.f;
            fade[6].type = SYNTH_FADE_ACTION_DISABLED;
            fade[7].current = 0.f;
            fade[7].auxCurrent = 1.f;
            fade[7].type = SYNTH_FADE_ACTION_DISABLED;
            fade[8].current = 0.f;
            fade[8].auxCurrent = 1.f;
            fade[8].type = SYNTH_FADE_ACTION_DISABLED;
            fade[9].current = 0.f;
            fade[9].auxCurrent = 1.f;
            fade[9].type = SYNTH_FADE_ACTION_DISABLED;
            fade[10].current = 0.f;
            fade[10].auxCurrent = 1.f;
            fade[10].type = SYNTH_FADE_ACTION_DISABLED;
            fade[11].current = 0.f;
            fade[11].auxCurrent = 1.f;
            fade[11].type = SYNTH_FADE_ACTION_DISABLED;
            fade[12].current = 0.f;
            fade[12].auxCurrent = 1.f;
            fade[12].type = SYNTH_FADE_ACTION_DISABLED;
            fade[13].current = 0.f;
            fade[13].auxCurrent = 1.f;
            fade[13].type = SYNTH_FADE_ACTION_DISABLED;
            fade[14].current = 0.f;
            fade[14].auxCurrent = 1.f;
            fade[14].type = SYNTH_FADE_ACTION_DISABLED;
            fade[15].current = 0.f;
            fade[15].auxCurrent = 1.f;
            fade[15].type = SYNTH_FADE_ACTION_DISABLED;
            fade += 16;
        }
    }

    synthMasterFaderActiveFlags = 0;
    synthMasterFaderPauseActiveFlags = 0;
    ((SynthGlobalState*)state)->initialized = 1;
    for (fadeIndex = 0; fadeIndex < 8; fadeIndex++)
    {
        *(u8*)(state + 0xA51 + fadeIndex * sizeof(SynthFade)) = 0;
    }
    ((SynthGlobalState*)state)->auxMixA = 1.f;
    ((SynthGlobalState*)state)->auxMixB = 1.f;

    inpInit(0);

    for (auxIndex = 0; auxIndex < 8; auxIndex++)
    {
        ((SynthGlobalState*)state)->auxASend[auxIndex] = 0;
        synthAuxAMIDI[auxIndex] = 0xFF;
        ((SynthGlobalState*)state)->auxBSend[auxIndex] = 0;
        synthAuxBMIDI[auxIndex] = 0xFF;
        ((SynthGlobalState*)state)->auxPairState[auxIndex][1] = 0;
        ((SynthGlobalState*)state)->auxPairState[auxIndex][0] = 0;
    }

    macInit();
    vidInit();
    voiceInitPriorityTables();

    for (auxIndex = 0; auxIndex < 16; auxIndex++)
    {
        ((SynthGlobalState*)state)->auxMixSlot[auxIndex] = 0;
    }

    voiceInitRegistrationTables();

    synthInitJobQueue(state);
    hwSetMesgCallback((u32)synthHWMessageHandler);
}

void synthExit(void)
{
    salFree(synthVoice);
}
