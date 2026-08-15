#include "musyx/inp_midi.h"
#include "musyx/mcmd_exec.h"
#include "musyx/voice_prio.h"
#include "musyx/mcmd_volume.h"
#include "musyx/inp_ctrl.h"
#include "musyx/snd_service.h"
#include "musyx/data_tables.h"
#include "musyx/snd_synth_api.h"
#include "musyx/voice_alloc.h"
#include "musyx/voice_id.h"
#include "musyx/voice_manage.h"
#include "musyx/hw_init.h"
#include "musyx/synth_channel_scale.h"
#include "musyx/synth_callback.h"
#include "musyx/synth_voice.h"
#include "musyx/mcmd_wait.h"
#include "musyx/synth_config.h"
#include "musyx/mcmd_loop.h"
#include "musyx/hw_aram.h"
#include "musyx/hw_break.h"
#include "musyx/hw_voice_params.h"
#include "musyx/mcmd_setup.h"
#include "musyx/snd_core.h"
#include "string.h"

#define SYNTH_GLOBAL_REG(index) (synthGlobalVariable[(index) - 0x10])

/* 64-bit control-flag word overlaying cFlagsHi(hi)/cFlagsLo(lo). */
#define MAC_CFLAGS(sv)     (*(u64*)&(sv)->cFlagsHi)
#define MAC_FLAG64(hi, lo) (((u64)(hi) << 32) | (u64)(lo))

/* Constant tables in this unit's data block (lbl_8032EDD0). */
typedef struct MacDataTables
{
    u16 pitchRatioTab[14]; /* 0x000 */
    s32 midi2TimeTab[128]; /* 0x01C */
    u8 pad21C[4];          /* 0x21C */
    u64 auxAMask[4];       /* 0x220 */
    u32 auxADirty[4];      /* 0x240 */
    u64 auxBMask[4];       /* 0x250 */
    u32 auxBDirty[4];      /* 0x270 */
} MacDataTables;

STATIC_ASSERT(offsetof(MacDataTables, midi2TimeTab) == 0x1C);
STATIC_ASSERT(offsetof(MacDataTables, auxAMask) == 0x220);
STATIC_ASSERT(offsetof(MacDataTables, auxADirty) == 0x240);
STATIC_ASSERT(offsetof(MacDataTables, auxBMask) == 0x250);
STATIC_ASSERT(offsetof(MacDataTables, auxBDirty) == 0x270);
STATIC_ASSERT(sizeof(MacDataTables) == 0x280);

extern u8 lbl_8032EDD0[];
McmdCommandArgs macCurrentCmd;
u64 macRealTime;
McmdVoiceState* macTimeQueueRoot;
McmdVoiceState* macActiveRoot;
u8 macStepsThisFrame;
extern const f32 sMacDlsScaleMax; /* 1023.0f */
extern const f32 sMacOne;         /* 1.0f */
/*
 * Choose a randomized note/velocity command and dispatch it through the
 * normal set-key handler.
 */
void mcmdRandomKey(McmdVoiceState* state, McmdCommandArgs* args)
{
    u8 tmp;
    s32 rangeLo;
    s32 rangeHi;
    u8 detune;
    u8 keyLo;
    u8 keyHi;

    if (((args->value >> 8) & 0xff) == 0)
    {
        keyHi = args->flags >> 0x18;
        keyLo = args->flags >> 8;
        detune = args->flags >> 0x18;
        if (((args->flags >> 8) & 0xff) > detune)
        {
            tmp = keyLo;
            keyLo = keyHi;
            keyHi = tmp;
        }
    }
    else
    {
        rangeLo = state->curNote - (s32)((args->flags >> 8) & 0xff);
        rangeHi = state->curNote + (args->flags >> 0x18);
        keyLo = rangeLo < 0 ? 0 : rangeLo > 0x7f ? 0x7f : rangeLo;
        keyHi = rangeHi < 0 ? 0 : rangeHi > 0x7f ? 0x7f : rangeHi;
    }

    if ((u8)args->value != 0)
    {
        detune = (sndRand() % 0xc9) - 100;
    }
    else
    {
        detune = (args->flags >> 0x10) & 0xff;
    }

    args->flags = (detune << 0x10) | 0x19 | ((keyLo + (sndRand() % ((keyHi - keyLo) + 1))) << 8);
    args->value = 0;
    state->curNote = (args->flags >> 8) & 0x7f;
    state->curDetune = (s8)(args->flags >> 0x10);
    if (voiceIsLastStarted(state) != 0)
    {
        inpSetMidiLastNote(state->midi, state->midiSet, state->curNote & 0xff);
    }
    args->flags = 4;
    mcmdWait(state, args);
}

/*
 * Queue a controller event and mark the owning MIDI/global dirty flag.
 */
void SelectSource(McmdVoiceState* svoice, McmdInputSlot* dest, McmdCommandArgs* cstep, u64 tstflag, u32 dirtyFlag)
{
    u8 combineMode;
    s32 scale;

    if (!(MAC_CFLAGS(svoice) & tstflag))
    {
        combineMode = 0;
        MAC_CFLAGS(svoice) |= tstflag;
    }
    else
    {
        combineMode = (u8)cstep->value;
    }

    scale = ((s16)(cstep->flags >> 16) << 16) / 100;
    if (scale < 0)
    {
        scale -= ((s8)(cstep->value >> 0x10) << 8) / 100;
    }
    else
    {
        scale += ((s8)(cstep->value >> 0x10) << 8) / 100;
    }

    inpAddCtrl(dest, (u8)(cstep->flags >> 8), scale, combineMode, (u8)(cstep->value >> 8) != 0);

    if ((dirtyFlag & 0x80000000) != 0)
    {
        inpSetGlobalMIDIDirtyFlag(svoice->midi, svoice->midiSet, dirtyFlag);
    }
    else
    {
        svoice->midiDirtyFlags |= dirtyFlag;
    }
}

void mcmdPortamento(McmdVoiceState* state, McmdCommandArgs* args)
{
    u32 time;

    state->portType = (args->flags >> 0x10) & 0xff;
    time = args->value >> 0x10;
    if ((args->value >> 8) & 1)
    {
        sndConvertMs(&time);
    }
    else
    {
        sndConvertTicks(&time, state);
    }

    state->portDuration = time;

    switch ((args->flags >> 8) & 0xff)
    {
    case 0:
        if (state->midi != 0xff)
        {
            inpSetMidiCtrl(MCMD_CTRL_PORTAMENTO, state->midi, state->midiSet, 0);
        }
        MAC_CFLAGS(state) &= ~MAC_FLAG64(0, 0x400);
        return;
    case 1:
        if (state->midi != 0xff)
        {
            inpSetMidiCtrl(MCMD_CTRL_PORTAMENTO, state->midi, state->midiSet, 0x7f);
        }
        while (TRUE)
        {
            if (!(MAC_CFLAGS(state) & MAC_FLAG64(0, 0x400)))
            {
                synthInitPortamento(state);
            }
            state->cFlagsLo |= 0x400;
            break;
        case 2:
            if (state->midi != 0xff &&
                inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, state->midi, state->midiSet) > 0x1f80)
            {
                continue;
            }
            break;
        }
        break;
    }
}

/*
 * Read a 32-bit synth register, either from the voice or EX controller bank.
 */
s32 varGet32(McmdVoiceState* state, u32 useExCtrl, u8 index)
{
    if (useExCtrl != 0)
    {
        return inpGetExCtrl(state, index);
    }
    index &= 0x1f;
    if (index < 0x10)
    {
        return state->local_vars[index];
    }
    return SYNTH_GLOBAL_REG(index);
}

static inline s32 varGetReg(McmdVoiceState* state, u32 useExCtrl, u8 index)
{
    if (useExCtrl != 0)
    {
        return (u16)inpGetExCtrl(state, index);
    }
    index &= 0x1f;
    if (index < 0x10)
    {
        return state->local_vars[index];
    }
    return SYNTH_GLOBAL_REG(index);
}

static inline u32 mcmdVarGet32Legacy(McmdVoiceState* state, u32 useExCtrl, u32 index)
{
    if (useExCtrl != 0)
    {
        return inpGetExCtrl(state, index);
    }
    index &= 0x1f;
    if (index < 0x10)
    {
        return state->local_vars[index];
    }
    return SYNTH_GLOBAL_REG(index);
}

/*
 * Read a signed 16-bit synth register.
 */
s16 varGet(McmdVoiceState* state, u32 useExCtrl, u8 index)
{
    return (s16)varGetReg(state, useExCtrl, index);
}

static inline s16 varGetSigned(McmdVoiceState* state, u32 useExCtrl, u8 index)
{
    return (s16)varGet32(state, useExCtrl, index);
}


static inline void varSet(McmdVoiceState* state, u8 useExCtrl, u8 index, s16 value)
{
    varSet32(state, useExCtrl, index, value);
}

/*
 * Write a synth register, routing high registers to the EX controller bank.
 */
void varSet32(McmdVoiceState* state, u32 useExCtrl, u8 index, s32 value)
{
    if (useExCtrl != 0)
    {
        inpSetExCtrl(state, index, value);
        return;
    }
    index &= 0x1f;
    if (index < 0x10)
    {
        state->local_vars[index] = value;
        return;
    }
    SYNTH_GLOBAL_REG(index) = value;
}

/*
 * Resume a trapped macro stream (keyoff/sample-end/message) if armed.
 */
static inline u32 ExecuteTrap(McmdVoiceState* sv, u8 trapType)
{
    if (sv->trapEventAny != 0 && sv->trapEventAddr[trapType] != 0)
    {
        sv->curAddr = sv->trapEventCurAddr[trapType];
        sv->addr = sv->trapEventAddr[trapType];
        sv->trapEventAddr[trapType] = 0;
        macMakeActive(sv);
        return 1;
    }
    return 0;
}

/*
 * Key off one voice identified by a full voice handle.
 */
static inline int SendSingleKeyOff(u32 voiceid)
{
    u32 i;

    if (voiceid != 0xffffffff)
    {
        i = voiceid & 0xff;
        if (voiceid == synthVoice[i].id)
        {
            macSetExternalKeyoff(&synthVoice[i]);
            return 0;
        }
    }
    return -1;
}

/*
 * Queue a message onto the voice owning a vid handle, resuming its
 * message-trap macro stream when armed.
 */
static inline u32 macPostMessage(u32 vid, u32 mesg)
{
    McmdVoiceState* sv;
    u32 v;

    if ((v = vidGetInternalId(vid)) != 0xffffffff &&
        (sv = &synthVoice[v & 0xff])->mesgNum < 4)
    {
        ++sv->mesgNum;
        sv->mesgQueue[sv->mesgWrite] = mesg;
        sv->mesgWrite = (sv->mesgWrite + 1) & 3;
        ExecuteTrap(sv, 2);
        return 1;
    }
    return 0;
}

/*
 * Queue register-derived messages onto voices found through vid handles.
 */
void mcmdVarCalculation(McmdVoiceState* state, McmdCommandArgs* args, u8 op)
{
    s16 s1;
    s16 s2;
    s32 t;

    s1 = varGetSigned(state, (u8)(args->flags >> 0x18), args->value);
    if (op == 4)
    {
        s2 = args->value >> 8;
    }
    else
    {
        s2 = varGetSigned(state, (u8)(args->value >> 8), args->value >> 0x10);
    }

    switch (op)
    {
    case 4:
    case 0:
        t = s1 + s2;
        break;
    case 1:
        t = s1 - s2;
        break;
    case 2:
        t = s1 * s2;
        break;
    case 3:
        t = s2 != 0 ? s1 / s2 : 0;
        break;
    }

    {
        u8 ctrl = args->flags >> 8;
        u8 index = args->flags >> 0x10;
        varSet(state, ctrl, index, (t < -0x8000 ? -0x8000 : t > 0x7fff ? 0x7fff : t));
    }
}

/*
 * Key off other voices in the same key group, optionally by immediate kill.
 */
void mcmdSendMessage(McmdVoiceState* state, McmdCommandArgs* args)
{
    u32 value;
    u32 targetInstrument;
    u8 i;
    McmdVoiceState* voiceState;

    value = mcmdVarGet32Legacy(state, 0, (args->value >> 8) & 0xff);

    if (((args->flags >> 8) & 0xff) == 0)
    {
        targetInstrument = args->flags >> 0x10;
        if (targetInstrument != 0xffff)
        {
            for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; i++)
            {
                if (synthVoice[i].addr != 0 &&
                    targetInstrument == synthVoice[i].macroId)
                {
                    macPostMessage(synthVoice[i].vidList->vid, value);
                }
            }
        }
        else
        {
            if (synthMessageCallback != 0)
            {
                synthMessageCallback(state->vidList->vid, value);
            }
        }
    }
    else
    {
        macPostMessage(mcmdVarGet32Legacy(state, 0, args->value), value);
    }
}

/*
 * Clear one trap stream and drop the trigger flag when none remain armed.
 */
static inline void mcmdUntrapEvent(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    u8 i;

    svoice->trapEventAddr[(cstep->flags >> 8) & 0xff] = 0;
    for (i = 0; i < 3; i++)
    {
        if (svoice->trapEventAddr[i] != 0)
        {
            return;
        }
    }
    svoice->trapEventAny = 0;
}

/*
 * Store the voice id (or clone list head) into a synth register.
 */
static inline void mcmdGetVID(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    if ((u8)(cstep->flags >> 0x10) == 0)
    {
        varSet32(svoice, 0, (u8)(cstep->flags >> 8), svoice->vidList->vid);
    }
    else
    {
        varSet32(svoice, 0, (u8)(cstep->flags >> 8), svoice->lastVID);
    }
}

static inline void mcmdAddPriority(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    s16 delta;
    s16 prio;

    delta = cstep->flags >> 0x10;
    prio = svoice->prio + delta;
    prio = prio < 0 ? 0 : prio > 0xff ? 0xff : prio;
    voiceSetPriority(svoice, prio);
}

static inline void mcmdSetAgeCounterByVolume(McmdVoiceState* svoice, McmdCommandArgs* cstep) {
    u32 age;

    age = (svoice->volume >> 0x10) & 0xff;
    age = (cstep->value & 0xffff) * age;
    age = (cstep->flags >> 0x10) + ((s32)age >> 7);
    svoice->age = age > 60000 ? 0x75300000 : age << 0xf;
    hwSetPriority(svoice->id & 0xff, ((u32)svoice->prio << 0x18) | (svoice->age >> 0xf));
}

static inline void mcmdIfVarCompare(McmdVoiceState* svoice, McmdCommandArgs* cstep, u8 cmp)
{
    s32 lhs;
    s32 rhs;
    u8 result;

    lhs = varGetReg(svoice, (cstep->flags >> 8) & 0xff, (cstep->flags >> 0x10) & 0xff);
    rhs = varGetReg(svoice, cstep->flags >> 0x18, (u8)cstep->value);

    switch (cmp)
    {
    case 0:
        result = !(rhs - lhs);
        break;
    case 1:
        result = lhs < rhs;
        break;
    }

    if ((cstep->value >> 8) & 0xff)
    {
        result = !result;
    }
    if (result != 0)
    {
        u16 step = cstep->value >> 0x10;
        svoice->curAddr = (u8*)((McmdCommandArgs*)svoice->addr + step);
    }
}

static inline void mcmdIfModulation(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    u8* macro;
    u8 mod;

    if (svoice->midi == 0xff)
    {
        return;
    }
    mod = inpGetModulation(svoice) >> 7;
    if (mod < (u8)(cstep->flags >> 8))
    {
        return;
    }

    if ((macro = dataGetMacro(cstep->flags >> 0x10)) != 0)
    {
        svoice->addr = macro;
        svoice->curAddr = macro + ((cstep->value & 0xffff) << 3);
    }
}

static inline void mcmdSRCModeSelect(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    hwSetSRCType(svoice->id & 0xff, (cstep->flags >> 8) & 0xff);
    hwSetPolyPhaseFilter(svoice->id & 0xff, (u8)(cstep->flags >> 0x10));
    MAC_CFLAGS(svoice) |= MAC_FLAG64(0x800, 0);
}

static inline void mcmdSendKeyOff(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    u32 voiceid;
    u32 i;

    voiceid = (svoice->orgNote + ((cstep->flags >> 8) & 0xff)) << 8;
    voiceid |= ((u16)(cstep->flags >> 0x10)) << 0x10;
    for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; i++)
    {
        if (synthVoice[i].id == (voiceid | i))
        {
            SendSingleKeyOff(voiceid | i);
        }
    }
}

/*
 * Assign a voice to a key group, evicting existing group members according to
 * the command's kill mode.
 */
void mcmdSetKeyGroup(McmdVoiceState* state, McmdCommandArgs* args)
{
    u32 i;
    u8 kg;
    u32 kill;
    McmdVoiceState* voice;

    state->keyGroup = 0;
    kg = (u8)(args->flags >> 8);
    kill = (u8)(args->flags >> 0x10) != 0;
    if (kg != 0)
    {
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; i++)
        {
            voice = &synthVoice[i];
            if (voice->addr != 0 && (MAC_CFLAGS(voice) & MAC_FLAG64(0, 2)) == 0 && kg == voice->keyGroup)
            {
                if (kill == 0)
                {
                    macSetExternalKeyoff(voice);
                }
                else
                {
                    voiceKill(i);
                }
            }
        }
        state->keyGroup = kg;
    }
}

/*
 * Run the active macro command stream for one voice.
 */
void macHandleActive(McmdVoiceState* sv)
{
    u32 ex;
    u32 cmd;
    u32* cmdValuePtr;
    u8 lastNote;
    u8* channelDefaults;
    f32 one;
    f32 dlsScaleMax;
    u32 unused;
    u8* dataTables = lbl_8032EDD0;

    if (MAC_CFLAGS(sv) & 3)
    {
        if (MAC_CFLAGS(sv) & 1)
        {
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 1);
            hwBreak(sv->id & 0xff);
        }

        sv->panning[0] = sv->panTarget[0] = sv->setup.pan << 16;
        sv->panning[1] = sv->panTarget[1] = 0;
        sv->volume = sv->setup.vol << 16;
        sv->volTable = 0;
        sv->orgVolume = sv->volume;
        sv->midi = sv->setup.midi;
        sv->midiSet = sv->setup.midiSet;
        sv->section = sv->setup.section;
        sv->track = sv->setup.track;
        sv->itdMode = sv->setup.itdMode;
        sv->keyGroup = 0;
        sv->vibModAddScale = 0;
        sv->treScale = 0;
        inpInit(sv);
        lastNote = inpGetMidiLastNote(sv->midi, sv->midiSet);
        if (lastNote != 0xff)
        {
            sv->lastNote = lastNote;
        }
        else
        {
            sv->lastNote = sv->orgNote;
        }

        inpSetMidiLastNote(sv->midi, sv->midiSet, sv->orgNote);
        voiceSetLastStarted(sv);
        sv->vGroup = sv->setup.vGroup;
        sv->studio = sv->setup.studio;
        sv->portTime = 0;
        sv->portDuration = 25600;
        sv->portType = 0;
        if (sv->midi != 0xff)
        {
            sv->portLastCtrlState = inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, sv->midi, sv->midiSet);
        }
        else
        {
            sv->portLastCtrlState = 0;
        }
        channelDefaults = inpGetChannelDefaults(sv->midi, sv->midiSet);
        sv->pbLowerKeyRange = channelDefaults[0];
        sv->pbUpperKeyRange = channelDefaults[0];
        sv->revVolScale = 128;
        sv->revVolOffset = 0;
        sv->loop = 0;
        sv->sweepNum[0] = 0;
        sv->sweepNum[1] = 0;
        sv->sweepOff[0] = 0;
        sv->sweepOff[1] = 0;
        sv->lfo[0].period = 0;
        sv->lfo[0].value = 0;
        sv->lfo[0].lastValue = 0x7fff;
        sv->lfo[1].period = 0;
        sv->lfo[1].value = 0;
        sv->lfo[1].lastValue = 0x7fff;
        sv->trapEventAddr[0] = 0;
        sv->trapEventAddr[1] = 0;
        sv->trapEventAddr[2] = 0;
        sv->trapEventAny = 0;
        sv->sInfo = 0xffffffff;
        sv->playFrq = 0xffffffff;
        sv->pbLast = 0x2000;
        sv->curOutputVolume = 0;
        MAC_CFLAGS(sv) &= MAC_FLAG64(0, 8);
        MAC_CFLAGS(sv) |= MAC_FLAG64(0x3000, 0);
        memset(sv->local_vars, 0, sizeof(sv->local_vars));
        *(u64*)&sv->waitTimeHi = macRealTime;
        *(u64*)&sv->macStartTimeHi = macRealTime;
        synthStartSynthJobHandling(sv);
    }

    macStepsThisFrame = 0;
    dlsScaleMax = sMacDlsScaleMax;
    one = sMacOne;
    cmdValuePtr = &macCurrentCmd.value;

    do
    {
        if (++macStepsThisFrame > 32)
        {
            break;
        }

        ex = 0;
        macCurrentCmd.flags = ((McmdCommandArgs*)sv->curAddr)->flags;
        *cmdValuePtr = ((McmdCommandArgs*)sv->curAddr)->value;
        sv->curAddr += 8;
        cmd = macCurrentCmd.flags;

        switch (cmd & 0x7f)
        {
        case 0x0: /* end of macro */
            vidRemoveVoiceReferences(sv);
            voiceFree(sv);
            ex = 1;
            break;
        case 0x1: /* stop */
            vidRemoveVoiceReferences(sv);
            voiceFree(sv);
            ex = 1;
            break;
        case 0x2: /* if key */
            if (sv->curNote >= (s32)((cmd >> 8) & 0xff))
            {
                u8* macro = dataGetMacro(cmd >> 0x10);
                if (macro != 0)
                {
                    sv->addr = macro;
                    sv->curAddr = macro + ((*cmdValuePtr & 0xffff) << 3);
                }
            }
            break;
        case 0x3: /* if velocity */
            if (((sv->volume >> 0x10) & 0xff) >= ((cmd >> 8) & 0xff))
            {
                u8* macro = dataGetMacro(cmd >> 0x10);
                if (macro != 0)
                {
                    sv->addr = macro;
                    sv->curAddr = macro + ((*cmdValuePtr & 0xffff) << 3);
                }
            }
            break;
        case 0x4: /* wait */
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        case 0x5: /* loop */
            mcmdLoop(sv, &macCurrentCmd);
            break;
        case 0x6: /* goto */
        {
            u8* macro = dataGetMacro(cmd >> 0x10);
            u32 stop;
            if (macro != 0)
            {
                sv->addr = macro;
                stop = 0;
                sv->curAddr = macro + ((*cmdValuePtr & 0xffff) << 3);
            }
            else
            {
                vidRemoveVoiceReferences(sv);
                voiceFree(sv);
                stop = 1;
            }
            ex = stop;
            break;
        }
        case 0x7: /* wait ms */
            ((u8*)cmdValuePtr)[2] = 1;
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        case 0x8: /* play macro */
            mcmdPlayMacro(sv, &macCurrentCmd);
            break;
        case 0x9: /* send key off */
            mcmdSendKeyOff(sv, &macCurrentCmd);
            break;
        case 0xa: /* if modulation */
            mcmdIfModulation(sv, &macCurrentCmd);
            break;
        case 0xb: /* set piano panning */
        {
            s32 delta;
            s32 scale;
            delta = (sv->curNote - (s32)((cmd >> 0x10) & 0xff)) << 0x10;
            scale = (s8)(u8)(cmd >> 8);
            delta = (delta * scale) >> 7;
            delta += ((u8)(cmd >> 0x18)) << 0x10;
            delta = delta < 0 ? 0 : delta > 0x7f0000 ? 0x7f0000 : delta;
            sv->panTarget[0] = delta;
            sv->panning[0] = delta;
            break;
        }
        case 0xc: /* set ADSR */
            mcmdSetADSR(sv, &macCurrentCmd);
            break;
        case 0xd: /* scale volume */
        {
            u16 scale = (u8)(cmd >> 8);
            u16 curve;
            if (((*cmdValuePtr >> 8) & 0xff) == 0)
            {
                sv->volume = (sv->volume * scale) / 0x7f;
            }
            else
            {
                sv->volume = (sv->orgVolume * scale) / 0x7f;
            }
            sv->volume += ((u8)(macCurrentCmd.flags >> 0x10)) << 0x10;
            if (sv->volume > 0x7f0000)
            {
                sv->volume = 0x7f0000;
            }
            curve = (u8)(macCurrentCmd.flags >> 0x18);
            curve |= ((u16)((u8)*cmdValuePtr) << 8);
            sv->volume = TranslateVolume(sv->volume, curve);
            MAC_CFLAGS(sv) |= MAC_FLAG64(0x1000, 0);
            break;
        }
        case 0xe: /* set panning */
            voiceConfigureParamRamp(sv, &macCurrentCmd, 0);
            break;
        case 0xf: /* envelope */
            mcmdScaleVolume(sv, &macCurrentCmd, sv->volume);
            break;
        case 0x10: /* start sample */
            mcmdStartSample(sv, &macCurrentCmd);
            break;
        case 0x11: /* stop sample */
            hwBreak(sv->id & 0xff);
            break;
        case 0x12: /* key off */
            MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x80);
            synthKeyStateUpdate(sv);
            break;
        case 0x13: /* if random */
            if ((u8)sndRand() >= ((macCurrentCmd.flags >> 8) & 0xff))
            {
                u8* macro = dataGetMacro(macCurrentCmd.flags >> 0x10);
                if (macro != 0)
                {
                    sv->addr = macro;
                    sv->curAddr = macro + ((*cmdValuePtr & 0xffff) << 3);
                }
            }
            break;
        case 0x14: /* fade in */
            mcmdScaleVolume(sv, &macCurrentCmd, 0);
            break;
        case 0x15: /* set surround panning */
            voiceConfigureParamRamp(sv, &macCurrentCmd, 1);
            break;
        case 0x16: /* set ADSR from ctrl */
        {
            f32 sScale;
            ADSR_INFO adsr;
            s32* row;
            sScale = voiceAdsrSustainTable[inpGetMidiCtrl(cmd >> 0x18, sv->midi, sv->midiSet) >> 7];
            row = (s32*)(dataTables +
                         (inpGetMidiCtrl((macCurrentCmd.flags >> 8) & 0xff, sv->midi, sv->midiSet) >> 7) * 4);
            adsr.data.dls.atime = row[7];
            row = (s32*)(dataTables +
                         (inpGetMidiCtrl((macCurrentCmd.flags >> 0x10) & 0xff, sv->midi, sv->midiSet) >> 7) *
                             4);
            adsr.data.dls.dtime = row[7];
            adsr.data.dls.slevel = 0xc1 - voiceAdsrDecayTable[(u32)(dlsScaleMax * sScale)];
            row = (s32*)(dataTables + (inpGetMidiCtrl((u8)*cmdValuePtr, sv->midi, sv->midiSet) >> 7) * 4);
            adsr.data.dls.rtime = row[7];
            adsr.data.dls.ascale = 0x80000000;
            adsr.data.dls.dscale = 0x80000000;
            hwSetADSR(sv->id & 0xff, &adsr, 2);
            MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x100);
            break;
        }
        case 0x17: /* random key */
            mcmdRandomKey(sv, &macCurrentCmd);
            break;
        case 0x18: /* add key */
            if ((cmd >> 0x18) == 0)
            {
                sv->curNote += (s8)((cmd >> 8) & 0xff);
            }
            else
            {
                sv->curNote = sv->orgNote + (s8)((cmd >> 8) & 0xff);
            }
            sv->curNote = (s16)sv->curNote < 0 ? 0 : sv->curNote > 0x7f ? 0x7f : sv->curNote;
            sv->curDetune = (s8)(macCurrentCmd.flags >> 0x10);
            if (voiceIsLastStarted(sv) != 0)
            {
                inpSetMidiLastNote(sv->midi, sv->midiSet, sv->curNote & 0xff);
            }
            macCurrentCmd.flags = 4;
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        case 0x19: /* set key */
            sv->curNote = (cmd >> 8) & 0x7f;
            sv->curDetune = (s8)(macCurrentCmd.flags >> 0x10);
            if (voiceIsLastStarted(sv) != 0)
            {
                inpSetMidiLastNote(sv->midi, sv->midiSet, sv->curNote & 0xff);
            }
            macCurrentCmd.flags = 4;
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        case 0x1a: /* last key */
            sv->curNote = sv->lastNote + (s8)((cmd >> 8) & 0xff);
            sv->curNote = (s16)sv->curNote < 0 ? 0 : sv->curNote > 0x7f ? 0x7f : sv->curNote;
            sv->curDetune = (s8)(macCurrentCmd.flags >> 0x10);
            if (sv->midi != 0xff)
            {
                inpSetMidiLastNote(sv->midi, sv->midiSet, sv->curNote & 0xff);
            }
            macCurrentCmd.flags = 4;
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        case 0x1b: /* portamento */
            mcmdPortamento(sv, &macCurrentCmd);
            break;
        case 0x1c: /* vibrato */
            mcmdVibrato(sv, &macCurrentCmd);
            break;
        case 0x1d: /* pitch sweep 1 */
        {
            s32 delta;
            sv->sweepOff[0] = 0;
            sv->sweepNum[0] = (macCurrentCmd.flags >> 8) & 0xff;
            sv->sweepCnt[0] = sv->sweepNum[0] << 0x10;
            delta = (s16)(macCurrentCmd.flags >> 0x10);
            if (delta >= 0)
            {
                delta = hwExitStream(delta);
            }
            else
            {
                delta = -hwExitStream(-delta);
            }
            sv->sweepAdd[0] = delta << 0x10;
            macCurrentCmd.flags = 0;
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        }
        case 0x1e: /* pitch sweep 2 */
        {
            s32 delta;
            sv->sweepOff[1] = 0;
            sv->sweepNum[1] = (macCurrentCmd.flags >> 8) & 0xff;
            sv->sweepCnt[1] = sv->sweepNum[1] << 0x10;
            delta = (s16)(macCurrentCmd.flags >> 0x10);
            if (delta >= 0)
            {
                delta = hwExitStream(delta);
            }
            else
            {
                delta = -hwExitStream(-delta);
            }
            sv->sweepAdd[1] = delta << 0x10;
            macCurrentCmd.flags = 0;
            ex = mcmdWait(sv, &macCurrentCmd);
            break;
        }
        case 0x1f: /* set pitch */
            sv->playFrq = cmd >> 8;
            sv->playFrq |= (u8)*cmdValuePtr;
            if (sv->sInfo != 0xffffffff)
            {
                DoSetPitch(sv);
            }
            break;
        case 0x20: /* set pitch ADSR */
            mcmdSetPitchADSR(sv, &macCurrentCmd);
            break;
        case 0x21: /* scale volume DLS */
        {
            u16 scale = (cmd >> 8) & 0xffff;
            if ((cmd >> 0x18) == 0)
            {
                sv->volume = ((sv->volume >> 5) * scale) >> 7;
            }
            else
            {
                sv->volume = ((sv->orgVolume >> 5) * scale) >> 7;
            }
            if (sv->volume > 0x7f0000)
            {
                sv->volume = 0x7f0000;
            }
            MAC_CFLAGS(sv) |= MAC_FLAG64(0x1000, 0);
            break;
        }
        case 0x22: /* set mod2vibrato */
            sv->vibModAddScale = (s8)(cmd >> 8) << 8;
            if (sv->vibModAddScale >= 0)
            {
                sv->vibModAddScale += ((s16)(s8)(macCurrentCmd.flags >> 0x10) << 8) / 100;
            }
            else
            {
                sv->vibModAddScale -= ((s16)(s8)(macCurrentCmd.flags >> 0x10) << 8) / 100;
            }
            break;
        case 0x23: /* setup tremolo */
            sv->treScale = (cmd >> 8) & 0xffff;
            sv->treModAddScale = *cmdValuePtr;
            sv->treCurScale = one;
            break;
        case 0x24: /* return */
            if (sv->callStackEntryNum != 0)
            {
                sv->addr = sv->callStack[sv->callStackIndex].addr;
                sv->curAddr = sv->callStack[sv->callStackIndex].curAddr;
                sv->callStackIndex = (sv->callStackIndex - 1) & 3;
                --sv->callStackEntryNum;
            }
            break;
        case 0x25: /* gosub */
        {
            u8* macro = dataGetMacro(cmd >> 0x10);
            u32 stop;
            if (macro != 0)
            {
                sv->callStackIndex = (sv->callStackIndex + 1) & 3;
                sv->callStack[sv->callStackIndex].addr = sv->addr;
                sv->callStack[sv->callStackIndex].curAddr = sv->curAddr;
                if (++sv->callStackEntryNum > 4)
                {
                    sv->callStackEntryNum = 4;
                }
                sv->addr = macro;
                stop = 0;
                sv->curAddr = macro + ((*cmdValuePtr & 0xffff) << 3);
            }
            else
            {
                vidRemoveVoiceReferences(sv);
                voiceFree(sv);
                stop = 1;
            }
            ex = stop;
            break;
        }
        case 0x28: /* trap event */
        {
            u8* macro = dataGetMacro(cmd >> 0x10);
            if (macro != 0)
            {
                u32 t = (macCurrentCmd.flags >> 8) & 0xff;
                sv->trapEventAddr[t] = macro;
                sv->trapEventCurAddr[t] = macro + ((macCurrentCmd.value & 0xffff) << 3);
                sv->trapEventAny = 1;
                if (t == 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0x100, 8)) == MAC_FLAG64(0x100, 8))
                {
                    MAC_CFLAGS(sv) |= MAC_FLAG64(0x400, 0);
                }
            }
            break;
        }
        case 0x29: /* untrap event */
            mcmdUntrapEvent(sv, &macCurrentCmd);
            break;
        case 0x2a: /* send message */
            mcmdSendMessage(sv, &macCurrentCmd);
            break;
        case 0x2b: /* get message */
        {
            u32 mesg = 0;
            if (sv->mesgNum != 0)
            {
                mesg = sv->mesgQueue[sv->mesgRead];
                sv->mesgRead = (sv->mesgRead + 1) & 3;
                --sv->mesgNum;
            }
            varSet32(sv, 0, (macCurrentCmd.flags >> 8) & 0xff, mesg);
            break;
        }
        case 0x2c: /* get VID */
            mcmdGetVID(sv, &macCurrentCmd);
            break;
        case 0x30: /* add age counter */
        {
            s32 age = (sv->age >> 0xf) + (s16)(cmd >> 0x10);
            if (age < 0)
            {
                sv->age = 0;
            }
            else if (age > 0xffff)
            {
                sv->age = 0x7fff8000;
            }
            else
            {
                sv->age = age << 0xf;
            }
            hwSetPriority(sv->id & 0xff, ((u32)sv->prio << 0x18) | (sv->age >> 0xf));
            break;
        }
        case 0x31: /* set age counter */
            sv->age = ((cmd >> 0x10) & 0xffff) << 0xf;
            hwSetPriority(sv->id & 0xff, ((u32)sv->prio << 0x18) | (sv->age >> 0xf));
            break;
        case 0x32: /* send flag */
            synthGlobalVariable[(cmd >> 8) & 0xff] = (cmd >> 0x10) & 0xff;
            break;
        case 0x33: /* set pitch wheel range */
            sv->pbLowerKeyRange = (cmd >> 0x10) & 0xff;
            sv->pbUpperKeyRange = (macCurrentCmd.flags >> 8) & 0xff;
            break;
        case 0x34: /* scale reverb */
            sv->revVolScale = (cmd >> 8) & 0xff;
            sv->revVolOffset = (macCurrentCmd.flags >> 0x10) & 0xff;
            break;
        case 0x35: /* pitchbend after key off */
            MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x10000);
            break;
        case 0x36: /* set priority */
            voiceSetPriority(sv, (cmd >> 8) & 0xff);
            break;
        case 0x37: /* add priority */
            mcmdAddPriority(sv, &macCurrentCmd);
            break;
        case 0x38: /* set age counter speed */
            if (*cmdValuePtr != 0)
            {
                sv->ageSpeed = (sv->age >> 8) / *cmdValuePtr;
            }
            else
            {
                sv->ageSpeed = 0;
            }
            break;
        case 0x39: /* set age counter by volume */
            mcmdSetAgeCounterByVolume(sv, &macCurrentCmd);
            break;
        case 0x40: /* volume select */
            SelectSource(sv, &sv->inpVolume, &macCurrentCmd, MAC_FLAG64(0, 0x80000), 1);
            break;
        case 0x41: /* panning select */
            SelectSource(sv, &sv->inpPanning, &macCurrentCmd, MAC_FLAG64(0, 0x100000), 2);
            break;
        case 0x42: /* pitch wheel select */
            SelectSource(sv, &sv->inpPitchBend, &macCurrentCmd, MAC_FLAG64(0, 0x200000), 8);
            break;
        case 0x43: /* mod wheel select */
            SelectSource(sv, &sv->inpModulation, &macCurrentCmd, MAC_FLAG64(0, 0x400000), 0x20);
            break;
        case 0x44: /* pedal select */
            SelectSource(sv, &sv->inpPedal, &macCurrentCmd, MAC_FLAG64(0, 0x2000000), 0x40);
            break;
        case 0x45: /* portamento select */
            SelectSource(sv, &sv->inpPortamento, &macCurrentCmd, MAC_FLAG64(0, 0x1000000), 0x80);
            break;
        case 0x46: /* reverb select */
            SelectSource(sv, &sv->inpReverb, &macCurrentCmd, MAC_FLAG64(0, 0x800000), 0x200);
            break;
        case 0x47: /* surround panning select */
            SelectSource(sv, &sv->inpSurroundPanning, &macCurrentCmd, MAC_FLAG64(0, 0x4000000), 4);
            break;
        case 0x48: /* doppler select */
            SelectSource(sv, &sv->inpDoppler, &macCurrentCmd, MAC_FLAG64(0, 0x8000000), 0x10);
            break;
        case 0x49: /* tremolo select */
            SelectSource(sv, &sv->inpTremolo, &macCurrentCmd, MAC_FLAG64(0, 0x10000000), 0x1000);
            break;
        case 0x4a: /* pre aux A select */
            SelectSource(sv, &sv->inpPreAuxA, &macCurrentCmd, MAC_FLAG64(0, 0x20000000), 0x100);
            break;
        case 0x4b: /* pre aux B select */
            SelectSource(sv, &sv->inpPreAuxB, &macCurrentCmd, MAC_FLAG64(0, 0x40000000), 0x400);
            break;
        case 0x4c: /* post aux B select */
            SelectSource(sv, &sv->inpPostAuxB, &macCurrentCmd, MAC_FLAG64(0, 0x80000000), 0x800);
            break;
        case 0x4d: /* aux A FX select */
        {
            u8 i = *cmdValuePtr >> 0x18;
            u64* mask = (u64*)(dataTables + i * 8);
            u32* dirty = (u32*)(dataTables + i * 4);
            SelectSource(sv, (McmdInputSlot*)((u8*)inpAuxA + sv->studio * 0x90 + i * 0x24), &macCurrentCmd, mask[68],
                         dirty[144]);
            break;
        }
        case 0x4e: /* aux B FX select */
        {
            u8 i = *cmdValuePtr >> 0x18;
            u64* mask = (u64*)(dataTables + i * 8);
            u32* dirty = (u32*)(dataTables + i * 4);
            SelectSource(sv, (McmdInputSlot*)((u8*)inpAuxB + sv->studio * 0x90 + i * 0x24), &macCurrentCmd, mask[74],
                         dirty[156]);
            break;
        }
        case 0x50: /* setup LFO */
        {
            u32 unused2;
            u32 phase;
            u32 time;
            u8 controllerIndex;

            controllerIndex = (u8)(macCurrentCmd.flags >> 8);
            time = (u16)(macCurrentCmd.flags >> 0x10);
            sndConvertMs(&time);
            if (sv->lfo[controllerIndex].period != 0)
            {
                phase = (u16)macCurrentCmd.value;
                sndConvertMs(&phase);
                sv->lfo[controllerIndex].time = phase;
            }
            sv->lfo[controllerIndex].period = time;
            break;
        }
        case 0x58: /* mode select */
            sv->volTable = ((cmd >> 8) & 0xff) != 0 ? 1 : 0;
            sv->itdMode = ((macCurrentCmd.flags >> 0x10) & 0xff) != 0 ? 0 : 1;
            break;
        case 0x59: /* set key group */
            mcmdSetKeyGroup(sv, &macCurrentCmd);
            break;
        case 0x5a: /* SRC mode select */
            mcmdSRCModeSelect(sv, &macCurrentCmd);
            break;
        case 0x60: /* var add */
            mcmdVarCalculation(sv, &macCurrentCmd, 0);
            break;
        case 0x61: /* var sub */
            mcmdVarCalculation(sv, &macCurrentCmd, 1);
            break;
        case 0x62: /* var mul */
            mcmdVarCalculation(sv, &macCurrentCmd, 2);
            break;
        case 0x63: /* var div */
            mcmdVarCalculation(sv, &macCurrentCmd, 3);
            break;
        case 0x64: /* var add randomized */
            mcmdVarCalculation(sv, &macCurrentCmd, 4);
            break;
        case 0x65: /* set var immediate */
        {
            u8 ctrl = (cmd >> 8) & 0xff;
            u8 index = (cmd >> 0x10) & 0xff;
            u32 unused3[4];
            varSet32(sv, ctrl, index, (s16)*cmdValuePtr);
            break;
        }
        case 0x70: /* if var equal */
            mcmdIfVarCompare(sv, &macCurrentCmd, 0);
            break;
        case 0x71: /* if var less */
            mcmdIfVarCompare(sv, &macCurrentCmd, 1);
            break;
        }
    } while (ex == 0);
}

/*
 * Advance the synth voice timer queue and process active voices.
 */
void macHandle(u32 deltaTime)
{
    McmdVoiceState* sv;
    McmdVoiceState* nextSv;
    u64 wakeTime;

    for (sv = macTimeQueueRoot; sv != 0 && *(u64*)&sv->waitHi <= macRealTime;)
    {
        nextSv = sv->nextTimeQueueMacro;
        wakeTime = *(u64*)&sv->waitHi;
        macMakeActive(sv);
        *(u64*)&sv->waitTimeHi = wakeTime;
        sv = nextSv;
    }

    for (sv = macActiveRoot; sv != 0; sv = sv->nextMacActive)
    {
        u32 hasTrap;
        if (sv->trapEventAny != 0)
        {
            hasTrap = sv->trapEventAddr[1] != 0;
        }
        else
        {
            hasTrap = 0;
        }
        if (hasTrap != 0)
        {
            if (!(MAC_CFLAGS(sv) & MAC_FLAG64(0, 0x20)) && hwIsActive(sv->id & 0xff) == 0)
            {
                ExecuteTrap(sv, 1);
            }
        }
        macHandleActive(sv);
    }

    macRealTime += deltaTime;
}

/*
 * Resume a yielded voice from its sample-end stream when needed.
 */
void macSampleEndNotify(McmdVoiceState* sv)
{
    if (sv->macState == MAC_STATE_YIELDED)
    {
        if (ExecuteTrap(sv, 1) == 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0, 0x40000)))
        {
            macMakeActive(sv);
        }
    }
}

/*
 * Mark a voice for key-off/release, falling back to its release stream.
 */
void macSetExternalKeyoff(McmdVoiceState* sv)
{
    MAC_CFLAGS(sv) |= MAC_FLAG64(0, 8);
    if (sv->addr != 0)
    {
        if (!(MAC_CFLAGS(sv) & MAC_FLAG64(0x100, 0)))
        {
            if (ExecuteTrap(sv, 0) == 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0, 4)))
            {
                macMakeActive(sv);
            }
        }
        else
        {
            MAC_CFLAGS(sv) |= MAC_FLAG64(0x400, 0);
        }
    }
}

/*
 * Set or clear the pedal hold state, releasing a deferred key-off.
 */
void macSetPedalState(McmdVoiceState* sv, u32 state)
{
    if (state != 0)
    {
        MAC_CFLAGS(sv) |= MAC_FLAG64(0x100, 0);
    }
    else
    {
        if (sv->addr != 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0x400, 0)))
        {
            if (ExecuteTrap(sv, 0) == 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0, 4)))
            {
                macMakeActive(sv);
            }
        }
        MAC_CFLAGS(sv) &= ~MAC_FLAG64(0x500, 0);
    }
}

/*
 * Insert a voice into the 64-bit wake-time queue sorted by 0x98:0x9c.
 */
void TimeQueueAdd(McmdVoiceState* state)
{
    McmdVoiceState* next;
    McmdVoiceState* prev;
    McmdVoiceState* cur;

    next = macTimeQueueRoot;
    prev = 0;
    while ((cur = next) != 0 && *(u64*)&cur->waitHi < *(u64*)&state->waitHi)
    {
        prev = cur;
        next = cur->nextTimeQueueMacro;
    }

    if (cur == 0)
    {
        if (prev == 0)
        {
            macTimeQueueRoot = state;
            state->nextTimeQueueMacro = 0;
            state->prevTimeQueueMacro = 0;
            return;
        }

        prev->nextTimeQueueMacro = state;
        state->prevTimeQueueMacro = prev;
        state->nextTimeQueueMacro = 0;
        return;
    }

    state->nextTimeQueueMacro = cur;
    prev = cur->prevTimeQueueMacro;
    state->prevTimeQueueMacro = prev;
    if (prev != 0)
    {
        cur->prevTimeQueueMacro->nextTimeQueueMacro = state;
    }
    else
    {
        macTimeQueueRoot = state;
    }
    cur->prevTimeQueueMacro = state;
}

/*
 * Remove a voice from the time queue and clear its scheduled wake time.
 */
void TimeQueueRemove(McmdVoiceState* sv, u32 disableUpdate)
{
    if (*(u64*)&sv->waitHi != 0)
    {
        if (*(u64*)&sv->waitHi != (u64)-1)
        {
            if (sv->prevTimeQueueMacro == 0)
            {
                macTimeQueueRoot = sv->nextTimeQueueMacro;
            }
            else
            {
                sv->prevTimeQueueMacro->nextTimeQueueMacro = sv->nextTimeQueueMacro;
            }
            if (sv->nextTimeQueueMacro != 0)
            {
                sv->nextTimeQueueMacro->prevTimeQueueMacro = sv->prevTimeQueueMacro;
            }
        }
        if (disableUpdate == 0)
        {
            synthForceLowPrecisionUpdate(sv);
        }
        *(u64*)&sv->waitHi = 0;
        *(u64*)&sv->waitTimeHi = macRealTime;
        MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 0x40004);
    }
}

/*
 * Move a yielded voice back onto the active voice list.
 */
void macMakeActive(McmdVoiceState* sv)
{
    if (sv->macState != MAC_STATE_RUNNABLE)
    {
        if (*(u64*)&sv->waitHi != 0)
        {
            if (*(u64*)&sv->waitHi != (u64)-1)
            {
                if (sv->prevTimeQueueMacro == 0)
                {
                    macTimeQueueRoot = sv->nextTimeQueueMacro;
                }
                else
                {
                    sv->prevTimeQueueMacro->nextTimeQueueMacro = sv->nextTimeQueueMacro;
                }
                if (sv->nextTimeQueueMacro != 0)
                {
                    sv->nextTimeQueueMacro->prevTimeQueueMacro = sv->prevTimeQueueMacro;
                }
            }
            synthForceLowPrecisionUpdate(sv);
            *(u64*)&sv->waitHi = 0;
            *(u64*)&sv->waitTimeHi = macRealTime;
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 0x40004);
        }
        if ((sv->nextMacActive = macActiveRoot) != 0)
        {
            ((McmdVoiceState*)macActiveRoot)->prevMacActive = sv;
        }
        sv->prevMacActive = 0;
        macActiveRoot = sv;
        sv->macState = MAC_STATE_RUNNABLE;
    }
}

/*
 * Detach a voice from the active list and move it to the requested scheduler
 * state.
 */
void macMakeInactive(McmdVoiceState* sv, int newState)
{
    if (sv->macState == newState)
    {
        return;
    }

    if (sv->macState == MAC_STATE_RUNNABLE)
    {
        if (sv->prevMacActive == 0)
        {
            macActiveRoot = sv->nextMacActive;
        }
        else
        {
            sv->prevMacActive->nextMacActive = sv->nextMacActive;
        }
        if (sv->nextMacActive != 0)
        {
            sv->nextMacActive->prevMacActive = sv->prevMacActive;
        }
    }

    if (newState == 2)
    {
        if (*(u64*)&sv->waitHi != 0)
        {
            if (*(u64*)&sv->waitHi != (u64)-1)
            {
                if (sv->prevTimeQueueMacro == 0)
                {
                    macTimeQueueRoot = sv->nextTimeQueueMacro;
                }
                else
                {
                    sv->prevTimeQueueMacro->nextTimeQueueMacro = sv->nextTimeQueueMacro;
                }
                if (sv->nextTimeQueueMacro != 0)
                {
                    sv->nextTimeQueueMacro->prevTimeQueueMacro = sv->prevTimeQueueMacro;
                }
            }
            *(u64*)&sv->waitHi = 0;
            *(u64*)&sv->waitTimeHi = macRealTime;
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 0x40004);
        }
    }
    sv->macState = newState;
}

/*
 * Allocate a voice and start a macro on it.
 */
u32 macStart(u16 macid, u8 priority, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 panning, u8 midi, u8 midiSet,
             u8 section, u16 step, u16 trackid, u8 new_vid, u8 vGroup, u8 studio, u32 itd)
{
    u32 voice;
    u32 vid;
    s32 fxFlag;
    u8* addr;
    McmdVoiceState* sv;
    u16 seqPrio;

    if ((addr = dataGetMacro(macid)) != 0)
    {
        fxFlag = key & 0x80;
        if (!fxFlag && (seqPrio = seqGetMIDIPriority(midiSet, midi)) != 0xffff)
        {
            priority = seqPrio;
        }

        if ((voice = voiceAllocate(priority, maxVoices, allocId, fxFlag != 0 ? 1 : 0)) != 0xffffffff)
        {
            sv = &synthVoice[voice];
            vidRemoveVoiceReferences(sv);
            if (sv->macState != MAC_STATE_STOPPED)
            {
                if (sv->macState == MAC_STATE_RUNNABLE)
                {
                    if (sv->prevMacActive == 0)
                    {
                        macActiveRoot = sv->nextMacActive;
                    }
                    else
                    {
                        sv->prevMacActive->nextMacActive = sv->nextMacActive;
                    }
                    if (sv->nextMacActive != 0)
                    {
                        sv->nextMacActive->prevMacActive = sv->prevMacActive;
                    }
                }
                TimeQueueRemove(sv, 1);
                sv->macState = MAC_STATE_STOPPED;
            }
            MAC_CFLAGS(sv) = (MAC_CFLAGS(sv) & MAC_FLAG64(0, 0x10)) | MAC_FLAG64(0, 2);

            if (hwIsActive(voice))
            {
                sv->cFlagsLo |= 1;
            }

            *(u64*)&sv->waitHi = 0;

            if (fxFlag != 0)
            {
                sv->fxFlag = 1;
                key &= 0x7f;
                inpResetMidiCtrl((u8)voice, 0xff, 1);
                inpResetChannelDefaults((u8)voice, 0xff);
                sv->setup.midi = voice;
                sv->setup.midiSet = 0xff;
                sv->setup.section = 0;
            }
            else
            {
                sv->fxFlag = 0;
                sv->setup.midi = midi;
                sv->setup.midiSet = midiSet;
                sv->setup.section = section;
            }

            sv->macroId = macid;
            sv->allocId = allocId;
            sv->age = 0x75300000;
            sv->ageSpeed = 0x400;
            sv->addr = addr;
            sv->curAddr = addr + (step << 3);
            sv->orgNote = key;
            sv->curNote = key;
            sv->curDetune = 0;
            sv->setup.vol = vol;
            sv->setup.pan = panning;
            sv->setup.track = trackid;
            sv->callStackEntryNum = 0;
            sv->callStackIndex = 0;
            sv->child = 0xffffffff;
            sv->parent = 0xffffffff;
            sv->lastVID = 0xffffffff;
            sv->setup.vGroup = vGroup;
            sv->setup.studio = studio;
            sv->setup.itdMode = itd != 0 ? 0 : 1;
            sv->mesgWrite = 0;
            sv->mesgRead = 0;
            sv->mesgNum = 0;
            sv->id = voice | ((macid << 0x10) | ((key & 0xff) << 8));
            voiceSetPriority(sv, priority);

            if ((vid = vidMakeNew(sv, new_vid)) != 0xffffffff)
            {
                if (sv->macState != MAC_STATE_RUNNABLE)
                {
                    TimeQueueRemove(sv, 0);
                    if ((sv->nextMacActive = macActiveRoot) != 0)
                    {
                        ((McmdVoiceState*)macActiveRoot)->prevMacActive = sv;
                    }
                    sv->prevMacActive = 0;
                    macActiveRoot = sv;
                    sv->macState = MAC_STATE_RUNNABLE;
                }
                return vid;
            }

            if (hwIsActive(voice))
            {
                hwBreak(voice);
            }
            voiceFree(sv);
        }
    }

    return 0xffffffff;
}

/*
 * Reset the macro scheduler state and every voice slot.
 */
void macInit(void)
{
    u32 i;

    macActiveRoot = 0;
    macTimeQueueRoot = 0;
    macRealTime = 0;
    for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; i++)
    {
        synthVoice[i].addr = 0;
        synthVoice[i].macState = MAC_STATE_STOPPED;
        synthVoice[i].loop = 0;
    }
}

const f32 sMacDlsScaleMax = 1023.0f;
const f32 sMacOne = 1.0f;
