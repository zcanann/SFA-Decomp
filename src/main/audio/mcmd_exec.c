#include "main/audio/inp_midi.h"
#include "main/audio/mcmd_exec.h"
#include "main/audio/voice_prio.h"
#include "main/audio/mcmd_volume.h"
#include "main/audio/inp_ctrl.h"
#include "main/audio/data_tables.h"
#include "main/audio/snd_synth_api.h"
#include "main/audio/voice_alloc.h"
#include "main/audio/voice_id.h"
#include "main/audio/hw_init.h"
#include "main/audio/synth_channel_scale.h"
#include "main/audio/mcmd_wait.h"
extern int mcmdLoop();
extern u8* synthVoice;
extern u8 lbl_803BD150[];
extern int macActiveRoot;
extern int macTimeQueueRoot;
extern int macRealTimeHi;
extern int macRealTimeLo;
extern void synthQueueVoicePrimaryUpdates(void* state);
extern void voiceKill(u32 voice);
extern u32 lbl_803BDA34[];
extern u32 voiceIsRegistered(int state);
extern void (*synthMessageCallback)(u32 id);

#define SYNTH_VOICE_STRIDE 0x404
#define SYNTH_GLOBAL_REG(index) (lbl_803BDA34[(index) - 0x10])

/* 64-bit control-flag word overlaying inputFlags(hi)/outputFlags(lo). */
#define MAC_CFLAGS(sv) (*(u64 *)&(sv)->inputFlags)
#define MAC_FLAG64(hi, lo) (((u64)(hi) << 32) | (u64)(lo))

/* Constant tables in this unit's data block (lbl_8032EDD0). */
typedef struct MacDataTables
{
    u16 pitchRatioTab[14]; /* 0x000 */
    s32 midi2TimeTab[128]; /* 0x01C */
    u8 pad21C[4]; /* 0x21C */
    u64 auxAMask[4]; /* 0x220 */
    u32 auxADirty[4]; /* 0x240 */
    u64 auxBMask[4]; /* 0x250 */
    u32 auxBDirty[4]; /* 0x270 */
} MacDataTables;

extern u8 lbl_8032EDD0[];
extern u8 lbl_803BDA74[]; /* per-studio aux B input slots */
extern u8 lbl_803BDEF4[]; /* per-studio aux A input slots */
extern u8 lbl_803DE2D0; /* macro steps executed this frame */
extern McmdCommandArgs lbl_803DE2E8; /* current macro step */
extern f32 lbl_803E7810; /* 1023.0f */
extern f32 lbl_803E7814; /* 1.0f */
extern f32 voiceAdsrSustainTable[];
extern u8 voiceAdsrDecayTable[];
extern void synthQueueVoiceInputUpdate(McmdVoiceState * state);
extern void fn_802712C8(McmdVoiceState * state); /* synthStartSynthJobHandling */

/*
 * Choose a randomized note/velocity command and dispatch it through the
 * normal set-key handler.
 */
void mcmdRandomKey(McmdVoiceState* state, McmdCommandArgs* args)
{
    u8 t;
    s32 i1;
    s32 i2;
    u8 detune;
    u8 k1;
    u8 k2;

    if (((args->value >> 8) & 0xff) == 0)
    {
        k2 = args->flags >> 0x18;
        k1 = args->flags >> 8;
        detune = args->flags >> 0x18;
        if (((args->flags >> 8) & 0xff) > detune)
        {
            t = k1;
            k1 = k2;
            k2 = t;
        }
    }
    else
    {
        i1 = state->key - (s32)((args->flags >> 8) & 0xff);
        i2 = state->key + (args->flags >> 0x18);
        k1 = i1 < 0 ? 0 : i1 > 0x7f ? 0x7f : i1;
        k2 = i2 < 0 ? 0 : i2 > 0x7f ? 0x7f : i2;
    }

    if ((u8)args->value != 0)
    {
        detune = (sndRand() % 0xc9) - 100;
    }
    else
    {
        detune = (args->flags >> 0x10) & 0xff;
    }

    args->flags = (detune << 0x10) | 0x19 | ((k1 + (sndRand() % (((u8)k2 - k1) + 1))) << 8);
    args->value = 0;
    state->key = (args->flags >> 8) & 0x7f;
    state->fineTune = (s8)(args->flags >> 0x10);
    if (voiceIsRegistered((int)state) != 0)
    {
        inpSetMidiLastNote(state->midiSlot, state->midiEvent, state->key & 0xff);
    }
    args->flags = 4;
    mcmdWait(state, args);
}

/*
 * Queue a controller event and mark the owning MIDI/global dirty flag.
 */
void SelectSource(McmdVoiceState* svoice, McmdInputSlot* dest, McmdCommandArgs* cstep,
                  u64 tstflag, u32 dirtyFlag)
{
    int comb;
    s32 scale;
    int destAddr;

    if ((MAC_CFLAGS(svoice) & tstflag) == 0)
    {
        comb = 0;
        MAC_CFLAGS(svoice) |= tstflag;
    }
    else
    {
        comb = cstep->value & 0xff;
    }

    scale = (s32)(cstep->flags & 0xffff0000) / 100;
    if (scale < 0)
    {
        scale -= ((s8)(cstep->value >> 0x10) << 8) / 100;
    }
    else
    {
        scale += ((s8)(cstep->value >> 0x10) << 8) / 100;
    }

    destAddr = (int)dest;
    inpAddCtrl(destAddr, (cstep->flags >> 8) & 0xff, scale, comb,
               (u8)(cstep->value >> 8) != 0);

    if (dirtyFlag & 0x80000000)
    {
        inpSetGlobalMIDIDirtyFlag(svoice->midiSlot, svoice->midiEvent, dirtyFlag);
    }
    else
    {
        svoice->inputDirtyFlags |= dirtyFlag;
    }
}

/*
 * Configure the portamento controller ramp trigger for the current voice.
 */
void mcmdPortamento(McmdVoiceState* state, McmdCommandArgs* args)
{
    u32 time;

    state->portamentoMode = (args->flags >> 0x10) & 0xff;
    time = args->value >> 0x10;
    if ((args->value >> 8) & 1)
    {
        sndConvertMs(&time);
    }
    else
    {
        sndConvertTicks(&time, (int)state);
    }

    state->portamentoDuration = time;

    switch ((args->flags >> 8) & 0xff)
    {
    case 0:
        if (state->midiSlot != 0xff)
        {
            inpSetMidiCtrl(0x41, state->midiSlot, state->midiEvent, 0);
        }
        MAC_CFLAGS(state) &= ~MAC_FLAG64(0, 0x400);
        return;
    case 1:
        if (state->midiSlot != 0xff)
        {
            inpSetMidiCtrl(0x41, state->midiSlot, state->midiEvent, 0x7f);
        }
    init_port:
        if (!(MAC_CFLAGS(state) & MAC_FLAG64(0, 0x400)))
        {
            fn_8026F5B8((int)state);
        }
        state->outputFlags |= 0x400;
        break;
    case 2:
        if (state->midiSlot != 0xff &&
            (u16)inpGetMidiCtrl(0x41, state->midiSlot, state->midiEvent) > 0x1f80)
        {
            goto init_port;
        }
        break;
    }
}

/*
 * Perform 16-bit register arithmetic with saturation.
 */
void mcmdVarCalculation(McmdVoiceState* state, McmdCommandArgs* args, u8 op)
{
    s32 t;
    s16 s1;
    s16 s2;

    s1 = varGet32(state, args->flags >> 0x18, (u8)args->value);
    if (op == 4)
    {
        s2 = args->value >> 8;
    }
    else
    {
        s2 = varGet32(state, (args->value >> 8) & 0xff, (args->value >> 0x10) & 0xff);
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

    varSet32(state, (args->flags >> 8) & 0xff, (args->flags >> 0x10) & 0xff,
             (s16)(t < -0x8000 ? -0x8000 : t > 0x7fff ? 0x7fff : t));
}

/*
 * Read a 32-bit synth register, either from the voice or EX controller bank.
 */
u32 varGet32(McmdVoiceState* state, u32 useExCtrl, u32 index)
{
    if (useExCtrl != 0)
    {
        return (u16)inpGetExCtrl(state, index);
    }
    index &= 0x1f;
    if (index < 0x10)
    {
        return state->localRegs[index];
    }
    return SYNTH_GLOBAL_REG(index);
}

/*
 * Read a signed 16-bit synth register.
 */
int varGet(McmdVoiceState* state, u32 useExCtrl, u32 index)
{
    u32 value;

    if (useExCtrl != 0)
    {
        value = (u16)inpGetExCtrl(state, index);
    }
    else
    {
        index &= 0x1f;
        if (index < 0x10)
        {
            value = state->localRegs[index];
        }
        else
        {
            value = SYNTH_GLOBAL_REG(index);
        }
    }
    return (s16)value;
}

/*
 * Write a synth register, routing high registers to the EX controller bank.
 */
#pragma dont_inline on
void varSet32(McmdVoiceState* state, u32 useExCtrl, u32 index, u32 value)
{
    if (useExCtrl != 0)
    {
        inpSetExCtrl(state, index, value);
        return;
    }
    index &= 0x1f;
    if (index < 0x10)
    {
        state->localRegs[index] = value;
        return;
    }
    SYNTH_GLOBAL_REG(index) = value;
}
#pragma dont_inline reset

/*
 * Queue register-derived messages onto voices found through vid handles.
 */
void mcmdSendMessage(McmdVoiceState* state, McmdCommandArgs* args)
{
    u32 index;
    u32 value;
    u32 targetInstrument;
    int offset;
    int voice;
    McmdVoiceState* voiceState;
    u8 i;
    u32 targetVoice;

    value = varGet32(state, 0, (args->value >> 8) & 0xff);

    if (((args->flags >> 8) & 0xff) == 0)
    {
        targetInstrument = args->flags >> 0x10;
        if (targetInstrument != 0xffff)
        {
            offset = 0;
            for (i = 0; i < lbl_803BD150[0x210]; i++)
            {
                voice = (int)(synthVoice + offset);
                voiceState = (McmdVoiceState*)voice;
                if (voiceState->macroBase != 0 && targetInstrument == voiceState->instrumentKey)
                {
                    targetVoice = vidGetInternalId(voiceState->vidListNode->id);
                    if (targetVoice != 0xffffffff)
                    {
                        voice = (int)(synthVoice + (targetVoice & 0xff) * SYNTH_VOICE_STRIDE);
                        voiceState = (McmdVoiceState*)voice;
                        if (voiceState->queuedMessageCount < 4)
                        {
                            voiceState->queuedMessageCount = voiceState->queuedMessageCount + 1;
                            voiceState->queuedMessages[voiceState->queuedMessageWriteIndex] = value;
                            voiceState->queuedMessageWriteIndex =
                                (voiceState->queuedMessageWriteIndex + 1) & 3;
                            if (voiceState->hasTriggerMacros != 0 &&
                                voiceState->messageMacroBase != 0)
                            {
                                voiceState->macroCursor = voiceState->messageMacroCursor;
                                voiceState->macroBase = voiceState->messageMacroBase;
                                voiceState->messageMacroBase = 0;
                                macMakeActive((McmdVoiceState*)voice);
                            }
                        }
                    }
                }
                offset += SYNTH_VOICE_STRIDE;
            }
        }
        else
        {
            if (synthMessageCallback != 0)
            {
                synthMessageCallback(state->vidListNode->id);
            }
        }
    }
    else
    {
        targetVoice = vidGetInternalId(varGet32(state, 0, args->value));
        if (targetVoice != 0xffffffff)
        {
            voice = (int)(synthVoice + (targetVoice & 0xff) * SYNTH_VOICE_STRIDE);
            voiceState = (McmdVoiceState*)voice;
            if (voiceState->queuedMessageCount < 4)
            {
                voiceState->queuedMessageCount = voiceState->queuedMessageCount + 1;
                voiceState->queuedMessages[voiceState->queuedMessageWriteIndex] = value;
                voiceState->queuedMessageWriteIndex =
                    (voiceState->queuedMessageWriteIndex + 1) & 3;
                if (voiceState->hasTriggerMacros != 0 && voiceState->messageMacroBase != 0)
                {
                    voiceState->macroCursor = voiceState->messageMacroCursor;
                    voiceState->macroBase = voiceState->messageMacroBase;
                    voiceState->messageMacroBase = 0;
                    macMakeActive((McmdVoiceState*)voice);
                }
            }
        }
    }
}

/*
 * Key off other voices in the same key group, optionally by immediate kill.
 */
void mcmdSetKeyGroup(McmdVoiceState* state, McmdCommandArgs* args)
{
    u32 i;
    int off;
    u32 kg;
    u32 kill;
    McmdVoiceState* voice;

    off = 0;
    state->keyGroup = 0;
    kg = (args->flags >> 8) & 0xff;
    kill = ((args->flags >> 0x10) & 0xff) != 0;
    if (kg != 0)
    {
        for (i = 0; i < lbl_803BD150[0x210]; off += SYNTH_VOICE_STRIDE, i++)
        {
            voice = (McmdVoiceState*)(synthVoice + off);
            if (voice->macroBase != 0 && (MAC_CFLAGS(voice) & MAC_FLAG64(0, 2)) == 0 &&
                kg == voice->keyGroup)
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
 * Run the active macro command stream for one voice (MusyX macHandleActive).
 */
void macHandleActive(McmdVoiceState* sv)
{
    u32 ex;
    u32 cmd;
    u32* para1;
    int lastNote;
    u8* channelDefaults;
    f32 dlsScaleMax;
    f32 one;

    if (MAC_CFLAGS(sv) & 3)
    {
        if (MAC_CFLAGS(sv) & 1)
        {
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 1);
            hwBreak(sv->voiceHandle & 0xff);
        }

        sv->paramCurrent[0] = sv->paramTarget[0] = sv->startupPan << 16;
        sv->paramCurrent[1] = sv->paramTarget[1] = 0;
        sv->volume = sv->startupVolume << 16;
        sv->volTable = 0;
        sv->volumeBase = sv->volume;
        sv->midiSlot = sv->startupMidiSlot;
        sv->midiEvent = sv->startupMidiEvent;
        sv->midiLayer = sv->startupMidiLayer;
        sv->track = sv->startupTrack;
        sv->itdMode = sv->startupDeferStart;
        sv->keyGroup = 0;
        sv->vibratoModAddScale = 0;
        sv->tremoloScale = 0;
        inpInit((u32)sv);
        lastNote = inpGetMidiLastNote(sv->midiSlot, sv->midiEvent);
        if ((u8)lastNote != 0xff)
        {
            sv->registeredKey = lastNote;
        }
        else
        {
            sv->registeredKey = sv->keyBase;
        }

        inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->keyBase);
        voiceRegister((int)sv);
        sv->vGroup = sv->startupVGroup;
        sv->studio = sv->startupStudio;
        sv->portamentoTime = 0;
        sv->portamentoDuration = 25600;
        sv->portamentoMode = 0;
        if (sv->midiSlot != 0xff)
        {
            sv->portamentoCtrlValue = inpGetMidiCtrl(0x41, sv->midiSlot, sv->midiEvent);
        }
        else
        {
            sv->portamentoCtrlValue = 0;
        }
        channelDefaults = inpGetChannelDefaults(sv->midiSlot, sv->midiEvent);
        sv->pitchBendRangeUp = channelDefaults[0];
        sv->pitchBendRangeDown = channelDefaults[0];
        sv->revVolScale = 128;
        sv->revVolOffset = 0;
        sv->loopCounter = 0;
        sv->sweepNum[0] = 0;
        sv->sweepNum[1] = 0;
        sv->sweepOff[0] = 0;
        sv->sweepOff[1] = 0;
        sv->exCtrls[0].rampFrames = 0;
        sv->exCtrls[0].value = 0;
        sv->exCtrls[0].limit = 0x7fff;
        sv->exCtrls[1].rampFrames = 0;
        sv->exCtrls[1].value = 0;
        sv->exCtrls[1].limit = 0x7fff;
        sv->trapMacroBase[0] = 0;
        sv->trapMacroBase[1] = 0;
        sv->trapMacroBase[2] = 0;
        sv->hasTriggerMacros = 0;
        sv->prevSampleId = 0xffffffff;
        sv->targetPitch = 0xffffffff;
        sv->pitchBend = 0x2000;
        sv->curOutputVolume = 0;
        MAC_CFLAGS(sv) &= MAC_FLAG64(0, 8);
        MAC_CFLAGS(sv) |= MAC_FLAG64(0x3000, 0);
        memset(sv->localRegs, 0, sizeof(sv->localRegs));
        *(u64*)&sv->activeTimeHi = *(u64*)&macRealTimeHi;
        *(u64*)&sv->startTimeHi = *(u64*)&macRealTimeHi;
        fn_802712C8(sv);
    }

    lbl_803DE2D0 = 0;
    dlsScaleMax = lbl_803E7810;
    one = lbl_803E7814;
    para1 = &lbl_803DE2E8.value;

    do
    {
        if (++lbl_803DE2D0 > 32)
        {
            break;
        }

        ex = 0;
        lbl_803DE2E8.flags = ((McmdCommandArgs*)sv->macroCursor)->flags;
        *para1 = ((McmdCommandArgs*)sv->macroCursor)->value;
        sv->macroCursor += 8;
        cmd = lbl_803DE2E8.flags;

        switch (cmd & 0x7f)
        {
        case 0x0: /* end of macro */
            vidRemoveVoice((int)sv);
            voiceFree((int)sv);
            ex = 1;
            break;
        case 0x1: /* stop */
            vidRemoveVoice((int)sv);
            voiceFree((int)sv);
            ex = 1;
            break;
        case 0x2: /* if key */
            if (sv->key >= (s32)((cmd >> 8) & 0xff))
            {
                u8* macro = dataGetMacro(cmd >> 0x10);
                if (macro != 0)
                {
                    sv->macroBase = macro;
                    sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                }
            }
            break;
        case 0x3: /* if velocity */
            if (((sv->volume >> 0x10) & 0xff) >= ((cmd >> 8) & 0xff))
            {
                u8* macro = dataGetMacro(cmd >> 0x10);
                if (macro != 0)
                {
                    sv->macroBase = macro;
                    sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                }
            }
            break;
        case 0x4: /* wait */
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x5: /* loop */
            mcmdLoop(sv, &lbl_803DE2E8);
            break;
        case 0x6: /* goto */
            {
                u8* macro = dataGetMacro(cmd >> 0x10);
                u32 stop;
                if (macro != 0)
                {
                    sv->macroBase = macro;
                    stop = 0;
                    sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                }
                else
                {
                    vidRemoveVoice((int)sv);
                    voiceFree((int)sv);
                    stop = 1;
                }
                ex = stop;
                break;
            }
        case 0x7: /* wait ms */
            ((u8*)para1)[2] = 1;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x8: /* play macro */
            mcmdPlayMacro(sv, &lbl_803DE2E8);
            break;
        case 0x9: /* send key off */
            {
                u32 voiceid;
                u32 i;
                int off;
                voiceid = (sv->keyBase + ((cmd >> 8) & 0xff)) << 8;
                voiceid |= (cmd >> 0x10) << 0x10;
                i = 0;
                off = 0;
                for (; i < lbl_803BD150[0x210]; off += SYNTH_VOICE_STRIDE, i++)
                {
                    u32 id = voiceid | i;
                    if (((McmdVoiceState*)(synthVoice + off))->voiceHandle == id)
                    {
                        if (id != 0xffffffff)
                        {
                            u32 slot = id & 0xff;
                            if (((McmdVoiceState*)(synthVoice + slot * SYNTH_VOICE_STRIDE))->voiceHandle == id)
                            {
                                macSetExternalKeyoff((McmdVoiceState*)(synthVoice + slot * SYNTH_VOICE_STRIDE));
                            }
                        }
                    }
                }
                break;
            }
        case 0xa: /* if modulation */
            if (sv->midiSlot != 0xff)
            {
                u32 mod = (inpGetModulation(sv) >> 7) & 0xff;
                if (mod >= ((lbl_803DE2E8.flags >> 8) & 0xff))
                {
                    u8* macro = dataGetMacro(lbl_803DE2E8.flags >> 0x10);
                    if (macro != 0)
                    {
                        sv->macroBase = macro;
                        sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                    }
                }
            }
            break;
        case 0xb: /* set piano panning */
            {
                s32 delta;
                s32 scale;
                delta = (sv->key - (s32)((cmd >> 0x10) & 0xff)) << 0x10;
                scale = (s8)(cmd >> 8);
                delta = (delta * scale) >> 7;
                delta += ((u8)(cmd >> 0x18)) << 0x10;
                delta = delta < 0 ? 0 : delta > 0x7f0000 ? 0x7f0000 : delta;
                sv->paramTarget[0] = delta;
                sv->paramCurrent[0] = delta;
                break;
            }
        case 0xc: /* set ADSR */
            mcmdSetADSR(sv, &lbl_803DE2E8);
            break;
        case 0xd: /* scale volume */
            {
                u16 scale = (u8)(cmd >> 8);
                u16 curve;
                if (((*para1 >> 8) & 0xff) == 0)
                {
                    sv->volume = (sv->volume * scale) / 0x7f;
                }
                else
                {
                    sv->volume = (sv->volumeBase * scale) / 0x7f;
                }
                sv->volume += ((u8)(lbl_803DE2E8.flags >> 0x10)) << 0x10;
                if (sv->volume > 0x7f0000)
                {
                    sv->volume = 0x7f0000;
                }
                curve = (lbl_803DE2E8.flags >> 0x18) | ((*para1 & 0xff) << 8);
                sv->volume = TranslateVolume(sv->volume, curve);
                MAC_CFLAGS(sv) |= MAC_FLAG64(0x1000, 0);
                break;
            }
        case 0xe: /* set panning */
            voiceConfigureParamRamp(sv, &lbl_803DE2E8, 0);
            break;
        case 0xf: /* envelope */
            mcmdScaleVolume(sv, &lbl_803DE2E8, sv->volume);
            break;
        case 0x10: /* start sample */
            mcmdStartSample(sv, &lbl_803DE2E8);
            break;
        case 0x11: /* stop sample */
            hwBreak(sv->voiceHandle & 0xff);
            break;
        case 0x12: /* key off */
            MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x80);
            synthQueueVoiceInputUpdate(sv);
            break;
        case 0x13: /* if random */
            if ((u8)sndRand() >= ((lbl_803DE2E8.flags >> 8) & 0xff))
            {
                u8* macro = dataGetMacro(lbl_803DE2E8.flags >> 0x10);
                if (macro != 0)
                {
                    sv->macroBase = macro;
                    sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                }
            }
            break;
        case 0x14: /* fade in */
            mcmdScaleVolume(sv, &lbl_803DE2E8, 0);
            break;
        case 0x15: /* set surround panning */
            voiceConfigureParamRamp(sv, &lbl_803DE2E8, 1);
            break;
        case 0x16: /* set ADSR from ctrl */
            {
                f32 sScale;
                McmdDlsAdsrInfo adsr;
                sScale = voiceAdsrSustainTable[(u16)inpGetMidiCtrl(cmd >> 0x18, sv->midiSlot, sv->midiEvent) >> 7];
                adsr.atime = ((MacDataTables*)lbl_8032EDD0)
                    ->midi2TimeTab[(u16)inpGetMidiCtrl((lbl_803DE2E8.flags >> 8) & 0xff,
                                                       sv->midiSlot, sv->midiEvent) >> 7];
                adsr.dtime = ((MacDataTables*)lbl_8032EDD0)
                    ->midi2TimeTab[(u16)inpGetMidiCtrl((lbl_803DE2E8.flags >> 0x10) & 0xff,
                                                       sv->midiSlot, sv->midiEvent) >> 7];
                adsr.slevel = 0xc1 - voiceAdsrDecayTable[(u32)(dlsScaleMax * sScale)];
                adsr.rtime = ((MacDataTables*)lbl_8032EDD0)
                    ->midi2TimeTab[(u16)inpGetMidiCtrl((u8) * para1, sv->midiSlot,
                                                       sv->midiEvent) >> 7];
                adsr.ascale = 0x80000000;
                adsr.dscale = 0x80000000;
                hwSetADSR(sv->voiceHandle & 0xff, &adsr, 2);
                MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x100);
                break;
            }
        case 0x17: /* random key */
            mcmdRandomKey(sv, &lbl_803DE2E8);
            break;
        case 0x18: /* add key */
            if ((cmd >> 0x18) == 0)
            {
                sv->key += (s8)((cmd >> 8) & 0xff);
            }
            else
            {
                sv->key = sv->keyBase + (s8)((cmd >> 8) & 0xff);
            }
            sv->key = (s16)sv->key < 0 ? 0 : sv->key > 0x7f ? 0x7f : sv->key;
            sv->fineTune = (s8)(lbl_803DE2E8.flags >> 0x10);
            if (voiceIsRegistered((int)sv) != 0)
            {
                inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->key & 0xff);
            }
            lbl_803DE2E8.flags = 4;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x19: /* set key */
            sv->key = (cmd >> 8) & 0x7f;
            sv->fineTune = (s8)(lbl_803DE2E8.flags >> 0x10);
            if (voiceIsRegistered((int)sv) != 0)
            {
                inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->key & 0xff);
            }
            lbl_803DE2E8.flags = 4;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x1a: /* last key */
            sv->key = sv->registeredKey + (s8)((cmd >> 8) & 0xff);
            sv->key = (s16)sv->key < 0 ? 0 : sv->key > 0x7f ? 0x7f : sv->key;
            sv->fineTune = (s8)(lbl_803DE2E8.flags >> 0x10);
            if (sv->midiSlot != 0xff)
            {
                inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->key & 0xff);
            }
            lbl_803DE2E8.flags = 4;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x1b: /* portamento */
            mcmdPortamento(sv, &lbl_803DE2E8);
            break;
        case 0x1c: /* vibrato */
            mcmdVibrato(sv, &lbl_803DE2E8);
            break;
        case 0x1d: /* pitch sweep 1 */
            {
                s32 delta;
                sv->sweepOff[0] = 0;
                sv->sweepNum[0] = (lbl_803DE2E8.flags >> 8) & 0xff;
                sv->sweepCnt[0] = sv->sweepNum[0] << 0x10;
                delta = (s16)(lbl_803DE2E8.flags >> 0x10);
                if (delta >= 0)
                {
                    delta = hwExitStream(delta);
                }
                else
                {
                    delta = -hwExitStream(-delta);
                }
                sv->sweepAdd[0] = delta << 0x10;
                lbl_803DE2E8.flags = 0;
                ex = mcmdWait(sv, &lbl_803DE2E8);
                break;
            }
        case 0x1e: /* pitch sweep 2 */
            {
                s32 delta;
                sv->sweepOff[1] = 0;
                sv->sweepNum[1] = (lbl_803DE2E8.flags >> 8) & 0xff;
                sv->sweepCnt[1] = sv->sweepNum[1] << 0x10;
                delta = (s16)(lbl_803DE2E8.flags >> 0x10);
                if (delta >= 0)
                {
                    delta = hwExitStream(delta);
                }
                else
                {
                    delta = -hwExitStream(-delta);
                }
                sv->sweepAdd[1] = delta << 0x10;
                lbl_803DE2E8.flags = 0;
                ex = mcmdWait(sv, &lbl_803DE2E8);
                break;
            }
        case 0x1f: /* set pitch */
            sv->targetPitch = cmd >> 8;
            sv->targetPitch |= (u8) * para1;
            if (sv->prevSampleId != 0xffffffff)
            {
                DoSetPitch(sv);
            }
            break;
        case 0x20: /* set pitch ADSR */
            mcmdSetPitchADSR(sv, &lbl_803DE2E8);
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
                    sv->volume = ((sv->volumeBase >> 5) * scale) >> 7;
                }
                if (sv->volume > 0x7f0000)
                {
                    sv->volume = 0x7f0000;
                }
                MAC_CFLAGS(sv) |= MAC_FLAG64(0x1000, 0);
                break;
            }
        case 0x22: /* set mod2vibrato */
            sv->vibratoModAddScale = (s8)(cmd >> 8) << 8;
            if (sv->vibratoModAddScale >= 0)
            {
                sv->vibratoModAddScale += ((s16)(s8)(lbl_803DE2E8.flags >> 0x10) << 8) / 100;
            }
            else
            {
                sv->vibratoModAddScale -= ((s16)(s8)(lbl_803DE2E8.flags >> 0x10) << 8) / 100;
            }
            break;
        case 0x23: /* setup tremolo */
            sv->tremoloScale = (cmd >> 8) & 0xffff;
            sv->tremoloModAddScale = *para1;
            sv->tremoloCurScale = one;
            break;
        case 0x24: /* return */
            if (sv->macroStackDepth != 0)
            {
                sv->macroBase = sv->macroStack[sv->macroStackIndex].macroBase;
                sv->macroCursor = sv->macroStack[sv->macroStackIndex].macroCursor;
                sv->macroStackIndex = (sv->macroStackIndex - 1) & 3;
                --sv->macroStackDepth;
            }
            break;
        case 0x25: /* gosub */
            {
                u8* macro = dataGetMacro(cmd >> 0x10);
                u32 stop;
                if (macro != 0)
                {
                    sv->macroStackIndex = (sv->macroStackIndex + 1) & 3;
                    sv->macroStack[sv->macroStackIndex].macroBase = sv->macroBase;
                    sv->macroStack[sv->macroStackIndex].macroCursor = sv->macroCursor;
                    if (++sv->macroStackDepth > 4)
                    {
                        sv->macroStackDepth = 4;
                    }
                    sv->macroBase = macro;
                    stop = 0;
                    sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                }
                else
                {
                    vidRemoveVoice((int)sv);
                    voiceFree((int)sv);
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
                    u32 t = (*para1 >> 8) & 0xff;
                    sv->trapMacroBase[t] = macro;
                    sv->trapMacroCursor[t] = macro + ((*para1 & 0xffff) << 3);
                    sv->hasTriggerMacros = 1;
                    if (t == 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0x100, 8)) == MAC_FLAG64(0x100, 8))
                    {
                        MAC_CFLAGS(sv) |= MAC_FLAG64(0x400, 0);
                    }
                }
                break;
            }
        case 0x29: /* untrap event */
            {
                u8 i;
                sv->trapMacroBase[(cmd >> 8) & 0xff] = 0;
                for (i = 0; i < 3; i++)
                {
                    if (sv->trapMacroBase[i] != 0)
                    {
                        goto next_command;
                    }
                }
                sv->hasTriggerMacros = 0;
                break;
            }
        case 0x2a: /* send message */
            mcmdSendMessage(sv, &lbl_803DE2E8);
            break;
        case 0x2b: /* get message */
            {
                u32 mesg = 0;
                if (sv->queuedMessageCount != 0)
                {
                    mesg = sv->queuedMessages[sv->queuedMessageReadIndex];
                    sv->queuedMessageReadIndex = (sv->queuedMessageReadIndex + 1) & 3;
                    --sv->queuedMessageCount;
                }
                varSet32(sv, 0, (lbl_803DE2E8.flags >> 8) & 0xff, mesg);
                break;
            }
        case 0x2c: /* get VID */
            if (((cmd >> 0x10) & 0xff) == 0)
            {
                varSet32(sv, 0, (cmd >> 8) & 0xff, sv->vidListNode->id);
            }
            else
            {
                varSet32(sv, 0, (cmd >> 8) & 0xff, (u32)sv->cloneVidListNode);
            }
            break;
        case 0x30: /* add age counter */
            {
                s32 age = (sv->priorityValue >> 0xf) + (s16)(cmd >> 0x10);
                if (age < 0)
                {
                    sv->priorityValue = 0;
                }
                else if (age > 0xffff)
                {
                    sv->priorityValue = 0x7fff8000;
                }
                else
                {
                    sv->priorityValue = age << 0xf;
                }
                hwSetPriority(sv->voiceHandle & 0xff,
                              ((u32)sv->priorityGroup << 0x18) | (sv->priorityValue >> 0xf));
                break;
            }
        case 0x31: /* set age counter */
            sv->priorityValue = ((cmd >> 0x10) & 0xffff) << 0xf;
            hwSetPriority(sv->voiceHandle & 0xff,
                          ((u32)sv->priorityGroup << 0x18) | (sv->priorityValue >> 0xf));
            break;
        case 0x32: /* send flag */
            lbl_803BDA34[(cmd >> 8) & 0xff] = (cmd >> 0x10) & 0xff;
            break;
        case 0x33: /* set pitch wheel range */
            sv->pitchBendRangeUp = (cmd >> 0x10) & 0xff;
            sv->pitchBendRangeDown = (lbl_803DE2E8.flags >> 8) & 0xff;
            break;
        case 0x34: /* scale reverb */
            sv->revVolScale = (cmd >> 8) & 0xff;
            sv->revVolOffset = (lbl_803DE2E8.flags >> 0x10) & 0xff;
            break;
        case 0x35: /* pitchbend after key off */
            MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x10000);
            break;
        case 0x36: /* set priority */
            voiceSetPriority(sv, (cmd >> 8) & 0xff);
            break;
        case 0x37: /* add priority */
            {
                s16 prio = sv->priorityGroup + (s16)(cmd >> 0x10);
                prio = prio < 0 ? 0 : prio > 0xff ? 0xff : prio;
                voiceSetPriority(sv, prio);
                break;
            }
        case 0x38: /* set age counter speed */
            if (*para1 != 0)
            {
                sv->priorityScale = (sv->priorityValue >> 8) / *para1;
            }
            else
            {
                sv->priorityScale = 0;
            }
            break;
        case 0x39: /* set age counter by volume */
            {
                u32 age = ((s32)((*para1 & 0xffff) * ((sv->volume >> 0x10) & 0xff)) >> 7) + (cmd >> 0x10);
                sv->priorityValue = age > 60000 ? 0x75300000 : age << 0xf;
                hwSetPriority(sv->voiceHandle & 0xff,
                              ((u32)sv->priorityGroup << 0x18) | (sv->priorityValue >> 0xf));
                break;
            }
        case 0x40: /* volume select */
            SelectSource(sv, &sv->volumeInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x80000), 1);
            break;
        case 0x41: /* panning select */
            SelectSource(sv, &sv->panningInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x100000), 2);
            break;
        case 0x42: /* pitch wheel select */
            SelectSource(sv, &sv->pitchBendInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x200000), 8);
            break;
        case 0x43: /* mod wheel select */
            SelectSource(sv, &sv->modulationInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x400000), 0x20);
            break;
        case 0x44: /* pedal select */
            SelectSource(sv, &sv->pedalInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x2000000), 0x40);
            break;
        case 0x45: /* portamento select */
            SelectSource(sv, &sv->portamentoInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x1000000), 0x80);
            break;
        case 0x46: /* reverb select */
            SelectSource(sv, &sv->reverbInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x800000), 0x200);
            break;
        case 0x47: /* surround panning select */
            SelectSource(sv, &sv->surPanningInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x4000000), 4);
            break;
        case 0x48: /* doppler select */
            SelectSource(sv, &sv->dopplerInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x8000000), 0x10);
            break;
        case 0x49: /* tremolo select */
            SelectSource(sv, &sv->tremoloInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x10000000), 0x1000);
            break;
        case 0x4a: /* pre aux A select */
            SelectSource(sv, &sv->preAuxAInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x20000000), 0x100);
            break;
        case 0x4b: /* pre aux B select */
            SelectSource(sv, &sv->preAuxBInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x40000000), 0x400);
            break;
        case 0x4c: /* post aux B select */
            SelectSource(sv, &sv->postAuxBInput, &lbl_803DE2E8, MAC_FLAG64(0, 0x80000000), 0x800);
            break;
        case 0x4d: /* aux A FX select */
            {
                u8 i = *para1 >> 0x18;
                SelectSource(sv,
                             (McmdInputSlot*)(lbl_803BDEF4 + sv->studio * 0x90 + i * 0x24),
                             &lbl_803DE2E8, ((MacDataTables*)lbl_8032EDD0)->auxAMask[i],
                             ((MacDataTables*)lbl_8032EDD0)->auxADirty[i]);
                break;
            }
        case 0x4e: /* aux B FX select */
            {
                u8 i = *para1 >> 0x18;
                SelectSource(sv,
                             (McmdInputSlot*)(lbl_803BDA74 + sv->studio * 0x90 + i * 0x24),
                             &lbl_803DE2E8, ((MacDataTables*)lbl_8032EDD0)->auxBMask[i],
                             ((MacDataTables*)lbl_8032EDD0)->auxBDirty[i]);
                break;
            }
        case 0x50: /* setup LFO */
            {
                u32 time;
                u32 phase;
                u32 n;
                time = (cmd >> 0x10) & 0xffff;
                sndConvertMs(&time);
                n = (cmd >> 8) & 0xff;
                if (sv->exCtrls[n].rampFrames != 0)
                {
                    phase = *para1 & 0xffff;
                    sndConvertMs(&phase);
                    sv->exCtrls[n].unk00 = phase;
                }
                sv->exCtrls[n].rampFrames = time;
                break;
            }
        case 0x58: /* mode select */
            sv->volTable = ((cmd >> 8) & 0xff) != 0 ? 1 : 0;
            sv->itdMode = ((lbl_803DE2E8.flags >> 0x10) & 0xff) != 0 ? 0 : 1;
            break;
        case 0x59: /* set key group */
            mcmdSetKeyGroup(sv, &lbl_803DE2E8);
            break;
        case 0x5a: /* SRC mode select */
            hwSetSRCType(sv->voiceHandle & 0xff, (cmd >> 8) & 0xff);
            hwSetPolyPhaseFilter(sv->voiceHandle & 0xff, (lbl_803DE2E8.flags >> 0x10) & 0xff);
            MAC_CFLAGS(sv) |= MAC_FLAG64(0x800, 0);
            break;
        case 0x60: /* var add */
            mcmdVarCalculation(sv, &lbl_803DE2E8, 0);
            break;
        case 0x61: /* var sub */
            mcmdVarCalculation(sv, &lbl_803DE2E8, 1);
            break;
        case 0x62: /* var mul */
            mcmdVarCalculation(sv, &lbl_803DE2E8, 2);
            break;
        case 0x63: /* var div */
            mcmdVarCalculation(sv, &lbl_803DE2E8, 3);
            break;
        case 0x64: /* var add randomized */
            mcmdVarCalculation(sv, &lbl_803DE2E8, 4);
            break;
        case 0x65: /* set var immediate */
            varSet32(sv, (cmd >> 8) & 0xff, (cmd >> 0x10) & 0xff, (s16) * para1);
            break;
        case 0x70: /* if var equal */
            {
                s32 a;
                s32 b;
                u8 result;
                a = varGet32(sv, (cmd >> 8) & 0xff, (cmd >> 0x10) & 0xff);
                b = varGet32(sv, lbl_803DE2E8.flags >> 0x18, (u8) * para1);
                result = !(b - a);
                if (((*para1 >> 8) & 0xff) != 0)
                {
                    result = !result;
                }
                if (result != 0)
                {
                    sv->macroCursor = sv->macroBase + ((*para1 >> 0x10) << 3);
                }
                break;
            }
        case 0x71: /* if var less */
            {
                s32 a;
                s32 b;
                u8 result;
                a = varGet32(sv, (cmd >> 8) & 0xff, (cmd >> 0x10) & 0xff);
                b = varGet32(sv, lbl_803DE2E8.flags >> 0x18, (u8) * para1);
                result = a < b;
                if (((*para1 >> 8) & 0xff) != 0)
                {
                    result = !result;
                }
                if (result != 0)
                {
                    sv->macroCursor = sv->macroBase + ((*para1 >> 0x10) << 3);
                }
                break;
            }
        }
    next_command:;
    }
    while (ex == 0);
}

/*
 * Resume a trapped macro stream (keyoff/sample-end/message) if armed.
 */
static u32 ExecuteTrap(McmdVoiceState* sv, u8 trapType)
{
    if (sv->hasTriggerMacros != 0 && sv->trapMacroBase[trapType] != 0)
    {
        sv->macroCursor = sv->trapMacroCursor[trapType];
        sv->macroBase = sv->trapMacroBase[trapType];
        sv->trapMacroBase[trapType] = 0;
        macMakeActive(sv);
        return 1;
    }
    return 0;
}

/*
 * Advance the synth voice timer queue and process active voices.
 */
void macHandle(u32 deltaTime)
{
    McmdVoiceState* sv;
    McmdVoiceState* nextSv;
    u64 w;

    for (sv = (McmdVoiceState*)macTimeQueueRoot;
         sv != 0 && *(u64*)&sv->wakeTimeHi <= *(u64*)&macRealTimeHi;)
    {
        nextSv = sv->timeNext;
        w = *(u64*)&sv->wakeTimeHi;
        macMakeActive(sv);
        *(u64*)&sv->activeTimeHi = w;
        sv = nextSv;
    }

    for (sv = (McmdVoiceState*)macActiveRoot; sv != 0; sv = sv->activeNext)
    {
        u32 hasTrap;
        if (sv->hasTriggerMacros != 0)
        {
            hasTrap = sv->sampleEndMacroBase != 0;
        }
        else
        {
            hasTrap = 0;
        }
        if (hasTrap != 0)
        {
            if (!(MAC_CFLAGS(sv) & MAC_FLAG64(0, 0x20)) &&
                hwIsActive(sv->voiceHandle & 0xff) == 0)
            {
                ExecuteTrap(sv, 1);
            }
        }
        macHandleActive(sv);
    }

    *(u64*)&macRealTimeHi += deltaTime;
}

/*
 * Resume a yielded voice from its sample-end stream when needed.
 */
void macSampleEndNotify(McmdVoiceState* sv)
{
    if (sv->queueMode == 1)
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
    if (sv->macroBase != 0)
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
        if (sv->macroBase != 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0x400, 0)))
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

    next = (McmdVoiceState*)macTimeQueueRoot;
    prev = 0;
    while ((cur = next) != 0 &&
        *(u64*)&cur->wakeTimeHi < *(u64*)&state->wakeTimeHi)
    {
        prev = cur;
        next = cur->timeNext;
    }

    if (cur == 0)
    {
        if (prev == 0)
        {
            macTimeQueueRoot = (int)state;
            state->timeNext = 0;
            state->timePrev = 0;
            return;
        }

        prev->timeNext = state;
        state->timePrev = prev;
        state->timeNext = 0;
        return;
    }

    state->timeNext = cur;
    prev = cur->timePrev;
    state->timePrev = prev;
    if (prev != 0)
    {
        cur->timePrev->timeNext = state;
    }
    else
    {
        macTimeQueueRoot = (int)state;
    }
    cur->timePrev = state;
}

/*
 * Remove a voice from the time queue and clear its scheduled wake time.
 */
#pragma dont_inline on
void TimeQueueRemove(McmdVoiceState* sv, u32 disableUpdate)
{
    if (*(u64*)&sv->wakeTimeHi != 0)
    {
        if (*(u64*)&sv->wakeTimeHi != (u64) - 1)
        {
            if (sv->timePrev == 0)
            {
                macTimeQueueRoot = (int)sv->timeNext;
            }
            else
            {
                sv->timePrev->timeNext = sv->timeNext;
            }
            if (sv->timeNext != 0)
            {
                sv->timeNext->timePrev = sv->timePrev;
            }
        }
        if (disableUpdate == 0)
        {
            synthQueueVoicePrimaryUpdates(sv);
        }
        *(u64*)&sv->wakeTimeHi = 0;
        *(u64*)&sv->activeTimeHi = *(u64*)&macRealTimeHi;
        MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 0x40004);
    }
}
#pragma dont_inline reset

/*
 * Move a yielded voice back onto the active voice list.
 */
void macMakeActive(McmdVoiceState* sv)
{
    if (sv->queueMode != 0)
    {
        if (*(u64*)&sv->wakeTimeHi != 0)
        {
            if (*(u64*)&sv->wakeTimeHi != (u64) - 1)
            {
                if (sv->timePrev == 0)
                {
                    macTimeQueueRoot = (int)sv->timeNext;
                }
                else
                {
                    sv->timePrev->timeNext = sv->timeNext;
                }
                if (sv->timeNext != 0)
                {
                    sv->timeNext->timePrev = sv->timePrev;
                }
            }
            synthQueueVoicePrimaryUpdates(sv);
            *(u64*)&sv->wakeTimeHi = 0;
            *(u64*)&sv->activeTimeHi = *(u64*)&macRealTimeHi;
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 0x40004);
        }
        if ((sv->activeNext = (McmdVoiceState*)macActiveRoot) != 0)
        {
            ((McmdVoiceState*)macActiveRoot)->activePrev = sv;
        }
        sv->activePrev = 0;
        macActiveRoot = (int)sv;
        sv->queueMode = 0;
    }
}

/*
 * Detach a voice from the active list and optionally stop it cold.
 */
void macMakeInactive(McmdVoiceState* sv, int newState)
{
    if (sv->queueMode == newState)
    {
        return;
    }

    if (sv->queueMode == 0)
    {
        if (sv->activePrev == 0)
        {
            macActiveRoot = (int)sv->activeNext;
        }
        else
        {
            sv->activePrev->activeNext = sv->activeNext;
        }
        if (sv->activeNext != 0)
        {
            sv->activeNext->activePrev = sv->activePrev;
        }
    }

    if (newState == 2)
    {
        if (*(u64*)&sv->wakeTimeHi != 0)
        {
            if (*(u64*)&sv->wakeTimeHi != (u64) - 1)
            {
                if (sv->timePrev == 0)
                {
                    macTimeQueueRoot = (int)sv->timeNext;
                }
                else
                {
                    sv->timePrev->timeNext = sv->timeNext;
                }
                if (sv->timeNext != 0)
                {
                    sv->timeNext->timePrev = sv->timePrev;
                }
            }
            *(u64*)&sv->wakeTimeHi = 0;
            *(u64*)&sv->activeTimeHi = *(u64*)&macRealTimeHi;
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 0x40004);
        }
    }
    sv->queueMode = newState;
}

/*
 * Allocate a voice and start a macro on it (MusyX macStart).
 */
u32 macStart(u16 macid, u8 priority, u8 maxVoices, u16 allocId, u8 key, u8 vol,
             u8 panning, u8 midi, u8 midiSet, u8 section, u16 step, u16 trackid,
             u8 new_vid, u8 vGroup, u8 studio, u32 itd)
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

        if ((voice = voiceAllocate(priority, maxVoices, allocId, fxFlag != 0 ? 1 : 0)) !=
            0xffffffff)
        {
            sv = (McmdVoiceState*)(synthVoice + voice * SYNTH_VOICE_STRIDE);
            vidRemoveVoice((int)sv);
            if (sv->queueMode != 2)
            {
                if (sv->queueMode == 0)
                {
                    if (sv->activePrev == 0)
                    {
                        macActiveRoot = (int)sv->activeNext;
                    }
                    else
                    {
                        sv->activePrev->activeNext = sv->activeNext;
                    }
                    if (sv->activeNext != 0)
                    {
                        sv->activeNext->activePrev = sv->activePrev;
                    }
                }
                TimeQueueRemove(sv, 1);
                sv->queueMode = 2;
            }
            MAC_CFLAGS(sv) = (MAC_CFLAGS(sv) & MAC_FLAG64(0, 0x10)) | MAC_FLAG64(0, 2);

            if (hwIsActive(voice))
            {
                sv->outputFlags |= 1;
            }

            *(u64*)&sv->wakeTimeHi = 0;

            if (fxFlag != 0)
            {
                sv->streamKind = 1;
                key &= 0x7f;
                inpResetMidiCtrl((u8)voice, 0xff, 1);
                inpResetChannelDefaults((u8)voice, 0xff);
                sv->startupMidiSlot = voice;
                sv->startupMidiEvent = 0xff;
                sv->startupMidiLayer = 0;
            }
            else
            {
                sv->streamKind = 0;
                sv->startupMidiSlot = midi;
                sv->startupMidiEvent = midiSet;
                sv->startupMidiLayer = section;
            }

            sv->instrumentKey = macid;
            sv->baseSample = allocId;
            sv->priorityValue = 0x75300000;
            sv->priorityScale = 0x400;
            sv->macroBase = addr;
            sv->macroCursor = addr + (step << 3);
            sv->keyBase = key;
            sv->key = key;
            sv->fineTune = 0;
            sv->startupVolume = vol;
            sv->startupPan = panning;
            sv->startupTrack = trackid;
            sv->macroStackDepth = 0;
            sv->macroStackIndex = 0;
            sv->voiceNextHandle = 0xffffffff;
            sv->voicePrevHandle = 0xffffffff;
            sv->cloneVidListNode = (McmdVidListNode*)0xffffffff;
            sv->startupVGroup = vGroup;
            sv->startupStudio = studio;
            sv->startupDeferStart = itd != 0 ? 0 : 1;
            sv->queuedMessageWriteIndex = 0;
            sv->queuedMessageReadIndex = 0;
            sv->queuedMessageCount = 0;
            sv->voiceHandle = voice | ((macid << 0x10) | ((key & 0xff) << 8));
            voiceSetPriority(sv, priority);

            if ((vid = vidMakeNew((int)sv, new_vid)) != 0xffffffff)
            {
                if (sv->queueMode != 0)
                {
                    TimeQueueRemove(sv, 0);
                    if ((sv->activeNext = (McmdVoiceState*)macActiveRoot) != 0)
                    {
                        ((McmdVoiceState*)macActiveRoot)->activePrev = sv;
                    }
                    sv->activePrev = 0;
                    macActiveRoot = (int)sv;
                    sv->queueMode = 0;
                }
                return vid;
            }

            if (hwIsActive(voice))
            {
                hwBreak(voice);
            }
            voiceFree((int)sv);
        }
    }

    return 0xffffffff;
}

/*
 * Reset the macro scheduler state and every voice slot.
 */
void macInit(void)
{
    int off;
    u32 i;

    macRealTimeLo = off = 0;
    macActiveRoot = 0;
    macTimeQueueRoot = 0;
    macRealTimeHi = 0;
    for (i = 0; i < lbl_803BD150[0x210]; off += SYNTH_VOICE_STRIDE, i++)
    {
        *(u32*)&((McmdVoiceState*)(synthVoice + off))->macroBase = 0;
        ((McmdVoiceState*)(synthVoice + off))->queueMode = 2;
        ((McmdVoiceState*)(synthVoice + off))->loopCounter = 0;
    }
}
