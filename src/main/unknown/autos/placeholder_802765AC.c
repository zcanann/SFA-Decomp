#include "ghidra_import.h"
#include "main/audio/hw_voice_control.h"
#include "main/audio/inp_midi.h"
#include "main/audio/snd_core.h"
#include "main/unknown/autos/placeholder_802765AC.h"
#include "main/unknown/autos/placeholder_80279608.h"
#include "main/unknown/autos/placeholder_8027591C.h"
#include "main/unknown/autos/placeholder_8027641C.h"
#include "main/audio/hw_adsr.h"
#include "main/audio/hw_aram.h"
#include "main/audio/hw_init.h"
#include "main/audio/hw_voice_params.h"
#include "main/audio/inp_ctrl.h"

extern undefined4 FUN_800033a8();
extern undefined4 audioKeymapFn_8026fc8c();
extern undefined4 FUN_80271a2c();
extern undefined4 FUN_80271ad4();
extern int FUN_80275364();
extern int mcmdLoop();
extern uint FUN_802757d4();
extern undefined4 FUN_802757dc();
extern undefined4 FUN_802757e0();
extern undefined4 FUN_802757e4();
extern undefined4 FUN_802757e8();
extern undefined4 FUN_802763c0();
extern uint FUN_80279008();
extern undefined4 FUN_8027975c();
extern uint FUN_8027976c();
extern undefined4 voiceInitPriorityTables();
extern undefined4 FUN_8027a664();
extern int FUN_8027a8fc();
extern undefined4 FUN_8027a904();
extern undefined4 FUN_8027ac38();
extern undefined4 FUN_8028134c();
extern undefined4 FUN_80281a30();
extern uint FUN_8028343c();
extern undefined4 FUN_80283444();
extern undefined4 hwStart();
extern bool FUN_80283844();
extern undefined4 FUN_80283850();
extern undefined4 hwAddInput();
extern undefined4 hwRemoveInput();
extern undefined4 FUN_80283e04();
extern undefined4 FUN_80283e08();
extern int aramStoreData();
extern int FUN_80286718();
extern uint countLeadingZeros();

extern undefined4 DAT_8032fa4c;
extern undefined4 DAT_8032fc50;
extern undefined4 DAT_8032fc54;
extern undefined4 DAT_8032fc80;
extern undefined4 DAT_8032fc84;
extern undefined4 DAT_803303fc;
extern undefined4 DAT_803307fc;
extern undefined4 DAT_803bdfc0;
extern undefined4 DAT_803be654;
extern undefined4 DAT_803be694;
extern undefined DAT_803be6d4;
extern undefined DAT_803beb54;
extern undefined4 DAT_803deee8;
extern undefined4* DAT_803deeec;
extern undefined4 DAT_803def50;
extern int* DAT_803def54;
extern int* DAT_803def58;
extern undefined4 DAT_803def60;
extern undefined4 DAT_803def64;
extern undefined4 DAT_803def68;
extern f64 DOUBLE_803e8498;
extern f64 DOUBLE_803e84a0;
extern f32 FLOAT_803e8488;
extern f32 FLOAT_803e848c;
extern f32 FLOAT_803e8490;
extern f32 FLOAT_803e84a8;
extern f32 FLOAT_803e84ac;
extern void* PTR_DAT_8032fc70;
extern void* PTR_DAT_8032fca0;
extern undefined4 uRam803def6c;

extern u8 *synthVoice;
extern u8 lbl_803BD150[];
extern int macActiveRoot;
extern int macTimeQueueRoot;
extern int macRealTimeHi;
extern int macRealTimeLo;
extern void synthQueueVoicePrimaryUpdates(void *state);
extern void *dataGetMacro(u32 key);
extern u16 seqGetMIDIPriority(u8 slot, u8 event);
extern u32 voiceAllocate(u32 priority, u32 maxInstances, u32 key, u8 streamKind);
extern void vidRemoveVoice(int state);
extern u32 vidMakeNew(int state, int returnNewId);
extern int hwIsActive(int slot);
extern void voiceFree(int state);
extern void inpResetChannelDefaults(u8 a, u8 b);
void audioFn_80278990(McmdVoiceState *state);
void fn_802788B4(McmdVoiceState *state, u32 skipFadeReset);
u32 macSetExternalKeyoff(int state);
extern u32 inpGetExCtrl(McmdVoiceState *state, u32 ctrl);
extern void inpSetExCtrl(McmdVoiceState *state, u32 ctrl, s16 value);
extern void voiceKill(u32 voice);
extern u8 lbl_803BDA34[];
extern void fn_8026F5B8(int state);
extern int voiceIsRegistered(int state);
extern int mcmdWait(McmdVoiceState *state, McmdCommandArgs *args);
extern int vidGetInternalId(u32 id);
extern void (*synthMessageCallback)(u32 id);

#define SYNTH_VOICE_STRIDE 0x404
#define SYNTH_GLOBAL_REG(index) (*(u32 *)(lbl_803BDA34 + (index) * 4 - 0x40))

/* 64-bit control-flag word overlaying inputFlags(hi)/outputFlags(lo). */
#define MAC_CFLAGS(sv) (*(u64 *)&(sv)->inputFlags)
#define MAC_FLAG64(hi, lo) (((u64)(hi) << 32) | (u64)(lo))

/* Constant tables in this unit's data block (lbl_8032EDD0). */
typedef struct MacDataTables {
    u16 pitchRatioTab[14]; /* 0x000 */
    s32 midi2TimeTab[128]; /* 0x01C */
    u8 pad21C[4];          /* 0x21C */
    u64 auxAMask[4];       /* 0x220 */
    u32 auxADirty[4];      /* 0x240 */
    u64 auxBMask[4];       /* 0x250 */
    u32 auxBDirty[4];      /* 0x270 */
} MacDataTables;

extern u8 lbl_8032EDD0[];
extern u8 lbl_803BDA74[]; /* per-studio aux B input slots */
extern u8 lbl_803BDEF4[]; /* per-studio aux A input slots */
extern u8 lbl_803DE2D0;   /* macro steps executed this frame */
extern McmdCommandArgs lbl_803DE2E8; /* current macro step */
extern f32 lbl_803E7810;  /* 1023.0f */
extern f32 lbl_803E7814;  /* 1.0f */
extern f32 voiceAdsrSustainTable[];
extern u8 voiceAdsrDecayTable[];

extern void synthQueueVoiceInputUpdate(McmdVoiceState *state);
extern void fn_802712C8(McmdVoiceState *state); /* synthStartSynthJobHandling */

/*
 * Choose a randomized note/velocity command and dispatch it through the
 * normal sample-start handler.
 */
void mcmdRandomKey(McmdVoiceState *state, McmdCommandArgs *args)
{
    u32 command;
    int lowKey;
    int highKey;
    int fineTune;
    u32 randomValue;
    int keyRange;

    if (((args->value >> 8) & 0xff) == 0) {
        command = args->flags;
        lowKey = (command >> 8) & 0xff;
        highKey = command >> 0x18;
        if (highKey < lowKey) {
            highKey = lowKey;
            lowKey = command >> 0x18;
        }
    } else {
        lowKey = state->key - (int)((args->flags >> 8) & 0xff);
        highKey = state->key + (int)(args->flags >> 0x18);
        if ((int)lowKey < 0) {
            lowKey = 0;
        } else if ((int)lowKey > 0x7f) {
            lowKey = 0x7f;
        }
        lowKey &= 0xff;
        if (highKey > 0x7f) {
            highKey = 0x7f;
        }
        highKey &= 0xff;
    }

    if ((args->value & 0xff) == 0) {
        fineTune = (args->flags >> 0x10) & 0xff;
    } else {
        fineTune = (sndRand() & 0xffff) % 0xc9 - 100;
    }
    randomValue = sndRand();
    keyRange = (highKey - lowKey) + 1;
    args->flags = ((fineTune & 0xff) << 0x10) | 0x19 |
            (lowKey + ((randomValue & 0xffff) -
                       ((int)(randomValue & 0xffff) / keyRange) * keyRange)) *
                0x100;
    args->value = 0;
    state->key = (u16)(args->flags >> 8) & 0x7f;
    state->fineTune = (s8)(args->flags >> 0x10);
    if (voiceIsRegistered((int)state) != 0) {
        inpSetMidiLastNote(state->midiSlot, state->midiEvent, state->key & 0xff);
    }
    args->flags = 4;
    mcmdWait(state, args);
}

/*
 * Queue a controller event and mark the owning MIDI/global dirty flag.
 */
void SelectSource(McmdVoiceState *svoice, McmdInputSlot *dest, McmdCommandArgs *cstep,
                  u64 tstflag, u32 dirtyFlag)
{
    u8 comb;
    s32 scale;

    if (!(MAC_CFLAGS(svoice) & tstflag)) {
        comb = 0;
        MAC_CFLAGS(svoice) |= tstflag;
    } else {
        comb = cstep->value;
    }

    scale = (s32)(cstep->flags & 0xffff0000) / 100;
    if (scale < 0) {
        scale -= ((s8)(cstep->value >> 0x10) << 8) / 100;
    } else {
        scale += ((s8)(cstep->value >> 0x10) << 8) / 100;
    }

    inpAddCtrl((int)dest, (cstep->flags >> 8) & 0xff, scale, comb,
               (u8)(cstep->value >> 8) != 0);

    if (dirtyFlag & 0x80000000) {
        inpSetGlobalMIDIDirtyFlag(svoice->midiSlot, svoice->midiEvent, dirtyFlag);
    } else {
        svoice->inputDirtyFlags |= dirtyFlag;
    }
}

/*
 * Read a 32-bit synth register, either from the voice or EX controller bank.
 */
#pragma dont_inline on
u32 varGet32(McmdVoiceState *state, u32 useExCtrl, u32 index)
{
    u32 value;

    if (useExCtrl != 0) {
        value = inpGetExCtrl(state, index);
        value &= 0xffff;
    } else {
        index &= 0x1f;
        if (index < 0x10) {
            value = state->localRegs[index];
        } else {
            value = SYNTH_GLOBAL_REG(index);
        }
    }
    return value;
}

/*
 * Read a signed 16-bit synth register.
 */
int varGet(McmdVoiceState *state, u32 useExCtrl, u32 index)
{
    u32 value;

    if (useExCtrl != 0) {
        value = inpGetExCtrl(state, index) & 0xffff;
    } else {
        index &= 0x1f;
        if (index < 0x10) {
            value = state->localRegs[index];
        } else {
            value = SYNTH_GLOBAL_REG(index);
        }
    }
    return (s16)value;
}

/*
 * Write a synth register, routing high registers to the EX controller bank.
 */
void varSet32(McmdVoiceState *state, u32 useExCtrl, u32 index, u32 value)
{
    if (useExCtrl != 0) {
        inpSetExCtrl(state, index, (s16)value);
    } else {
        index &= 0x1f;
        if (index < 0x10) {
            state->localRegs[index] = value;
        } else {
            SYNTH_GLOBAL_REG(index) = value;
        }
    }
}
#pragma dont_inline reset

/*
 * Configure the portamento controller ramp trigger for the current voice.
 */
void mcmdPortamento(McmdVoiceState *state, McmdCommandArgs *args)
{
    u32 duration[2];
    int mode;

    state->portamentoMode = args->flags >> 0x10;
    duration[0] = args->value >> 0x10;
    if (((args->value >> 8) & 1) != 0) {
        sndConvertMs(duration);
    } else {
        sndConvertTicks(duration, (int)state);
    }
    state->portamentoDuration = duration[0];
    mode = (args->flags >> 8) & 0xff;
    if (mode == 1) {
        if (state->midiSlot != 0xff) {
            inpSetMidiCtrl(MCMD_CTRL_PORTAMENTO, state->midiSlot, state->midiEvent, 0x7f);
        }
    } else {
        if (mode == 0) {
            if (state->midiSlot != 0xff) {
                inpSetMidiCtrl(MCMD_CTRL_PORTAMENTO, state->midiSlot, state->midiEvent, 0);
            }
            state->outputFlags &= ~MCMD_VOICE_PORTAMENTO_OUTPUT_FLAG;
            state->inputFlags = state->inputFlags;
            return;
        }
        if (mode > 2) {
            return;
        }
        if (state->midiSlot == 0xff) {
            return;
        }
        if ((u16)inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, state->midiSlot, state->midiEvent) <=
            0x1f80) {
            return;
        }
    }
    if ((state->outputFlags & MCMD_VOICE_PORTAMENTO_OUTPUT_FLAG) == 0) {
        fn_8026F5B8((int)state);
    }
    state->outputFlags |= MCMD_VOICE_PORTAMENTO_OUTPUT_FLAG;
}

/*
 * Arithmetic command over synth registers.
 */
void mcmdVarCalculation(McmdVoiceState *state, McmdCommandArgs *args, u8 op)
{
    u32 command;
    u32 operand;
    int opValue;
    s16 lhs;
    s16 rhs;
    int result;

    operand = args->value;
    command = args->flags;
    lhs = (s16)varGet32(state, command >> 0x18, operand & 0xff);
    opValue = op;
    if (opValue == 4) {
        rhs = (s16)(operand >> 8);
    } else {
        operand = args->value;
        rhs = (s16)varGet32(state, (operand >> 8) & 0xff, (operand >> 0x10) & 0xff);
    }

    opValue = op;
    if (opValue == 2) {
        result = lhs * rhs;
    } else {
        if (opValue < 2) {
            if (opValue == 0) {
                result = lhs + rhs;
            } else {
                result = lhs - rhs;
                goto clamp;
            }
        } else if (opValue != 4) {
            if (opValue < 4) {
                if (rhs == 0) {
                    result = 0;
                } else {
                    result = lhs / (int)rhs;
                }
            }
            goto clamp;
        } else {
            result = lhs + rhs;
        }
    }

clamp:
    command = args->flags;
    if (result < -0x8000) {
        rhs = -0x8000;
    } else if (result <= 0x7fff) {
        rhs = (s16)result;
    } else {
        rhs = 0x7fff;
    }
    varSet32(state, (command >> 8) & 0xff, (command >> 0x10) & 0xff, (int)rhs);
}

/*
 * Queue register-derived messages onto voices found through vid handles.
 */
void mcmdSendMessage(McmdVoiceState *state, McmdCommandArgs *args)
{
    u32 index;
    u32 value;
    u32 targetInstrument;
    int offset;
    int voice;
    McmdVoiceState *voiceState;
    u8 i;
    u32 targetVoice;

    index = (args->value >> 8) & 0x1f;
    if (index < 0x10) {
        value = state->localRegs[index];
    } else {
        value = SYNTH_GLOBAL_REG(index);
    }

    if (((args->flags >> 8) & 0xff) == 0) {
        targetInstrument = args->flags >> 0x10;
        if (targetInstrument != 0xffff) {
            offset = 0;
            for (i = 0; i < *(u8 *)(lbl_803BD150 + 0x210); i++) {
                voice = (int)(synthVoice + offset);
                voiceState = (McmdVoiceState *)voice;
                if (voiceState->macroBase != 0 && targetInstrument == voiceState->instrumentKey) {
                    targetVoice = vidGetInternalId(voiceState->vidListNode->id);
                    if (targetVoice != 0xffffffff) {
                        voice = (int)(synthVoice + (targetVoice & 0xff) * SYNTH_VOICE_STRIDE);
                        voiceState = (McmdVoiceState *)voice;
                        if (voiceState->queuedMessageCount < 4) {
                            voiceState->queuedMessageCount = voiceState->queuedMessageCount + 1;
                            voiceState->queuedMessages[voiceState->queuedMessageWriteIndex] = value;
                            voiceState->queuedMessageWriteIndex =
                                (voiceState->queuedMessageWriteIndex + 1) & 3;
                            if (voiceState->hasTriggerMacros != 0 &&
                                voiceState->messageMacroBase != 0) {
                                voiceState->macroCursor = voiceState->messageMacroCursor;
                                voiceState->macroBase = voiceState->messageMacroBase;
                                voiceState->messageMacroBase = 0;
                                audioFn_80278990((McmdVoiceState *)voice);
                            }
                        }
                    }
                }
                offset += SYNTH_VOICE_STRIDE;
            }
        } else {
            if (synthMessageCallback != 0) {
                synthMessageCallback(state->vidListNode->id);
            }
        }
    } else {
        index = args->value & 0x1f;
        if (index < 0x10) {
            targetInstrument = state->localRegs[index];
        } else {
            targetInstrument = SYNTH_GLOBAL_REG(index);
        }
        targetVoice = vidGetInternalId(targetInstrument);
        if (targetVoice != 0xffffffff) {
            voice = (int)(synthVoice + (targetVoice & 0xff) * SYNTH_VOICE_STRIDE);
            voiceState = (McmdVoiceState *)voice;
            if (voiceState->queuedMessageCount < 4) {
                voiceState->queuedMessageCount = voiceState->queuedMessageCount + 1;
                voiceState->queuedMessages[voiceState->queuedMessageWriteIndex] = value;
                voiceState->queuedMessageWriteIndex =
                    (voiceState->queuedMessageWriteIndex + 1) & 3;
                if (voiceState->hasTriggerMacros != 0 && voiceState->messageMacroBase != 0) {
                    voiceState->macroCursor = voiceState->messageMacroCursor;
                    voiceState->macroBase = voiceState->messageMacroBase;
                    voiceState->messageMacroBase = 0;
                    audioFn_80278990((McmdVoiceState *)voice);
                }
            }
        }
    }
}

/*
 * Key off other voices in the same tag group, optionally by immediate stop.
 */
void mcmdSetKeyGroup(McmdVoiceState *state, McmdCommandArgs *args)
{
    u32 group;
    u32 doKill;
    u32 i;
    int synthInfo;
    int offset;
    McmdVoiceState *voice;

    offset = 0;
    state->keyGroup = 0;
    group = (args->flags >> 8) & 0xff;
    doKill = ((args->flags >> 0x10) & 0xff) != 0;
    if (group != 0) {
        synthInfo = (int)lbl_803BD150;
        for (i = 0; i < *(u8 *)(synthInfo + 0x210); i++) {
            voice = (McmdVoiceState *)(synthVoice + offset);
            if (voice->macroBase != 0) {
                if (((voice->outputFlags & MCMD_VOICE_ALLOCATED_OUTPUT_FLAG) == 0) &&
                    group == voice->keyGroup) {
                    if (doKill == 0) {
                        macSetExternalKeyoff((int)voice);
                    } else {
                        voiceKill(i);
                    }
                }
            }
            offset += 0x404;
        }
        state->keyGroup = group;
    }
}

/*
 * Run the active macro command stream for one voice (MusyX macHandleActive).
 */
void macHandleActive(McmdVoiceState *sv)
{
    u32 ex;
    u32 cmd;
    u32 *para1;
    int lastNote;
    u8 *channelDefaults;

    if (MAC_CFLAGS(sv) & 3) {
        if (MAC_CFLAGS(sv) & 1) {
            MAC_CFLAGS(sv) &= ~MAC_FLAG64(0, 1);
            hwBreak(sv->voiceHandle & 0xff);
        }

        sv->paramCurrent[0] = sv->paramTarget[0] = (u32)sv->startupPan << 16;
        sv->paramCurrent[1] = sv->paramTarget[1] = 0;
        sv->volume = (u32)sv->startupVolume << 16;
        sv->volTable = 0;
        sv->volumeBase = sv->volume;
        sv->midiSlot = sv->startupMidiSlot;
        sv->midiEvent = sv->startupMidiEvent;
        sv->midiLayer = sv->startupMidiLayer;
        sv->studio = sv->startupStudio;
        sv->itdMode = sv->startupDeferStart;
        sv->keyGroup = 0;
        sv->vibratoModAddScale = 0;
        sv->tremoloScale = 0;
        inpInit((u32)sv);
        lastNote = inpGetMidiLastNote(sv->midiSlot, sv->midiEvent);
        if ((u8)lastNote != 0xff) {
            sv->registeredKey = lastNote;
        } else {
            sv->registeredKey = sv->keyBase;
        }

        inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->keyBase);
        voiceRegister((int)sv);
        sv->auxA = sv->startupAuxA;
        sv->auxB = sv->startupAuxB;
        sv->portamentoTime = 0;
        sv->portamentoDuration = 25600;
        sv->portamentoMode = 0;
        if (sv->midiSlot != 0xff) {
            sv->portamentoCtrlValue = inpGetMidiCtrl(0x41, sv->midiSlot, sv->midiEvent);
        } else {
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
        sv->activeTimeHi = macRealTimeHi;
        sv->activeTimeLo = macRealTimeLo;
        sv->startTimeHi = macRealTimeHi;
        sv->startTimeLo = macRealTimeLo;
        fn_802712C8(sv);
    }

    lbl_803DE2D0 = 0;
    para1 = &lbl_803DE2E8.value;

    do {
        if (++lbl_803DE2D0 > 32) {
            break;
        }

        ex = 0;
        lbl_803DE2E8.flags = ((McmdCommandArgs *)sv->macroCursor)->flags;
        *para1 = ((McmdCommandArgs *)sv->macroCursor)->value;
        sv->macroCursor += 8;
        cmd = lbl_803DE2E8.flags;

        switch (cmd & 0x7f) {
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
            if (sv->key >= ((cmd >> 8) & 0xff)) {
                u8 *macro = dataGetMacro(cmd >> 0x10);
                if (macro != 0) {
                    sv->macroBase = macro;
                    sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
                }
            }
            break;
        case 0x3: /* if velocity */
            if (((sv->volume >> 0x10) & 0xff) >= ((cmd >> 8) & 0xff)) {
                u8 *macro = dataGetMacro(cmd >> 0x10);
                if (macro != 0) {
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
            u8 *macro = dataGetMacro(cmd >> 0x10);
            u32 stop;
            if (macro != 0) {
                sv->macroBase = macro;
                stop = 0;
                sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
            } else {
                vidRemoveVoice((int)sv);
                voiceFree((int)sv);
                stop = 1;
            }
            ex = stop;
            break;
        }
        case 0x7: /* wait ms */
            ((u8 *)para1)[2] = 1;
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
            voiceid = ((sv->keyBase + ((cmd >> 8) & 0xff)) << 8) | ((cmd >> 0x10) << 0x10);
            i = 0;
            off = 0;
            for (; i < *(u8 *)(lbl_803BD150 + 0x210); off += SYNTH_VOICE_STRIDE, i++) {
                u32 id = voiceid | i;
                if (*(u32 *)(synthVoice + off + 0xf4) == id) {
                    if (id != 0xffffffff) {
                        u32 slot = id & 0xff;
                        if (*(u32 *)(synthVoice + slot * SYNTH_VOICE_STRIDE + 0xf4) == id) {
                            macSetExternalKeyoff((int)(synthVoice + slot * SYNTH_VOICE_STRIDE));
                        }
                    }
                }
            }
            break;
        }
        case 0xa: /* if modulation */
            if (sv->midiSlot != 0xff) {
                u32 mod = (inpGetModulation(sv) >> 7) & 0xff;
                if (mod >= ((lbl_803DE2E8.flags >> 8) & 0xff)) {
                    u8 *macro = dataGetMacro(lbl_803DE2E8.flags >> 0x10);
                    if (macro != 0) {
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
            delta = (sv->key << 0x10) - (((cmd >> 0x10) & 0xff) << 0x10);
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
            u32 curve;
            if (((*para1 >> 8) & 0xff) == 0) {
                sv->volume = (sv->volume * scale) / 0x7f;
            } else {
                sv->volume = (sv->volumeBase * scale) / 0x7f;
            }
            sv->volume += ((u8)(lbl_803DE2E8.flags >> 0x10)) << 0x10;
            if (sv->volume > 0x7f0000) {
                sv->volume = 0x7f0000;
            }
            curve = (lbl_803DE2E8.flags >> 0x18) | ((*para1 & 0xff) << 8);
            sv->volume = fn_802763C0(sv->volume, curve);
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
            if ((u8)sndRand() >= ((lbl_803DE2E8.flags >> 8) & 0xff)) {
                u8 *macro = dataGetMacro(lbl_803DE2E8.flags >> 0x10);
                if (macro != 0) {
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
            sScale = voiceAdsrSustainTable[inpGetMidiCtrl(cmd >> 0x18, sv->midiSlot, sv->midiEvent) >> 7];
            adsr.atime = ((MacDataTables *)lbl_8032EDD0)
                             ->midi2TimeTab[inpGetMidiCtrl((lbl_803DE2E8.flags >> 8) & 0xff,
                                                           sv->midiSlot, sv->midiEvent) >> 7];
            adsr.dtime = ((MacDataTables *)lbl_8032EDD0)
                             ->midi2TimeTab[inpGetMidiCtrl((lbl_803DE2E8.flags >> 0x10) & 0xff,
                                                           sv->midiSlot, sv->midiEvent) >> 7];
            adsr.slevel = 0xc1 - voiceAdsrDecayTable[(u32)(lbl_803E7810 * sScale)];
            adsr.rtime = ((MacDataTables *)lbl_8032EDD0)
                             ->midi2TimeTab[inpGetMidiCtrl((u8)*para1, sv->midiSlot,
                                                           sv->midiEvent) >> 7];
            adsr.ascale = 0x80000000;
            adsr.dscale = 0x80000000;
            hwSetADSR(sv->voiceHandle & 0xff, (u32 *)&adsr, 2);
            MAC_CFLAGS(sv) |= MAC_FLAG64(0, 0x100);
            break;
        }
        case 0x17: /* random key */
            mcmdRandomKey(sv, &lbl_803DE2E8);
            break;
        case 0x18: /* add key */
            if ((cmd >> 0x18) == 0) {
                sv->key += (s8)((cmd >> 8) & 0xff);
            } else {
                sv->key = sv->keyBase + (s8)((cmd >> 8) & 0xff);
            }
            sv->key = (s16)sv->key < 0 ? 0 : sv->key > 0x7f ? 0x7f : sv->key;
            sv->fineTune = (s8)(lbl_803DE2E8.flags >> 0x10);
            if (voiceIsRegistered((int)sv) != 0) {
                inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->key & 0xff);
            }
            lbl_803DE2E8.flags = 4;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x19: /* set key */
            sv->key = (cmd >> 8) & 0x7f;
            sv->fineTune = (s8)(lbl_803DE2E8.flags >> 0x10);
            if (voiceIsRegistered((int)sv) != 0) {
                inpSetMidiLastNote(sv->midiSlot, sv->midiEvent, sv->key & 0xff);
            }
            lbl_803DE2E8.flags = 4;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        case 0x1a: /* last key */
            sv->key = sv->registeredKey + (s8)((cmd >> 8) & 0xff);
            sv->key = (s16)sv->key < 0 ? 0 : sv->key > 0x7f ? 0x7f : sv->key;
            sv->fineTune = (s8)(lbl_803DE2E8.flags >> 0x10);
            if (sv->midiSlot != 0xff) {
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
            if (delta >= 0) {
                delta = hwExitStream(delta);
            } else {
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
            if (delta >= 0) {
                delta = hwExitStream(delta);
            } else {
                delta = -hwExitStream(-delta);
            }
            sv->sweepAdd[1] = delta << 0x10;
            lbl_803DE2E8.flags = 0;
            ex = mcmdWait(sv, &lbl_803DE2E8);
            break;
        }
        case 0x1f: /* set pitch */
            sv->targetPitch = cmd >> 8;
            sv->targetPitch |= (u8)*para1;
            if (sv->prevSampleId != 0xffffffff) {
                DoSetPitch(sv);
            }
            break;
        case 0x20: /* set pitch ADSR */
            mcmdSetPitchADSR(sv, &lbl_803DE2E8);
            break;
        case 0x21: /* scale volume DLS */
        {
            u16 scale = (cmd >> 8) & 0xffff;
            if ((cmd >> 0x18) == 0) {
                sv->volume = ((sv->volume >> 5) * scale) >> 7;
            } else {
                sv->volume = ((sv->volumeBase >> 5) * scale) >> 7;
            }
            if (sv->volume > 0x7f0000) {
                sv->volume = 0x7f0000;
            }
            MAC_CFLAGS(sv) |= MAC_FLAG64(0x1000, 0);
            break;
        }
        case 0x22: /* set mod2vibrato */
            sv->vibratoModAddScale = (s8)(cmd >> 8) << 8;
            if (sv->vibratoModAddScale >= 0) {
                sv->vibratoModAddScale += ((s16)(s8)(lbl_803DE2E8.flags >> 0x10) << 8) / 100;
            } else {
                sv->vibratoModAddScale -= ((s16)(s8)(lbl_803DE2E8.flags >> 0x10) << 8) / 100;
            }
            break;
        case 0x23: /* setup tremolo */
            sv->tremoloScale = (cmd >> 8) & 0xffff;
            sv->tremoloModAddScale = *para1;
            sv->tremoloCurScale = lbl_803E7814;
            break;
        case 0x24: /* return */
            if (sv->macroStackDepth != 0) {
                sv->macroBase = sv->macroStack[sv->macroStackIndex].macroBase;
                sv->macroCursor = sv->macroStack[sv->macroStackIndex].macroCursor;
                sv->macroStackIndex = (sv->macroStackIndex - 1) & 3;
                --sv->macroStackDepth;
            }
            break;
        case 0x25: /* gosub */
        {
            u8 *macro = dataGetMacro(cmd >> 0x10);
            u32 stop;
            if (macro != 0) {
                sv->macroStackIndex = (sv->macroStackIndex + 1) & 3;
                sv->macroStack[sv->macroStackIndex].macroBase = sv->macroBase;
                sv->macroStack[sv->macroStackIndex].macroCursor = sv->macroCursor;
                if (++sv->macroStackDepth > 4) {
                    sv->macroStackDepth = 4;
                }
                sv->macroBase = macro;
                stop = 0;
                sv->macroCursor = macro + ((*para1 & 0xffff) << 3);
            } else {
                vidRemoveVoice((int)sv);
                voiceFree((int)sv);
                stop = 1;
            }
            ex = stop;
            break;
        }
        case 0x28: /* trap event */
        {
            u8 *macro = dataGetMacro(cmd >> 0x10);
            if (macro != 0) {
                u32 t = (*para1 >> 8) & 0xff;
                sv->trapMacroBase[t] = macro;
                sv->trapMacroCursor[t] = macro + ((*para1 & 0xffff) << 3);
                sv->hasTriggerMacros = 1;
                if (t == 0 && (MAC_CFLAGS(sv) & MAC_FLAG64(0x100, 8)) == MAC_FLAG64(0x100, 8)) {
                    MAC_CFLAGS(sv) |= MAC_FLAG64(0x400, 0);
                }
            }
            break;
        }
        case 0x29: /* untrap event */
        {
            u32 i;
            sv->trapMacroBase[(cmd >> 8) & 0xff] = 0;
            for (i = 0; i < 3; i++) {
                if (sv->trapMacroBase[i] != 0) {
                    break;
                }
            }
            if (i >= 3) {
                sv->hasTriggerMacros = 0;
            }
            break;
        }
        case 0x2a: /* send message */
            mcmdSendMessage(sv, &lbl_803DE2E8);
            break;
        case 0x2b: /* get message */
        {
            u32 mesg = 0;
            if (sv->queuedMessageCount != 0) {
                mesg = sv->queuedMessages[sv->queuedMessageReadIndex];
                sv->queuedMessageReadIndex = (sv->queuedMessageReadIndex + 1) & 3;
                --sv->queuedMessageCount;
            }
            varSet32(sv, 0, (lbl_803DE2E8.flags >> 8) & 0xff, mesg);
            break;
        }
        case 0x2c: /* get VID */
            if (((cmd >> 0x10) & 0xff) == 0) {
                varSet32(sv, 0, (cmd >> 8) & 0xff, sv->vidListNode->id);
            } else {
                varSet32(sv, 0, (cmd >> 8) & 0xff, (u32)sv->cloneVidListNode);
            }
            break;
        case 0x30: /* add age counter */
        {
            s32 age = (sv->priorityValue >> 0xf) + (s16)(cmd >> 0x10);
            if (age < 0) {
                sv->priorityValue = 0;
            } else if (age > 0xffff) {
                sv->priorityValue = 0x7fff8000;
            } else {
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
            *(u32 *)(lbl_803BDA34 + ((cmd >> 8) & 0xff) * 4) = (cmd >> 0x10) & 0xff;
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
            voiceSetPriority((int)sv, (cmd >> 8) & 0xff);
            break;
        case 0x37: /* add priority */
        {
            s16 prio = sv->priorityGroup + (s16)(cmd >> 0x10);
            prio = prio < 0 ? 0 : prio > 0xff ? 0xff : prio;
            voiceSetPriority((int)sv, (u8)prio);
            break;
        }
        case 0x38: /* set age counter speed */
            if (*para1 != 0) {
                sv->priorityScale = (sv->priorityValue >> 8) / *para1;
            } else {
                sv->priorityScale = 0;
            }
            break;
        case 0x39: /* set age counter by volume */
        {
            u32 age = ((((sv->volume >> 0x10) & 0xff) * (*para1 & 0xffff)) >> 7) + (cmd >> 0x10);
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
            u32 i = *para1 >> 0x18;
            SelectSource(sv,
                         (McmdInputSlot *)(lbl_803BDEF4 + sv->auxB * 0x90 + i * 0x24),
                         &lbl_803DE2E8, ((MacDataTables *)lbl_8032EDD0)->auxAMask[i],
                         ((MacDataTables *)lbl_8032EDD0)->auxADirty[i]);
            break;
        }
        case 0x4e: /* aux B FX select */
        {
            u32 i = *para1 >> 0x18;
            SelectSource(sv,
                         (McmdInputSlot *)(lbl_803BDA74 + sv->auxB * 0x90 + i * 0x24),
                         &lbl_803DE2E8, ((MacDataTables *)lbl_8032EDD0)->auxBMask[i],
                         ((MacDataTables *)lbl_8032EDD0)->auxBDirty[i]);
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
            if (sv->exCtrls[n].rampFrames != 0) {
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
            varSet32(sv, (cmd >> 8) & 0xff, (cmd >> 0x10) & 0xff, (s16)*para1);
            break;
        case 0x70: /* if var equal */
        {
            s32 a;
            s32 b;
            u8 result;
            u32 idx = (cmd >> 0x10) & 0xff;
            if (((cmd >> 8) & 0xff) != 0) {
                a = (u16)inpGetExCtrl(sv, idx);
            } else {
                idx &= 0x1f;
                if (idx < 0x10) {
                    a = sv->localRegs[idx];
                } else {
                    a = SYNTH_GLOBAL_REG(idx);
                }
            }
            idx = (u8)*para1;
            if ((lbl_803DE2E8.flags >> 0x18) != 0) {
                b = (u16)inpGetExCtrl(sv, idx);
            } else {
                idx &= 0x1f;
                if (idx < 0x10) {
                    b = sv->localRegs[idx];
                } else {
                    b = SYNTH_GLOBAL_REG(idx);
                }
            }
            result = !(b - a);
            if (((*para1 >> 8) & 0xff) != 0) {
                result = !result;
            }
            if (result != 0) {
                sv->macroCursor = sv->macroBase + ((*para1 >> 0x10) << 3);
            }
            break;
        }
        case 0x71: /* if var less */
        {
            s32 a;
            s32 b;
            u8 result;
            u32 idx = (cmd >> 0x10) & 0xff;
            if (((cmd >> 8) & 0xff) != 0) {
                a = (u16)inpGetExCtrl(sv, idx);
            } else {
                idx &= 0x1f;
                if (idx < 0x10) {
                    a = sv->localRegs[idx];
                } else {
                    a = SYNTH_GLOBAL_REG(idx);
                }
            }
            idx = (u8)*para1;
            if ((lbl_803DE2E8.flags >> 0x18) != 0) {
                b = (u16)inpGetExCtrl(sv, idx);
            } else {
                idx &= 0x1f;
                if (idx < 0x10) {
                    b = sv->localRegs[idx];
                } else {
                    b = SYNTH_GLOBAL_REG(idx);
                }
            }
            result = a < b;
            if (((*para1 >> 8) & 0xff) != 0) {
                result = !result;
            }
            if (result != 0) {
                sv->macroCursor = sv->macroBase + ((*para1 >> 0x10) << 3);
            }
            break;
        }
        }
    } while (ex == 0);
}

/*
 * Advance the synth voice timer queue and process active voices.
 */
void macHandle(u32 delta)
{
    int timer;
    int active;
    u32 wakeLo;
    int wakeHi;
    int nextTimer;
    int hasAlt;
    u32 oldLo;
    McmdVoiceState *activeState;

    timer = macTimeQueueRoot;
    while (timer != 0) {
        wakeLo = *(u32 *)(timer + 0x9c);
        wakeHi = *(int *)(timer + 0x98);
        if (macRealTimeHi < (u32)(macRealTimeLo < wakeLo) + wakeHi) {
            break;
        }
        nextTimer = *(int *)(timer + 0x44);
        audioFn_80278990((McmdVoiceState *)timer);
        *(u32 *)(timer + 0xa4) = wakeLo;
        *(int *)(timer + 0xa0) = wakeHi;
        timer = nextTimer;
    }

    active = macActiveRoot;
    for (; active != 0; active = *(int *)(active + 0x3c)) {
        activeState = (McmdVoiceState *)active;
        if (activeState->hasTriggerMacros == 0) {
            hasAlt = 0;
        } else {
            hasAlt = activeState->sampleEndMacroBase != 0;
        }
        if (hasAlt && ((activeState->outputFlags & MCMD_VOICE_ACTIVE_OUTPUT_FLAG) == 0) &&
            hwIsActive(activeState->voiceHandle & 0xff) == 0 &&
            (activeState->hasTriggerMacros != 0 && activeState->sampleEndMacroBase != 0)) {
            activeState->macroCursor = activeState->sampleEndMacroCursor;
            activeState->macroBase = activeState->sampleEndMacroBase;
            activeState->sampleEndMacroBase = 0;
            audioFn_80278990((McmdVoiceState *)active);
        }
        macHandleActive((McmdVoiceState *)active);
    }
    oldLo = macRealTimeLo;
    macRealTimeLo = oldLo + delta;
    macRealTimeHi += CARRY4(oldLo, delta);
}

/*
 * Resume an active voice from its alternate command stream when needed.
 */
void macSampleEndNotify(int state)
{
    bool resumed;
    McmdVoiceState *voiceState;

    voiceState = (McmdVoiceState *)state;
    if (voiceState->queueMode == 1) {
        if (voiceState->hasTriggerMacros == 0 || voiceState->sampleEndMacroBase == 0) {
            resumed = false;
        } else {
            voiceState->macroCursor = voiceState->sampleEndMacroCursor;
            voiceState->macroBase = voiceState->sampleEndMacroBase;
            voiceState->sampleEndMacroBase = 0;
            audioFn_80278990((McmdVoiceState *)state);
            resumed = true;
        }
        if (!resumed && ((voiceState->outputFlags & MCMD_VOICE_INACTIVE_WAIT_OUTPUT_FLAG) != 0)) {
            audioFn_80278990((McmdVoiceState *)state);
        }
    }
}

/*
 * Mark a voice for key-off/release, falling back to its release stream.
 */
u32 macSetExternalKeyoff(int state)
{
    u32 resumed;
    u32 result;
    McmdVoiceState *voiceState;

    voiceState = (McmdVoiceState *)state;
    result = voiceState->inputFlags;
    voiceState->outputFlags |= MCMD_VOICE_KEYOFF_OUTPUT_FLAG;
    if (voiceState->macroBase != 0) {
        result = 0;
        if ((voiceState->inputFlags & MCMD_VOICE_KEYOFF_INPUT_FLAG) == 0) {
            if (voiceState->hasTriggerMacros == 0 || voiceState->keyoffMacroBase == 0) {
                resumed = 0;
            } else {
                voiceState->macroCursor = voiceState->keyoffMacroCursor;
                voiceState->macroBase = voiceState->keyoffMacroBase;
                voiceState->keyoffMacroBase = 0;
                audioFn_80278990((McmdVoiceState *)state);
                resumed = 1;
            }
            if (!resumed) {
                result = voiceState->outputFlags & MCMD_VOICE_KEYOFF_WAIT_OUTPUT_FLAG;
                if (result != 0) {
                    audioFn_80278990((McmdVoiceState *)state);
                }
            }
        } else {
            voiceState->inputFlags |= MCMD_VOICE_DEFERRED_KEYOFF_INPUT_FLAG;
        }
    }
    return result;
}

/*
 * Clear or defer the release request flag.
 */
void macSetPedalState(int state, u32 defer)
{
    u32 resumed;
    McmdVoiceState *voiceState;

    voiceState = (McmdVoiceState *)state;
    if (defer != 0) {
        voiceState->inputFlags |= MCMD_VOICE_KEYOFF_INPUT_FLAG;
    } else {
        if (voiceState->macroBase != 0 &&
            ((voiceState->inputFlags & MCMD_VOICE_DEFERRED_KEYOFF_INPUT_FLAG) != 0)) {
            if (voiceState->hasTriggerMacros == 0 || voiceState->keyoffMacroBase == 0) {
                resumed = 0;
            } else {
                voiceState->macroCursor = voiceState->keyoffMacroCursor;
                voiceState->macroBase = voiceState->keyoffMacroBase;
                voiceState->keyoffMacroBase = 0;
                audioFn_80278990((McmdVoiceState *)state);
                resumed = 1;
            }
            if (!resumed && ((voiceState->outputFlags & MCMD_VOICE_KEYOFF_WAIT_OUTPUT_FLAG) != 0)) {
                audioFn_80278990((McmdVoiceState *)state);
            }
        }
        voiceState->inputFlags &= ~(MCMD_VOICE_KEYOFF_INPUT_FLAG |
                                    MCMD_VOICE_DEFERRED_KEYOFF_INPUT_FLAG);
    }
}

/*
 * Insert a voice into the 64-bit wake-time queue sorted by 0x98:0x9c.
 */
void TimeQueueAdd(McmdVoiceState *state)
{
    McmdVoiceState *next;
    McmdVoiceState *prev;
    McmdVoiceState *cur;

    next = (McmdVoiceState *)macTimeQueueRoot;
    prev = 0;
    while ((cur = next) != 0 &&
           *(u64 *)&cur->wakeTimeHi < *(u64 *)&state->wakeTimeHi) {
        prev = cur;
        next = cur->timeNext;
    }

    if (cur == 0) {
        if (prev == 0) {
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
    if (prev != 0) {
        cur->timePrev->timeNext = state;
    } else {
        macTimeQueueRoot = (int)state;
    }
    cur->timePrev = state;
}

/*
 * Remove a voice from the time queue and clear its scheduled wake time.
 */
void fn_802788B4(McmdVoiceState *state, u32 skipFadeReset)
{
    u32 wakeHi;
    u32 wakeLo;
    McmdVoiceState *prev;
    McmdVoiceState *next;
    u32 zero;
    u32 allBits;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u32 flags118;
    u32 flags114;

    wakeHi = state->wakeTimeHi;
    zero = 0;
    wakeLo = state->wakeTimeLo;
    if (((wakeHi ^ zero) | (wakeLo ^ zero)) != 0) {
        allBits = 0xffffffff;
        if (((wakeLo ^ allBits) | (wakeHi ^ allBits)) != 0) {
            prev = state->timePrev;
            if (prev == 0) {
                macTimeQueueRoot = (int)state->timeNext;
            } else {
                prev->timeNext = state->timeNext;
            }
            next = state->timeNext;
            if (next != 0) {
                next->timePrev = state->timePrev;
            }
        }
        if (skipFadeReset == 0) {
            synthQueueVoicePrimaryUpdates(state);
        }
        state->wakeTimeLo = 0;
        state->wakeTimeHi = 0;
        activeTimeHi = macRealTimeHi;
        activeTimeLo = macRealTimeLo;
        state->activeTimeLo = activeTimeLo;
        state->activeTimeHi = activeTimeHi;
        flags118 = state->outputFlags;
        flags114 = state->inputFlags;
        state->outputFlags = flags118 & 0xfffbfffb;
        state->inputFlags = flags114 & allBits;
    }
}

/*
 * Move a live voice back onto the active voice list.
 */
void audioFn_80278990(McmdVoiceState *state)
{
    u32 wakeHi;
    u32 wakeLo;
    McmdVoiceState *prev;
    McmdVoiceState *next;
    u32 zero;
    u32 allBits;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u32 flags118;
    u32 flags114;
    u32 activeHead;

    if (state->queueMode != 0) {
        wakeHi = state->wakeTimeHi;
        zero = 0;
        wakeLo = state->wakeTimeLo;
        if (((wakeHi ^ zero) | (wakeLo ^ zero)) != 0) {
            allBits = 0xffffffff;
            if (((wakeLo ^ allBits) | (wakeHi ^ allBits)) != 0) {
                prev = state->timePrev;
                if (prev == 0) {
                    macTimeQueueRoot = (int)state->timeNext;
                } else {
                    prev->timeNext = state->timeNext;
                }
                next = state->timeNext;
                if (next != 0) {
                    next->timePrev = state->timePrev;
                }
            }
            synthQueueVoicePrimaryUpdates(state);
            state->wakeTimeLo = 0;
            state->wakeTimeHi = 0;
            activeTimeHi = macRealTimeHi;
            activeTimeLo = macRealTimeLo;
            state->activeTimeLo = activeTimeLo;
            state->activeTimeHi = activeTimeHi;
            flags118 = state->outputFlags;
            flags114 = state->inputFlags;
            state->outputFlags = flags118 & 0xfffbfffb;
            state->inputFlags = flags114 & allBits;
        }
        activeHead = macActiveRoot;
        state->activeNext = (McmdVoiceState *)activeHead;
        if (activeHead != 0) {
            ((McmdVoiceState *)macActiveRoot)->activePrev = state;
        }
        state->activePrev = 0;
        macActiveRoot = (int)state;
        state->queueMode = 0;
    }
}

/*
 * Change a voice list state, unlinking it from active or timer queues as needed.
 */
void fn_80278A98(McmdVoiceState *state, int mode)
{
    McmdVoiceState *activePrev;
    McmdVoiceState *activeNext;
    u32 wakeHi;
    u32 wakeLo;
    McmdVoiceState *prev;
    McmdVoiceState *next;
    u32 zero;
    u32 allBits;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u32 flags118;
    u32 flags114;

    if (state->queueMode == mode) {
        return;
    }
    if (state->queueMode == 0) {
        activePrev = state->activePrev;
        if (activePrev == 0) {
            macActiveRoot = (int)state->activeNext;
        } else {
            activePrev->activeNext = state->activeNext;
        }
        activeNext = state->activeNext;
        if (activeNext != 0) {
            activeNext->activePrev = state->activePrev;
        }
    }
    if (mode == 2) {
        wakeHi = state->wakeTimeHi;
        zero = 0;
        wakeLo = state->wakeTimeLo;
        if (((wakeHi ^ zero) | (wakeLo ^ zero)) != 0) {
            allBits = 0xffffffff;
            if (((wakeLo ^ allBits) | (wakeHi ^ allBits)) != 0) {
                prev = state->timePrev;
                if (prev == 0) {
                    macTimeQueueRoot = (int)state->timeNext;
                } else {
                    prev->timeNext = state->timeNext;
                }
                next = state->timeNext;
                if (next != 0) {
                    next->timePrev = state->timePrev;
                }
            }
            state->wakeTimeLo = 0;
            state->wakeTimeHi = 0;
            activeTimeHi = macRealTimeHi;
            activeTimeLo = macRealTimeLo;
            state->activeTimeLo = activeTimeLo;
            state->activeTimeHi = activeTimeHi;
            flags118 = state->outputFlags;
            flags114 = state->inputFlags;
            state->outputFlags = flags118 & 0xfffbfffb;
            state->inputFlags = flags114 & allBits;
        }
    }
    state->queueMode = mode;
}

/*
 * Allocate and initialize a synth voice from an instrument/sample command.
 */
int audioFn_80278b94(u16 instrumentKey, u32 priority, u32 maxInstances, u32 baseSample,
                u8 keyFlags, u8 volume, u8 pan, u32 midiSlot, u8 midiEvent, u8 midiLayer,
                u16 sampleOffsetIndex, u8 studio, u8 returnNewId, u8 auxA, u8 auxB,
                int startImmediately)
{
    int instrument;
    u8 streamKey;
    u32 streamKind;
    u32 midiPriority;
    u32 voiceId;
    int wasActive;
    int vid;
    int state;
    McmdVoiceState *voiceState;
    u32 activePrev;
    u32 activeNext;
    u32 activeHead;

    instrument = (int)dataGetMacro(instrumentKey);
    if (instrument != 0) {
        streamKey = keyFlags & 0x80;
        if (streamKey == 0) {
            midiPriority = seqGetMIDIPriority(midiEvent, midiSlot);
            if ((midiPriority & 0xffff) != 0xffff) {
                priority = midiPriority & 0xff;
            }
        }
        if (streamKey != 0) {
            streamKind = 1;
        } else {
            streamKind = 0;
        }
        voiceId = voiceAllocate(priority, maxInstances, baseSample, streamKind);
        if (voiceId != 0xffffffff) {
            state = (int)(synthVoice + voiceId * 0x404);
            voiceState = (McmdVoiceState *)state;
            vidRemoveVoice(state);
            if (*(int *)(state + 0x4c) != 2) {
                if (*(int *)(state + 0x4c) == 0) {
                    activePrev = *(u32 *)(state + 0x40);
                    if (activePrev == 0) {
                        macActiveRoot = *(int *)(state + 0x3c);
                    } else {
                        *(int *)(activePrev + 0x3c) = *(int *)(state + 0x3c);
                    }
                    activeNext = *(u32 *)(state + 0x3c);
                    if (activeNext != 0) {
                        *(int *)(activeNext + 0x40) = *(int *)(state + 0x40);
                    }
                }
                fn_802788B4((McmdVoiceState *)state, 1);
                *(int *)(state + 0x4c) = 2;
            }

            voiceState->outputFlags = (voiceState->outputFlags & 0x10) | 2;
            voiceState->inputFlags = 0;
            wasActive = hwIsActive(voiceId);
            if (wasActive != 0) {
                voiceState->outputFlags |= 1;
            }
            voiceState->wakeTimeLo = 0;
            voiceState->wakeTimeHi = 0;
            if (streamKey == 0) {
                voiceState->streamKind = 0;
                voiceState->startupMidiSlot = (u8)midiSlot;
                voiceState->startupMidiEvent = midiEvent;
                voiceState->startupMidiLayer = midiLayer;
            } else {
                voiceState->streamKind = 1;
                keyFlags &= 0x7f;
                inpResetMidiCtrl(voiceId & 0xff, 0xff, 1);
                inpResetChannelDefaults(voiceId & 0xff, 0xff);
                voiceState->startupMidiSlot = voiceId;
                voiceState->startupMidiEvent = 0xff;
                voiceState->startupMidiLayer = 0;
            }

            voiceState->instrumentKey = instrumentKey;
            voiceState->baseSample = (s16)baseSample;
            voiceState->priorityValue = 0x75300000;
            voiceState->priorityScale = 0x400;
            voiceState->macroBase = (u8 *)instrument;
            voiceState->macroCursor = (u8 *)(instrument + (u32)sampleOffsetIndex * 8);
            voiceState->keyBase = keyFlags;
            voiceState->key = keyFlags;
            voiceState->fineTune = 0;
            voiceState->startupVolume = volume;
            voiceState->startupPan = pan;
            voiceState->startupStudio = studio;
            voiceState->macroStackDepth = 0;
            voiceState->macroStackIndex = 0;
            voiceState->voiceNextHandle = -1;
            voiceState->voicePrevHandle = -1;
            voiceState->cloneVidListNode = (void *)-1;
            voiceState->startupAuxA = auxA;
            voiceState->startupAuxB = auxB;
            voiceState->startupDeferStart = startImmediately == 0;
            voiceState->queuedMessageWriteIndex = 0;
            voiceState->queuedMessageReadIndex = 0;
            voiceState->queuedMessageCount = 0;
            voiceState->voiceHandle = voiceId | ((u32)instrumentKey << 0x10) |
                                      ((u32)keyFlags << 8);
            voiceSetPriority(state, priority);
            vid = vidMakeNew(state, returnNewId);
            if (vid != -1) {
                if (*(int *)(state + 0x4c) == 0) {
                    return vid;
                }
                fn_802788B4((McmdVoiceState *)state, 0);
                activeHead = macActiveRoot;
                *(int *)(state + 0x3c) = activeHead;
                if (activeHead != 0) {
                    *(int *)(activeHead + 0x40) = state;
                }
                *(int *)(state + 0x40) = 0;
                macActiveRoot = state;
                *(int *)(state + 0x4c) = 0;
                return vid;
            }
            wasActive = hwIsActive(voiceId);
            if (wasActive != 0) {
                hwBreak(voiceId);
            }
            voiceFree(state);
        }
    }
    return -1;
}

/*
 * Reset the global voice list heads and per-voice list bookkeeping.
 */
void fn_80278EA4(void)
{
    int offset;
    u32 i;

    macRealTimeLo = 0;
    offset = 0;
    macActiveRoot = 0;
    macTimeQueueRoot = 0;
    macRealTimeHi = 0;
    for (i = 0; i < *(u32 *)(lbl_803BD150 + 0x210); i++) {
        *(u32 *)(synthVoice + offset + 0x34) = 0;
        *(u32 *)(synthVoice + offset + 0x4c) = 2;
        *(u16 *)(synthVoice + offset + 0xaa) = 0;
        offset += 0x404;
    }
}
