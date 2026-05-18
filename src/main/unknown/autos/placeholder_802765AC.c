#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802765AC.h"
#include "main/unknown/autos/placeholder_80279608.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_8026fc8c();
extern undefined4 FUN_80271a2c();
extern undefined4 FUN_80271ad4();
extern int FUN_80275364();
extern int FUN_8027566c();
extern uint FUN_802757d4();
extern undefined4 FUN_802757dc();
extern undefined4 FUN_802757e0();
extern undefined4 FUN_802757e4();
extern undefined4 FUN_802757e8();
extern undefined4 FUN_802763c0();
extern uint FUN_80279008();
extern undefined4 FUN_8027975c();
extern uint FUN_8027976c();
extern undefined4 FUN_80279c7c();
extern undefined4 FUN_8027a664();
extern int FUN_8027a8fc();
extern undefined4 FUN_8027a904();
extern undefined4 FUN_8027ac38();
extern undefined4 FUN_8028134c();
extern undefined4 FUN_80281a30();
extern uint FUN_80282070();
extern void* FUN_80282078();
extern undefined4 FUN_80282588();
extern undefined4 FUN_8028261c();
extern char FUN_80282620();
extern uint FUN_802827f8();
extern undefined4 FUN_80282fe0();
extern uint FUN_8028343c();
extern undefined4 FUN_80283444();
extern uint FUN_8028348c();
extern undefined4 FUN_802836ac();
extern undefined4 FUN_802836e8();
extern uint FUN_80283710();
extern bool FUN_80283844();
extern undefined4 FUN_80283850();
extern undefined4 FUN_80283ba0();
extern undefined4 FUN_80283bd4();
extern undefined4 FUN_80283e04();
extern undefined4 FUN_80283e08();
extern int FUN_80284468();
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
extern void hwBreak(int slot);
extern void voiceFree(int state);
extern void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
extern void inpResetChannelDefaults(u8 a, u8 b);
void audioFn_80278990(int state);
void fn_802788B4(int state, u32 skipFadeReset);
u32 macSetExternalKeyoff(int state);
extern u32 inpGetExCtrl(int state, u32 ctrl);
extern void inpSetExCtrl(int state, u32 ctrl, s16 value);
extern void voiceKill(u32 voice);
extern u8 lbl_803BDA34[];
extern void sndConvertTicks(u32 *p, McmdVoiceState *state);
extern void sndConvertMs(u32 *p);
extern void inpSetMidiCtrl(int idx, u8 a, u8 b, u8 mask);
extern u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key);
extern void fn_8026F5B8(int state);
extern u16 sndRand(void);
extern int voiceIsRegistered(int state);
extern void inpSetMidiLastNote(u8 a, u8 b, u8 v);
extern int mcmdWait(McmdVoiceState *state, McmdCommandArgs *args);
extern void inpAddCtrl(int obj, int b, int c, int d, u32 flag);
extern void inpSetGlobalMIDIDirtyFlag(u8 a, u8 b, u32 flag);
extern int vidGetInternalId(u32 id);
extern void (*synthMessageCallback)(u32 id);

#define SYNTH_VOICE_STRIDE 0x404
#define SYNTH_GLOBAL_REG(index) (*(u32 *)(lbl_803BDA34 + (index) * 4 - 0x40))

/*
 * --INFO--
 *
 * Function: FUN_8027656c
 * EN v1.0 Address: 0x8027656C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802765AC
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027656c(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276570
 * EN v1.0 Address: 0x80276570
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276804
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276570(int param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276574
 * EN v1.0 Address: 0x80276574
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276A84
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276574(int param_1,uint *param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276578
 * EN v1.0 Address: 0x80276578
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80276B24
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80276578(uint param_1,short param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80276580
 * EN v1.0 Address: 0x80276580
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276BA4
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276580(int param_1,uint *param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276584
 * EN v1.0 Address: 0x80276584
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276CD0
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276584(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276588
 * EN v1.0 Address: 0x80276588
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276E70
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276588(int param_1,int param_2,uint *param_3,undefined4 param_4,uint param_5,uint param_6
                 ,uint param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8027658c
 * EN v1.0 Address: 0x8027658C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276FA4
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027658c(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276590
 * EN v1.0 Address: 0x80276590
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80277108
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80276590(int param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80276598
 * EN v1.0 Address: 0x80276598
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8027716C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80276598(int param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802765a0
 * EN v1.0 Address: 0x802765A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802771D4
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765a0(int param_1,int param_2,uint param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765a4
 * EN v1.0 Address: 0x802765A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80277238
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765a4(int param_1,uint *param_2,byte param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765a8
 * EN v1.0 Address: 0x802765A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80277368
 * EN v1.1 Size: 564b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765a8(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765ac
 * EN v1.0 Address: 0x802765AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8027759C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765ac(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765b0
 * EN v1.0 Address: 0x802765B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80277670
 * EN v1.1 Size: 5388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765b0(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765b4
 * EN v1.0 Address: 0x802765B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278B7C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765b4(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765b8
 * EN v1.0 Address: 0x802765B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278CC4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765b8(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765bc
 * EN v1.0 Address: 0x802765BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80278D74
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_802765bc(int *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802765c4
 * EN v1.0 Address: 0x802765C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278E68
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765c4(int *param_1,int param_2)
{
}

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
#pragma scheduling off
#pragma peephole off
void SelectSource(int state, int ctrlObj, u32 *args, int unused, u32 stateFlag,
                  u32 activeFlag, u32 dirtyFlag)
{
    u32 command;
    u32 inputFlags;
    u32 outputFlags;
    u32 zero;
    int baseValue;
    int signedDelta;
    u32 ctrlValue;

    (void)unused;
    zero = 0;
    inputFlags = *(u32 *)(state + 0x114);
    outputFlags = *(u32 *)(state + 0x118);
    if (((inputFlags & stateFlag) | (outputFlags & activeFlag)) == zero) {
        *(u32 *)(state + 0x118) = outputFlags | activeFlag;
        ctrlValue = 0;
        *(u32 *)(state + 0x114) = inputFlags | stateFlag;
    } else {
        ctrlValue = args[1] & 0xff;
    }

    command = *args;
    baseValue = (int)(command & 0xffff0000) / 100;
    if (baseValue < 0) {
        signedDelta = ((s8)(args[1] >> 0x10) << 8) / 100;
        signedDelta = -signedDelta;
    } else {
        signedDelta = ((s8)(args[1] >> 0x10) << 8) / 100;
    }

    inpAddCtrl(ctrlObj, (command >> 8) & 0xff, baseValue + signedDelta, ctrlValue,
               ((args[1] >> 8) & 0xff) != 0);
    if ((dirtyFlag & 0x80000000) != 0) {
        inpSetGlobalMIDIDirtyFlag(*(u8 *)(state + 0x121), *(u8 *)(state + 0x122),
                                  dirtyFlag);
    } else {
        *(u32 *)(state + 0x214) |= dirtyFlag;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * Read a 32-bit synth register, either from the voice or EX controller bank.
 */
#pragma dont_inline on
u32 varGet32(McmdVoiceState *state, u32 useExCtrl, u32 index)
{
    u32 value;

    if (useExCtrl != 0) {
        value = inpGetExCtrl((int)state, index);
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
        value = inpGetExCtrl((int)state, index) & 0xffff;
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
        inpSetExCtrl((int)state, index, (s16)value);
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
 * Configure the controller-0x41 ramp trigger for the current voice.
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
        sndConvertTicks(duration, state);
    }
    state->portamentoDuration = duration[0];
    mode = (args->flags >> 8) & 0xff;
    if (mode == 1) {
        if (state->midiSlot != 0xff) {
            inpSetMidiCtrl(0x41, state->midiSlot, state->midiEvent, 0x7f);
        }
    } else {
        if (mode == 0) {
            if (state->midiSlot != 0xff) {
                inpSetMidiCtrl(0x41, state->midiSlot, state->midiEvent, 0);
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
        if ((u16)inpGetMidiCtrl(0x41, state->midiSlot, state->midiEvent) <= 0x1f80) {
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
                                audioFn_80278990(voice);
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
                    audioFn_80278990(voice);
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
 * Large per-voice command dispatcher. Stubbed, but named so callers can
 * reference the recovered current EN boundary.
 */
#pragma dont_inline on
void macHandleActive(int state)
{
    (void)state;
}
#pragma dont_inline reset

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
        audioFn_80278990(timer);
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
            audioFn_80278990(active);
        }
        macHandleActive(active);
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
            audioFn_80278990(state);
            resumed = true;
        }
        if (!resumed && ((voiceState->outputFlags & MCMD_VOICE_INACTIVE_WAIT_OUTPUT_FLAG) != 0)) {
            audioFn_80278990(state);
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
                audioFn_80278990(state);
                resumed = 1;
            }
            if (!resumed) {
                result = voiceState->outputFlags & MCMD_VOICE_KEYOFF_WAIT_OUTPUT_FLAG;
                if (result != 0) {
                    audioFn_80278990(state);
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
                audioFn_80278990(state);
                resumed = 1;
            }
            if (!resumed && ((voiceState->outputFlags & MCMD_VOICE_KEYOFF_WAIT_OUTPUT_FLAG) != 0)) {
                audioFn_80278990(state);
            }
        }
        voiceState->inputFlags &= ~(MCMD_VOICE_KEYOFF_INPUT_FLAG |
                                    MCMD_VOICE_DEFERRED_KEYOFF_INPUT_FLAG);
    }
}

/*
 * Insert a voice into the 64-bit wake-time queue sorted by 0x98:0x9c.
 */
void TimeQueueAdd(int state)
{
    u32 next;
    u32 prev;
    u32 cur;

    next = macTimeQueueRoot;
    prev = 0;
    while ((cur = next) != 0 &&
           (*(u32 *)(cur + 0x98) < *(u32 *)(state + 0x98) ||
            (*(u32 *)(cur + 0x98) == *(u32 *)(state + 0x98) &&
             *(u32 *)(cur + 0x9c) < *(u32 *)(state + 0x9c)))) {
        prev = cur;
        next = *(int *)(cur + 0x44);
    }

    if (cur == 0) {
        if (prev == 0) {
            macTimeQueueRoot = state;
            *(int *)(state + 0x44) = 0;
            *(int *)(state + 0x48) = 0;
            return;
        }

        *(int *)(prev + 0x44) = state;
        *(int *)(state + 0x48) = prev;
        *(int *)(state + 0x44) = 0;
        return;
    }

    *(int *)(state + 0x44) = cur;
    prev = *(int *)(cur + 0x48);
    *(int *)(state + 0x48) = prev;
    if (prev != 0) {
        *(int *)(*(int *)(cur + 0x48) + 0x44) = state;
    } else {
        macTimeQueueRoot = state;
    }
    *(int *)(cur + 0x48) = state;
}

/*
 * Remove a voice from the time queue and clear its scheduled wake time.
 */
void fn_802788B4(int state, u32 skipFadeReset)
{
    u32 wakeHi;
    u32 wakeLo;
    u32 prev;
    u32 next;
    u32 zero;
    u32 allBits;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u32 flags118;
    u32 flags114;

    wakeHi = *(u32 *)(state + 0x98);
    zero = 0;
    wakeLo = *(u32 *)(state + 0x9c);
    if (((wakeHi ^ zero) | (wakeLo ^ zero)) != 0) {
        allBits = 0xffffffff;
        if (((wakeLo ^ allBits) | (wakeHi ^ allBits)) != 0) {
            prev = *(u32 *)(state + 0x48);
            if (prev == 0) {
                macTimeQueueRoot = *(int *)(state + 0x44);
            } else {
                *(int *)(prev + 0x44) = *(int *)(state + 0x44);
            }
            next = *(u32 *)(state + 0x44);
            if (next != 0) {
                *(int *)(next + 0x48) = *(int *)(state + 0x48);
            }
        }
        if (skipFadeReset == 0) {
            synthQueueVoicePrimaryUpdates((void *)state);
        }
        *(int *)(state + 0x9c) = 0;
        *(int *)(state + 0x98) = 0;
        activeTimeHi = macRealTimeHi;
        activeTimeLo = macRealTimeLo;
        *(int *)(state + 0xa4) = activeTimeLo;
        *(int *)(state + 0xa0) = activeTimeHi;
        flags118 = *(u32 *)(state + 0x118);
        flags114 = *(u32 *)(state + 0x114);
        *(u32 *)(state + 0x118) = flags118 & 0xfffbfffb;
        *(u32 *)(state + 0x114) = flags114 & allBits;
    }
}

/*
 * Move a live voice back onto the active voice list.
 */
void audioFn_80278990(int state)
{
    u32 wakeHi;
    u32 wakeLo;
    u32 prev;
    u32 next;
    u32 zero;
    u32 allBits;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u32 flags118;
    u32 flags114;
    u32 activeHead;

    if (*(int *)(state + 0x4c) != 0) {
        wakeHi = *(u32 *)(state + 0x98);
        zero = 0;
        wakeLo = *(u32 *)(state + 0x9c);
        if (((wakeHi ^ zero) | (wakeLo ^ zero)) != 0) {
            allBits = 0xffffffff;
            if (((wakeLo ^ allBits) | (wakeHi ^ allBits)) != 0) {
                prev = *(u32 *)(state + 0x48);
                if (prev == 0) {
                    macTimeQueueRoot = *(int *)(state + 0x44);
                } else {
                    *(int *)(prev + 0x44) = *(int *)(state + 0x44);
                }
                next = *(u32 *)(state + 0x44);
                if (next != 0) {
                    *(int *)(next + 0x48) = *(int *)(state + 0x48);
                }
            }
            synthQueueVoicePrimaryUpdates((void *)state);
            *(int *)(state + 0x9c) = 0;
            *(int *)(state + 0x98) = 0;
            activeTimeHi = macRealTimeHi;
            activeTimeLo = macRealTimeLo;
            *(int *)(state + 0xa4) = activeTimeLo;
            *(int *)(state + 0xa0) = activeTimeHi;
            flags118 = *(u32 *)(state + 0x118);
            flags114 = *(u32 *)(state + 0x114);
            *(u32 *)(state + 0x118) = flags118 & 0xfffbfffb;
            *(u32 *)(state + 0x114) = flags114 & allBits;
        }
        activeHead = macActiveRoot;
        *(int *)(state + 0x3c) = activeHead;
        if (activeHead != 0) {
            *(int *)(macActiveRoot + 0x40) = state;
        }
        *(int *)(state + 0x40) = 0;
        macActiveRoot = state;
        *(int *)(state + 0x4c) = 0;
    }
}

/*
 * Change a voice list state, unlinking it from active or timer queues as needed.
 */
void fn_80278A98(int state, int mode)
{
    u32 activePrev;
    u32 activeNext;
    u32 wakeHi;
    u32 wakeLo;
    u32 prev;
    u32 next;
    u32 zero;
    u32 allBits;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u32 flags118;
    u32 flags114;

    if (*(int *)(state + 0x4c) == mode) {
        return;
    }
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
    if (mode == 2) {
        wakeHi = *(u32 *)(state + 0x98);
        zero = 0;
        wakeLo = *(u32 *)(state + 0x9c);
        if (((wakeHi ^ zero) | (wakeLo ^ zero)) != 0) {
            allBits = 0xffffffff;
            if (((wakeLo ^ allBits) | (wakeHi ^ allBits)) != 0) {
                prev = *(u32 *)(state + 0x48);
                if (prev == 0) {
                    macTimeQueueRoot = *(int *)(state + 0x44);
                } else {
                    *(int *)(prev + 0x44) = *(int *)(state + 0x44);
                }
                next = *(u32 *)(state + 0x44);
                if (next != 0) {
                    *(int *)(next + 0x48) = *(int *)(state + 0x48);
                }
            }
            *(int *)(state + 0x9c) = 0;
            *(int *)(state + 0x98) = 0;
            activeTimeHi = macRealTimeHi;
            activeTimeLo = macRealTimeLo;
            *(int *)(state + 0xa4) = activeTimeLo;
            *(int *)(state + 0xa0) = activeTimeHi;
            flags118 = *(u32 *)(state + 0x118);
            flags114 = *(u32 *)(state + 0x114);
            *(u32 *)(state + 0x118) = flags118 & 0xfffbfffb;
            *(u32 *)(state + 0x114) = flags114 & allBits;
        }
    }
    *(int *)(state + 0x4c) = mode;
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
                fn_802788B4(state, 1);
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
            *(u8 *)(state + 0x8c) = 0;
            *(u8 *)(state + 0x8d) = 0;
            voiceState->voiceNextHandle = -1;
            voiceState->voicePrevHandle = -1;
            voiceState->cloneVidListNode = (void *)-1;
            voiceState->startupAuxA = auxA;
            voiceState->startupAuxB = auxB;
            voiceState->startupDeferStart = startImmediately == 0;
            voiceState->queuedMessageWriteIndex = 0;
            voiceState->unk3ED = 0;
            voiceState->queuedMessageCount = 0;
            voiceState->voiceHandle = voiceId | ((u32)instrumentKey << 0x10) |
                                      ((u32)keyFlags << 8);
            voiceSetPriority(state, priority);
            vid = vidMakeNew(state, returnNewId);
            if (vid != -1) {
                if (*(int *)(state + 0x4c) == 0) {
                    return vid;
                }
                fn_802788B4(state, 0);
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
