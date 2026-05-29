#include "ghidra_import.h"
#include "main/audio/mcmd.h"

extern u16 sndRand(void);
extern void sndConvertTicks(u32 *p, McmdVoiceState *state);
extern void sndConvertMs(u32 *p);
extern void TimeQueueAdd(McmdVoiceState *state);
extern void fn_80278A98(McmdVoiceState *state, int mode);
extern int hwIsActive(int slot);
extern u32 macRealTimeHi;
extern u32 macRealTimeLo;

/*
 * Delay/schedule a voice command, optionally randomizing the delay and
 * inserting the voice into the global time queue.
 */
int mcmdWait(McmdVoiceState *state, McmdCommandArgs *args)
{
    u32 delay;
    u32 rand;
    u32 lo;
    u32 hi;
    u32 isMs;
    u64 wake;

    delay = args->value >> 0x10;
    if (delay != 0) {
        if ((args->flags & MCMD_LOOP_WAIT_FOR_KEYOFF_FLAG) == 0) {
            state->outputFlags &= 0xfffffffb;
            state->inputFlags &= 0xffffffff;
        } else {
            if ((state->outputFlags & MCMD_VOICE_KEYOFF_OUTPUT_FLAG) != 0) {
                if ((state->inputFlags & MCMD_VOICE_KEYOFF_INPUT_FLAG) == 0) {
                    return 0;
                }
                state->outputFlags &= 0xffffffff;
                state->inputFlags |= MCMD_VOICE_DEFERRED_KEYOFF_INPUT_FLAG;
            }
            state->outputFlags |= MCMD_VOICE_KEYOFF_WAIT_OUTPUT_FLAG;
        }

        if ((args->flags & MCMD_LOOP_WAIT_FOR_INACTIVE_FLAG) == 0) {
            state->outputFlags &= 0xfffbffff;
            state->inputFlags &= 0xffffffff;
        } else {
            if (((state->outputFlags & MCMD_VOICE_ACTIVE_OUTPUT_FLAG) == 0) &&
                hwIsActive(state->voiceHandle & 0xff) == 0) {
                return 0;
            }
            state->outputFlags |= MCMD_VOICE_INACTIVE_WAIT_OUTPUT_FLAG;
        }

        if ((args->flags & MCMD_LOOP_RANDOM_DELAY_FLAG) != 0) {
            rand = sndRand();
            delay = (rand & 0xffff) - ((rand & 0xffff) / delay) * delay;
        }

        if (delay == 0xffff) {
            state->wakeTimeLo = 0xffffffff;
            state->wakeTimeHi = 0xffffffff;
        } else {
            isMs = (args->value & MCMD_WAIT_TIME_UNIT_MS_FLAG) != 0;
            if (isMs != 0) {
                sndConvertMs(&delay);
            } else {
                sndConvertTicks(&delay, state);
            }
            if (isMs == 0) {
                if ((args->value & MCMD_WAIT_ABSOLUTE_TIME_FLAG) == 0) {
                    lo = state->activeTimeLo;
                    hi = state->activeTimeHi;
                    wake = (((u64)hi << 32) | lo) + delay;
                    state->wakeTimeLo = (u32)wake;
                    state->wakeTimeHi = (u32)(wake >> 32);
                } else {
                    state->wakeTimeLo = delay;
                    state->wakeTimeHi = 0;
                }
            } else {
                if ((args->value & MCMD_WAIT_ABSOLUTE_TIME_FLAG) == 0) {
                    lo = macRealTimeLo;
                    hi = macRealTimeHi;
                    wake = (((u64)hi << 32) | lo) + delay;
                    state->wakeTimeLo = (u32)wake;
                    state->wakeTimeHi = (u32)(wake >> 32);
                } else {
                    lo = state->startTimeLo;
                    hi = state->startTimeHi;
                    wake = (((u64)hi << 32) | lo) + delay;
                    state->wakeTimeLo = (u32)wake;
                    state->wakeTimeHi = (u32)(wake >> 32);
                }
            }

            if ((u32)(macRealTimeLo < state->wakeTimeLo) + state->wakeTimeHi <= macRealTimeHi) {
                state->activeTimeLo = state->wakeTimeLo;
                state->activeTimeHi = state->wakeTimeHi;
                state->wakeTimeLo = 0;
                state->wakeTimeHi = 0;
            }
        }

        if ((state->wakeTimeLo | state->wakeTimeHi) != 0) {
            if ((state->wakeTimeLo ^ 0xffffffff | state->wakeTimeHi ^ 0xffffffff) != 0) {
                TimeQueueAdd(state);
            }
            fn_80278A98(state, 1);
            return 1;
        }
    }
    return 0;
}
