#include "ghidra_import.h"

extern u16 sndRand(void);
extern void sndConvertTicks(u32 *p, int state);
extern void sndConvertMs(u32 *p);
extern void TimeQueueAdd(int state);
extern void fn_80278A98(int state, int mode);
extern int hwIsActive(int slot);
extern u32 macRealTimeHi;
extern u32 macRealTimeLo;

/*
 * Delay/schedule a voice command, optionally randomizing the delay and
 * inserting the voice into the global time queue.
 */
int mcmdWait(int state, u32 *args)
{
    u32 delay[2];
    u32 rand;
    u32 nowHi;
    int carry;

    delay[0] = args[1] >> 0x10;
    if (delay[0] != 0) {
        if (((*args >> 8) & 1) == 0) {
            *(u32 *)(state + 0x118) &= 0xfffffffb;
            *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
        } else {
            if ((*(u32 *)(state + 0x118) & 8) != 0) {
                if ((*(u32 *)(state + 0x114) & 0x100) == 0) {
                    return 0;
                }
                *(u32 *)(state + 0x118) = *(u32 *)(state + 0x118);
                *(u32 *)(state + 0x114) |= 0x400;
            }
            *(u32 *)(state + 0x118) |= 4;
        }

        if (((*args >> 0x18) & 1) == 0) {
            *(u32 *)(state + 0x118) &= 0xfffbffff;
            *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
        } else {
            if (((*(u32 *)(state + 0x118) & 0x20) == 0) &&
                hwIsActive(*(u32 *)(state + 0xf4) & 0xff) == 0) {
                return 0;
            }
            *(u32 *)(state + 0x118) |= 0x40000;
        }

        if (((*args >> 0x10) & 1) != 0) {
            rand = sndRand();
            delay[0] = (rand & 0xffff) - ((rand & 0xffff) / delay[0]) * delay[0];
        }

        if (delay[0] == 0xffff) {
            *(u32 *)(state + 0x9c) = 0xffffffff;
            *(u32 *)(state + 0x98) = 0xffffffff;
        } else {
            if (((args[1] >> 8) & 1) == 0) {
                sndConvertTicks(delay, state);
                if ((args[1] & 1) == 0) {
                    *(u32 *)(state + 0x9c) = *(u32 *)(state + 0xa4) + delay[0];
                    *(u32 *)(state + 0x98) =
                        *(int *)(state + 0xa0) + CARRY4(*(u32 *)(state + 0xa4), delay[0]);
                } else {
                    *(u32 *)(state + 0x9c) = delay[0];
                    *(u32 *)(state + 0x98) = 0;
                }
            } else {
                sndConvertMs(delay);
                nowHi = macRealTimeHi;
                if ((args[1] & 1) == 0) {
                    carry = CARRY4(macRealTimeLo, delay[0]);
                    *(u32 *)(state + 0x9c) = macRealTimeLo + delay[0];
                    *(u32 *)(state + 0x98) = nowHi + carry;
                } else {
                    *(u32 *)(state + 0x9c) = *(u32 *)(state + 0x94) + delay[0];
                    *(u32 *)(state + 0x98) =
                        *(int *)(state + 0x90) + CARRY4(*(u32 *)(state + 0x94), delay[0]);
                }
            }

            if ((u32)(macRealTimeLo < *(u32 *)(state + 0x9c)) + *(int *)(state + 0x98) <=
                macRealTimeHi) {
                *(u32 *)(state + 0xa4) = *(u32 *)(state + 0x9c);
                *(u32 *)(state + 0xa0) = *(u32 *)(state + 0x98);
                *(u32 *)(state + 0x9c) = 0;
                *(u32 *)(state + 0x98) = 0;
            }
        }

        if ((*(u32 *)(state + 0x9c) | *(u32 *)(state + 0x98)) != 0) {
            if ((*(u32 *)(state + 0x9c) ^ 0xffffffff |
                 *(u32 *)(state + 0x98) ^ 0xffffffff) != 0) {
                TimeQueueAdd(state);
            }
            fn_80278A98(state, 1);
            return 1;
        }
    }
    return 0;
}
