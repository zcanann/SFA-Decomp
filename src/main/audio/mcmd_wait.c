#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/mcmd_exec.h"
#include "main/audio/hw_init.h"

extern u16 sndRand(void);
extern void sndConvertTicks(u32 * p, McmdVoiceState * state);
extern void sndConvertMs(u32 * p);



extern u64 macRealTimeHi; /* u64 macRealTime: lo word = macRealTimeLo */

/* 64-bit control-flag word overlaying inputFlags(hi)/outputFlags(lo). */
#define MAC_CFLAGS(sv) (*(u64 *)&(sv)->inputFlags)
#define MAC_FLAG64(hi, lo) (((u64)(hi) << 32) | (u64)(lo))

#define MAC_WAIT(sv) (*(u64 *)&(sv)->wakeTimeHi)
#define MAC_START_TIME(sv) (*(u64 *)&(sv)->startTimeHi)
#define MAC_WAIT_TIME(sv) (*(u64 *)&(sv)->activeTimeHi)
#define MAC_REALTIME macRealTimeHi

/*
 * Delay/schedule a voice command, optionally randomizing the delay and
 * inserting the voice into the global time queue.
 */
int mcmdWait(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    u32 w;
    u32 ms;

    if ((ms = cstep->value >> 0x10))
    {
        if ((u8)(cstep->flags >> 8) & 1)
        {
            if (MAC_CFLAGS(svoice) & MAC_FLAG64(0, 8))
            {
                if (!(MAC_CFLAGS(svoice) & MAC_FLAG64(0x100, 0)))
                {
                    return 0;
                }
                MAC_CFLAGS(svoice) |= MAC_FLAG64(0x400, 0);
            }
            MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 4);
        }
        else
        {
            MAC_CFLAGS(svoice) &= ~MAC_FLAG64(0, 4);
        }

        if ((u8)(cstep->flags >> 0x18) & 1)
        {
            if (!(MAC_CFLAGS(svoice) & MAC_FLAG64(0, 0x20)) &&
                !hwIsActive(svoice->voiceHandle & 0xff))
            {
                return 0;
            }
            MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 0x40000);
        }
        else
        {
            MAC_CFLAGS(svoice) &= ~MAC_FLAG64(0, 0x40000);
        }

        if ((u8)(cstep->flags >> 0x10) & 1)
        {
            ms = sndRand() % ms;
        }

        if (ms != 0xFFFF)
        {
            if ((w = ((u8)(cstep->value >> 8) & 1) != 0))
            {
                sndConvertMs(&ms);
            }
            else
            {
                sndConvertTicks(&ms, svoice);
            }

            if (w != 0)
            {
                if ((u8)cstep->value & 1)
                {
                    MAC_WAIT(svoice) = MAC_START_TIME(svoice) + ms;
                }
                else
                {
                    MAC_WAIT(svoice) = MAC_REALTIME + ms;
                }
            }
            else
            {
                if ((u8)cstep->value & 1)
                {
                    MAC_WAIT(svoice) = ms;
                }
                else
                {
                    MAC_WAIT(svoice) = MAC_WAIT_TIME(svoice) + ms;
                }
            }

            if (!(MAC_WAIT(svoice) > MAC_REALTIME))
            {
                MAC_WAIT_TIME(svoice) = MAC_WAIT(svoice);
                MAC_WAIT(svoice) = 0;
            }
        }
        else
        {
            MAC_WAIT(svoice) = (u64) - 1;
        }

        if (MAC_WAIT(svoice) != 0)
        {
            if (MAC_WAIT(svoice) != (u64) - 1)
            {
                TimeQueueAdd(svoice);
            }
            macMakeInactive(svoice, 1);
            return 1;
        }
    }

    return 0;
}
