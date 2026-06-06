#ifndef MAIN_AUDIO_SYNTH_VOICE_H_
#define MAIN_AUDIO_SYNTH_VOICE_H_

#include "global.h"

/* Synth voice record, stride 0x404 off synthVoice; field names/offsets from
 * upstream musyx (MP4 musyx/synth.h SYNTH_VOICE), verified against SFA
 * codegen (synthInit store pattern, voice_id/vid list walkers, the
 * portamento block). Unverified regions left padded. */
typedef struct SynthVoice {
    u8 pad0[0xec];
    u32 child;             /* 0xec */
    u32 parent;            /* 0xf0 */
    u32 id;                /* 0xf4 */
    u32 vidList;           /* 0xf8 */
    u32 vidMasterList;     /* 0xfc */
    u16 allocId;           /* 0x100 */
    u16 macroId;           /* 0x102 */
    u8 keyGroup;           /* 0x104 */
    u8 pad105[7];          /* 0x105 */
    u8 prio;               /* 0x10c */
    u8 pad10D[3];          /* 0x10d */
    u32 age;               /* 0x110 */
    u32 cFlags[2];         /* 0x114: u64 upstream; MWCC 8-aligns a real u64 member, so spell u64 reads *(u64 *)&cFlags */
    u8 block;              /* 0x11c */
    u8 fxFlag;             /* 0x11d */
    u8 vGroup;             /* 0x11e */
    u8 studio;             /* 0x11f */
    u8 track;              /* 0x120 */
    u8 midi;               /* 0x121 */
    u8 midiSet;            /* 0x122 */
    u8 section;            /* 0x123 */
    u32 sInfo;             /* 0x124 */
    u32 playFrq;           /* 0x128 */
    u16 curNote;           /* 0x12c */
    s8 curDetune;          /* 0x12e */
    u8 orgNote;            /* 0x12f */
    u8 lastNote;           /* 0x130 */
    u8 portType;           /* 0x131 */
    u16 portLastCtrlState; /* 0x132 */
    u32 portDuration;      /* 0x134 */
    u32 portCurPitch;      /* 0x138 */
    u32 portTime;          /* 0x13c */
    u8 pad140[0x404 - 0x140];
} SynthVoice; /* size 0x404 */

STATIC_ASSERT(offsetof(SynthVoice, child) == 0xec);
STATIC_ASSERT(offsetof(SynthVoice, prio) == 0x10c);
STATIC_ASSERT(offsetof(SynthVoice, cFlags) == 0x114);
STATIC_ASSERT(offsetof(SynthVoice, midi) == 0x121);
STATIC_ASSERT(offsetof(SynthVoice, curNote) == 0x12c);
STATIC_ASSERT(offsetof(SynthVoice, portTime) == 0x13c);
STATIC_ASSERT(sizeof(SynthVoice) == 0x404);

#endif /* MAIN_AUDIO_SYNTH_VOICE_H_ */
