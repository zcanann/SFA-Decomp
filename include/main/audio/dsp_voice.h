#ifndef MAIN_AUDIO_DSP_VOICE_H_
#define MAIN_AUDIO_DSP_VOICE_H_

#include "global.h"
#include "main/audio/adsr.h"

/* SAL DSP voice record, stride 0xF4 off dspVoice; field names/offsets from
 * upstream musyx (MP4 musyx/dspvoice.h), verified against hw_* codegen.
 * Unverified middle regions left padded. */
typedef struct DspVoice {
    u8 pad0[0x18];   /* 0x00: pb..mesgCallBackUserValue */
    u32 mesgCallBackUserValue; /* 0x18 */
    u32 prio;        /* 0x1c */
    u32 currentAddr; /* 0x20 */
    u32 changed[5];  /* 0x24 */
    u32 pitch[5];    /* 0x38 */
    u16 volL;        /* 0x4c */
    u16 volR;        /* 0x4e */
    u16 volS;        /* 0x50 */
    u16 volLa;       /* 0x52 */
    u16 volRa;       /* 0x54 */
    u16 volSa;       /* 0x56 */
    u16 volLb;       /* 0x58 */
    u16 volRb;       /* 0x5a */
    u16 volSb;       /* 0x5c */
    u8 pad5E[0x70 - 0x5e];
    u16 smp_id;      /* 0x70 */
    u8 pad72[2];
    u32 smpInfo[8];  /* 0x74: SAMPLE_INFO */
    u8 pad94[0xa4 - 0x94];
    ADSR_VARS adsr;  /* 0xa4 */
    u16 srcTypeSelect; /* 0xcc */
    u16 srcCoefSelect; /* 0xce */
    u16 itdShiftL;   /* 0xd0 */
    u16 itdShiftR;   /* 0xd2 */
    u8 padD4[0xe4 - 0xd4];
    struct {
        u8 pitch;    /* 0xe4 */
        u8 vol;      /* 0xe5 */
        u8 volA;     /* 0xe6 */
        u8 volB;     /* 0xe7 */
    } lastUpdate;
    u8 padE8[0xef - 0xe8];
    u8 studio;       /* 0xef */
    u32 flags;       /* 0xf0 */
} DspVoice; /* size 0xf4 */

STATIC_ASSERT(offsetof(DspVoice, volL) == 0x4c);
STATIC_ASSERT(offsetof(DspVoice, prio) == 0x1c);
STATIC_ASSERT(offsetof(DspVoice, smp_id) == 0x70);
STATIC_ASSERT(offsetof(DspVoice, adsr) == 0xa4);
STATIC_ASSERT(offsetof(DspVoice, itdShiftL) == 0xd0);
STATIC_ASSERT(offsetof(DspVoice, studio) == 0xef);
STATIC_ASSERT(sizeof(DspVoice) == 0xf4);

/* SAL DSP studio record, stride 0xBC off lbl_803CC1E0 (MP4 DSPstudioinfo). */
typedef struct DspStudioInfo {
    u8 pad0[0x54];
    u32 type;          /* 0x54 */
    u8 pad58[0xac - 0x58];
    void *auxAHandler; /* 0xac */
    void *auxBHandler; /* 0xb0 */
    void *auxAUser;    /* 0xb4 */
    void *auxBUser;    /* 0xb8 */
} DspStudioInfo; /* size 0xbc */

STATIC_ASSERT(offsetof(DspStudioInfo, auxAHandler) == 0xac);
STATIC_ASSERT(sizeof(DspStudioInfo) == 0xbc);

#endif /* MAIN_AUDIO_DSP_VOICE_H_ */
