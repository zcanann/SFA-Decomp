#ifndef MUSYX_DSP_H
#define MUSYX_DSP_H

#include "types.h"

/* MusyX runtime DSP control structures (hw_dspctrl.c family, MUSY_VERSION <= 2.0.0). */

typedef struct _PBMIX {
    u16 vL, vDeltaL, vR, vDeltaR;
    u16 vAuxAL, vDeltaAuxAL, vAuxAR, vDeltaAuxAR;
    u16 vAuxBL, vDeltaAuxBL, vAuxBR, vDeltaAuxBR;
    u16 vAuxBS, vDeltaAuxBS, vS, vDeltaS, vAuxAS, vDeltaAuxAS;
} _PBMIX;

typedef struct _PBITD {
    u16 flag, bufferHi, bufferLo, shiftL, shiftR, targetShiftL, targetShiftR;
} _PBITD;

typedef struct _PBUPDATE {
    u16 updNum[5];
    u16 dataHi, dataLo;
} _PBUPDATE;

typedef struct _PBDPOP {
    u16 aL, aAuxAL, aAuxBL, aR, aAuxAR, aAuxBR, aS, aAuxAS, aAuxBS;
} _PBDPOP;

typedef struct _PBVE {
    u16 currentVolume, currentDelta;
} _PBVE;

typedef struct _PBFIR {
    u16 numCoefs, coefsHi, coefsLo;
} _PBFIR;

typedef struct _PBADDR {
    u16 loopFlag, format, loopAddressHi, loopAddressLo;
    u16 endAddressHi, endAddressLo, currentAddressHi, currentAddressLo;
} _PBADDR;

typedef struct _PBADPCM {
    u16 a[8][2];
    u16 gain, pred_scale, yn1, yn2;
} _PBADPCM;

typedef struct _PBSRC {
    u16 ratioHi, ratioLo, currentAddressFrac;
    u16 last_samples[4];
} _PBSRC;

typedef struct _PBADPCMLOOP {
    u16 loop_pred_scale, loop_yn1, loop_yn2;
} _PBADPCMLOOP;

typedef struct _PB {
    u16 nextHi;             /* 0x00 */
    u16 nextLo;             /* 0x02 */
    u16 currHi;             /* 0x04 */
    u16 currLo;             /* 0x06 */
    u16 srcSelect;          /* 0x08 */
    u16 coefSelect;         /* 0x0a */
    u16 mixerCtrl;          /* 0x0c */
    u16 state;              /* 0x0e */
    u16 loopType;           /* 0x10 */
    _PBMIX mix;             /* 0x12 */
    _PBITD itd;             /* 0x36 */
    _PBUPDATE update;       /* 0x44 */
    _PBDPOP dpop;           /* 0x52 */
    _PBVE ve;               /* 0x64 */
    _PBFIR fir;             /* 0x68 */
    _PBADDR addr;           /* 0x6e */
    _PBADPCM adpcm;         /* 0x7e */
    _PBSRC src;             /* 0xa6 */
    _PBADPCMLOOP adpcmLoop; /* 0xb4 */
    u16 streamLoopCnt;      /* 0xba */
} _PB;

typedef struct _SPB {
    u16 dpopLHi, dpopLLo, dpopLDelta;
    u16 dpopRHi, dpopRLo, dpopRDelta;
    u16 dpopSHi, dpopSLo, dpopSDelta;
    u16 dpopALHi, dpopALLo, dpopALDelta;
    u16 dpopARHi, dpopARLo, dpopARDelta;
    u16 dpopASHi, dpopASLo, dpopASDelta;
    u16 dpopBLHi, dpopBLLo, dpopBLDelta;
    u16 dpopBRHi, dpopBRLo, dpopBRDelta;
    u16 dpopBSHi, dpopBSLo, dpopBSDelta;
} _SPB;

typedef struct SAMPLE_INFO {
    u32 info;        /* 0x00 */
    void *addr;      /* 0x04 */
    void *extraData; /* 0x08 */
    u32 offset;      /* 0x0c */
    u32 length;      /* 0x10 */
    u32 loop;        /* 0x14 */
    u32 loopLength;  /* 0x18 */
    u8 compType;     /* 0x1c */
} SAMPLE_INFO;

typedef struct VSampleInfo {
    void *loopBufferAddr; /* 0x00 */
    u32 loopBufferLength; /* 0x04 */
    u8 inLoopBuffer;      /* 0x08 */
} VSampleInfo;

typedef struct ADSR_VARS {
    u8 mode;          /* 0x00 */
    u8 state;         /* 0x01 */
    u32 cnt;          /* 0x04 */
    s32 currentVolume; /* 0x08 */
    s32 currentIndex; /* 0x0c */
    s32 currentDelta; /* 0x10 */
    union {
        struct {
            u32 aTime;
            u32 dTime;
            u16 sLevel;
            u32 rTime;
            u16 cutOff;
            u8 aMode;
        } dls;
        struct {
            u32 aTime;
            u32 dTime;
            u16 sLevel;
            u32 rTime;
        } linear;
    } data; /* 0x14 */
} ADSR_VARS;

typedef struct SNDADPCMinfo {
    u16 coefTab[8][2]; /* 0x00 */
    u16 initialPS;     /* 0x20 */
    u16 loopPS;        /* 0x22 */
    u16 loopY1;        /* 0x24 */
    u16 loopY2;        /* 0x26 */
} SNDADPCMinfo;

typedef struct DSPADPCMplusBlk {
    u16 PS; /* 0x00 */
    u16 Y0; /* 0x02 */
    u16 Y1; /* 0x04 */
} DSPADPCMplusBlk;

typedef struct DSPADPCMplusInfo {
    u16 coefTab[8][2];         /* 0x00 */
    u16 loopPS;                /* 0x20 */
    u16 loopY0;                /* 0x22 */
    u16 loopY1;                /* 0x24 */
    DSPADPCMplusBlk blk[1];    /* 0x26 */
} DSPADPCMplusInfo;

typedef struct DSPvoice {
    _PB *pb;                    /* 0x00 */
    void *patchData;            /* 0x04 */
    void *itdBuffer;            /* 0x08 */
    struct DSPvoice *next;      /* 0x0c */
    struct DSPvoice *prev;      /* 0x10 */
    struct DSPvoice *nextAlien; /* 0x14 */
    u32 mesgCallBackUserValue;  /* 0x18 */
    u32 prio;                   /* 0x1c */
    u32 currentAddr;            /* 0x20 */
    u32 changed[5];             /* 0x24 */
    u32 pitch[5];               /* 0x38 */
    u16 volL;                   /* 0x4c */
    u16 volR;                   /* 0x4e */
    u16 volS;                   /* 0x50 */
    u16 volLa;                  /* 0x52 */
    u16 volRa;                  /* 0x54 */
    u16 volSa;                  /* 0x56 */
    u16 volLb;                  /* 0x58 */
    u16 volRb;                  /* 0x5a */
    u16 volSb;                  /* 0x5c */
    u16 lastVolL;               /* 0x5e */
    u16 lastVolR;               /* 0x60 */
    u16 lastVolS;               /* 0x62 */
    u16 lastVolLa;              /* 0x64 */
    u16 lastVolRa;              /* 0x66 */
    u16 lastVolSa;              /* 0x68 */
    u16 lastVolLb;              /* 0x6a */
    u16 lastVolRb;              /* 0x6c */
    u16 lastVolSb;              /* 0x6e */
    u16 smp_id;                 /* 0x70 */
    SAMPLE_INFO smp_info;       /* 0x74 */
    VSampleInfo vSampleInfo;    /* 0x94 */
    u8 streamLoopPS;            /* 0xa0 */
    ADSR_VARS adsr;             /* 0xa4 */
    u16 srcTypeSelect;          /* 0xcc */
    u16 srcCoefSelect;          /* 0xce */
    u16 itdShiftL;              /* 0xd0 */
    u16 itdShiftR;              /* 0xd2 */
    u8 singleOffset;            /* 0xd4 */
    struct {
        u32 posHi;
        u32 posLo;
        u32 pitch;
    } playInfo;                 /* 0xd8 */
    struct {
        u8 pitch;
        u8 vol;
        u8 volA;
        u8 volB;
    } lastUpdate;               /* 0xe4 */
    u32 virtualSampleID;        /* 0xe8 */
    u8 state;                   /* 0xec */
    u8 postBreak;               /* 0xed */
    u8 startupBreak;            /* 0xee */
    u8 studio;                  /* 0xef */
    u32 flags;                  /* 0xf0 */
} DSPvoice;

typedef struct DSPhostDPop {
    s32 l, r, s, lA, rA, sA, lB, rB, sB;
} DSPhostDPop;

typedef struct DSPinput {
    u8 studio;             /* 0x00 */
    u16 vol;               /* 0x02 */
    u16 volA;              /* 0x04 */
    u16 volB;              /* 0x06 */
    void *desc;            /* 0x08 */
} DSPinput;

typedef struct DSPstudioinfo {
    _SPB *spb;                /* 0x00 */
    DSPhostDPop hostDPopSum;  /* 0x04 */
    s32 *main[2];             /* 0x28 */
    s32 *auxA[3];             /* 0x30 */
    s32 *auxB[3];             /* 0x3c */
    DSPvoice *voiceRoot;      /* 0x48 */
    DSPvoice *alienVoiceRoot; /* 0x4c */
    u8 state;                 /* 0x50 */
    u8 isMaster;              /* 0x51 */
    u8 numInputs;             /* 0x52 */
    u32 type;                 /* 0x54 */
    DSPinput in[7];           /* 0x58 */
    void *auxAHandler;        /* 0xac */
    void *auxBHandler;        /* 0xb0 */
    void *auxAUser;           /* 0xb4 */
    void *auxBUser;           /* 0xb8 */
} DSPstudioinfo;

#endif /* MUSYX_DSP_H */
