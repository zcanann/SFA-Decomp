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

/* DSPvoice/DSPstudioinfo + SAMPLE_INFO/VSampleInfo/ADSR_VARS moved to the
 * canonical include/main/audio/dsp_voice.h (+ adsr.h). */
#include "main/audio/dsp_voice.h"

typedef struct SNDADPCMinfo {
    u16 unk0;          /* 0x00 */
    u8 initialPS;      /* 0x02 */
    u8 loopPS;         /* 0x03 */
    u16 loopY0;        /* 0x04 */
    u16 loopY1;        /* 0x06 */
    u16 coefTab[8][2]; /* 0x08 */
} SNDADPCMinfo;

typedef struct DSPADPCMplusBlk {
    u16 Y0; /* 0x00 */
    u16 Y1; /* 0x02 */
    u8 PS;  /* 0x04 */
    u8 pad5; /* 0x05 */
} DSPADPCMplusBlk;

typedef struct DSPADPCMplusInfo {
    u16 unk0;               /* 0x00 */
    u8 initialPS;           /* 0x02 */
    u8 loopPS;              /* 0x03 */
    u16 loopY0;             /* 0x04 */
    u16 loopY1;             /* 0x06 */
    u16 coefTab[8][2];      /* 0x08 */
    DSPADPCMplusBlk blk[1]; /* 0x28 */
} DSPADPCMplusInfo;

#endif /* MUSYX_DSP_H */
