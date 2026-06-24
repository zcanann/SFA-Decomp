#ifndef MAIN_AUDIO_ADSR_H_
#define MAIN_AUDIO_ADSR_H_

#include "global.h"

/* ADSR envelope state, layout from upstream musyx (MP4 musyx/adsr.h);
 * offsets verified against adsr_setup.c/adsr_handle.c codegen. */
typedef struct ADSR_INFO {
    union ai_data {
        struct {
            s32 atime;
            s32 dtime;
            u16 slevel;
            u16 rtime;
            s32 ascale;
            s32 dscale;
        } dls;
        struct {
            u16 atime;
            u16 dtime;
            u16 slevel;
            u16 rtime;
        } linear;
    } data;
} ADSR_INFO;

typedef struct ADSR_VARS {
    u8 mode;
    u8 state;
    u32 cnt;
    u32 currentVolume; /* s32 upstream; SFA codegen reads unsigned */
    u32 currentIndex;
    u32 currentDelta;
    u32 aTime;
    u32 dTime;
    u16 sLevel;
    u32 rTime;
    u16 cutOff;
    u8 aMode;
} ADSR_VARS;

STATIC_ASSERT(offsetof(ADSR_VARS, cnt) == 0x4);
STATIC_ASSERT(offsetof(ADSR_VARS, sLevel) == 0x1C);
STATIC_ASSERT(offsetof(ADSR_VARS, aMode) == 0x26);

/* ADSR_VARS.mode - envelope curve family */
#define ADSR_MODE_LINEAR 0 /* linear ramps */
#define ADSR_MODE_DLS 1    /* DLS volume curve (lbl_8032F618 / 0xC1-step index) */

/* ADSR_VARS.state - envelope phase */
#define ADSR_STATE_ATTACK 0  /* ramp 0 -> peak */
#define ADSR_STATE_DECAY 1   /* ramp peak -> sustain level */
#define ADSR_STATE_SUSTAIN 2 /* enter the held sustain phase */
#define ADSR_STATE_HOLD 3    /* held at sustain; volume frozen */
#define ADSR_STATE_RELEASE 4 /* ramp current -> 0, then done */

#endif /* MAIN_AUDIO_ADSR_H_ */
