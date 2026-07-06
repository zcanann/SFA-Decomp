#ifndef MAIN_FRAME_TIMING_H_
#define MAIN_FRAME_TIMING_H_

#include "types.h"

/*
 * Per-frame timing globals (set by the main-loop / platform interface in
 * pi_dolphin). timeDelta is the elapsed time for this frame, used to
 * integrate motion; framesThisStep is the number of game frames advanced.
 */
extern f32 timeDelta;
extern u8 framesThisStep;

#endif
