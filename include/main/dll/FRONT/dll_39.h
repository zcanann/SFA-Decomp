#ifndef MAIN_DLL_FRONT_DLL_39_H_
#define MAIN_DLL_FRONT_DLL_39_H_

#include "ghidra_import.h"

typedef struct NAttractModeMovieDims {
  int width;
  int height;
} NAttractModeMovieDims;

#define NATTRACTMODE_PREPARE_FAIL_LINE 0x2FB
#define NATTRACTMODE_MOVIE_HEAP 0x18
#define NATTRACTMODE_WORK_BUFFER_SIZE 0x4000
#define NATTRACTMODE_MOVIE_STATE_PREPARED 2
#define NATTRACTMODE_MOVIE_STATE_RELEASED 4
#define NATTRACTMODE_MOVIE_BUSY 1
#define NATTRACTMODE_MOVIE_READY 0
#define NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE 0
#define NATTRACTMODE_MOVIE_SETUP_ID 2
#define NATTRACTMODE_MOVIE_START_FRAME_DEFAULT 0
#define NATTRACTMODE_MOVIE_START_FRAME_ALTERNATE 100
#define NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN 10

#define gAttractMovieState lbl_803DD610
#define gTitleMenuSelection lbl_803DD614
#define gAttractMoviePreparePending lbl_803DD619
#define gAttractMovieScratchBuffer lbl_803DD61C
#define gAttractMovieWorkBuffer lbl_803DD620
#define gAttractMovieOptionalBuffer lbl_803DD624
#define gAttractMovieBuffer3 lbl_803DD628
#define gAttractMovieBuffer2 lbl_803DD62C
#define gAttractMovieBuffer1 lbl_803DD630
#define gAttractMovieBuffer0 lbl_803DD634
#define gAttractMovieDims lbl_803DD638
#define gAttractMovieOffsetY lbl_803DD640
#define gAttractMovieOffsetX lbl_803DD644
#define gAttractMovieRetraceCountdown lbl_803DD64D
#define gAttractMoviePlaybackEnabled lbl_803DD64F
#define gAttractMovieIdleFrameCount lbl_803DD698

int n_rareware_frameStart(void);
void n_rareware_release(void);
void n_rareware_initialise(void);
void n_attractmode_releaseMovieBuffers(void);
void n_attractmode_prepareMovie(void);
void TitleMenu_render(u8 *param_1);
void TitleMenu_frameEnd(void);

#endif /* MAIN_DLL_FRONT_DLL_39_H_ */
