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

int fn_80115FBC(void);
void n_rareware_release(void);
void fn_801160E0(void);
void n_attractmode_releaseMovieBuffers(void);
void n_attractmode_prepareMovie(void);
void fn_801165BC(u8 *param_1);
void TitleMenu_frameEnd(void);

#endif /* MAIN_DLL_FRONT_DLL_39_H_ */
