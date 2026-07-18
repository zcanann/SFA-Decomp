#ifndef MAIN_ATTRACT_MOVIE_API_H_
#define MAIN_ATTRACT_MOVIE_API_H_

#include "types.h"

extern s32 gAttractMovieState;
extern u8 gAttractMoviePreparePending;
extern u8 gAttractMovieRetraceCountdown;
extern void* gAttractMovieBuffer0;
extern void* gAttractMovieBuffer1;
extern void* gAttractMovieBuffer2;
extern void* gAttractMovieBuffer3;
extern void* gAttractMovieOptionalBuffer;
extern void* gAttractMovieWorkBuffer;
extern void* gAttractMovieScratchBuffer;
extern int gAttractMovieOffsetX;
extern int gAttractMovieOffsetY;

BOOL Movie_SetVolumeFade(int volume, int fadeFrames);

#endif /* MAIN_ATTRACT_MOVIE_API_H_ */
