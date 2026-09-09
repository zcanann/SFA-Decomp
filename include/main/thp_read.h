#ifndef MAIN_THP_READ_H_
#define MAIN_THP_READ_H_

#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/os/OSThread.h"

/* ReadedBuffer is DVD-filled; ReadedBuffer2 has passed audio decoding. */
void PushReadedBuffer2(AttractMovieReadBuffer* buffer);
AttractMovieReadBuffer* PopReadedBuffer2(void);
void PushFreeReadBuffer(AttractMovieReadBuffer* buffer);
AttractMovieReadBuffer* PopReadedBuffer(void);
void ReadThreadCancel(void);
void ReadThreadStart(void);
BOOL CreateReadThread(OSPriority priority);

#endif /* MAIN_THP_READ_H_ */
