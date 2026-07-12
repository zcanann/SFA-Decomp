#ifndef MAIN_FILEIO_H_
#define MAIN_FILEIO_H_

#include "types.h"

void dvdCheckError(void);
int DVDRead(void* fileInfo, void* buf, int size, int offset);

#endif /* MAIN_FILEIO_H_ */
