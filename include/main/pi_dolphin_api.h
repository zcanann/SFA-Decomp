#ifndef MAIN_PI_DOLPHIN_API_H_
#define MAIN_PI_DOLPHIN_API_H_

#include "types.h"

double SeekTwiceBeforeRead(void);
int GXFlush_(u8 visible, int unused);
int loadAndDecompressDataFile();
int mapGetDirIdx(int idx);
u32 mapLoadDataFile(int mapId, int fileId);
u8 isHeavyFogEnabled(void);
void waitNextFrame(void);

#endif /* MAIN_PI_DOLPHIN_API_H_ */
