#ifndef MAIN_PI_DOLPHIN_API_H_
#define MAIN_PI_DOLPHIN_API_H_

#include "types.h"
#include "main/pi_frame_api.h"

double SeekTwiceBeforeRead(void);
int GXFlush_(u8 visible, int unused);
int loadAndDecompressDataFile();
int mapGetDirIdx(int idx);
u32 mapLoadDataFile(int mapId, int fileId);
u8 isHeavyFogEnabled(void);
void fn_8004D6D8(void);
void fn_80050F2C(void);

#endif /* MAIN_PI_DOLPHIN_API_H_ */
