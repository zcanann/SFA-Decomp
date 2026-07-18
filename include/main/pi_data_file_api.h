#ifndef MAIN_PI_DATA_FILE_API_H_
#define MAIN_PI_DATA_FILE_API_H_

#include "types.h"

u32 mapLoadDataFile(int mapId, int fileId);
s32 getDataFileSize(int id);
void loadDataFiles(int arg);

#define loadDataFilesNoArgLegacy() \
    (((void (*)(void))loadDataFiles)())

#endif /* MAIN_PI_DATA_FILE_API_H_ */
