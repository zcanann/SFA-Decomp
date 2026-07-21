#ifndef MAIN_PI_DATA_FILE_API_H_
#define MAIN_PI_DATA_FILE_API_H_

#include "types.h"

void* mapLoadDataFile(int mapId, int fileId);
s32 getDataFileSize(int id);
void loadDataFiles();

#endif /* MAIN_PI_DATA_FILE_API_H_ */
