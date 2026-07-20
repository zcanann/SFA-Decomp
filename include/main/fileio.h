#ifndef MAIN_FILEIO_H_
#define MAIN_FILEIO_H_

#include "types.h"
#include "dolphin/dvd.h"

extern u8 gDvdErrorPauseActive;
extern u8 gDvdCoverOpenErrorActive;
extern int gDvdLastDriveStatus;
extern DVDCommandBlock gDvdStreamPlayAddrCommandBlock;
extern DVDFileInfo* gFileInfo;
extern volatile int gDvdReadCallbackResult;

void dvdCheckError(void);
int DVDRead(DVDFileInfo* fileInfo, void* buf, s32 size, s32 offset);
void DvdRead_Callback(s32 result, DVDFileInfo* fileInfo);
void setFileInfo(DVDFileInfo* fileInfo);
void* loadFileByPath(char* path, int* outSize, int unused);
void* loadFileByPathAsync(char* path, int* outSize, int unused, DVDCallback callback);

#endif /* MAIN_FILEIO_H_ */
