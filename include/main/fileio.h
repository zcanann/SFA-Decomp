#ifndef MAIN_FILEIO_H_
#define MAIN_FILEIO_H_

#include "types.h"
#include "dolphin/dvd.h"

extern u8 gDvdErrorPauseActive;
extern u8 gDvdCoverOpenErrorActive;
extern int gDvdLastDriveStatus;
extern DVDCommandBlock lbl_80339950;
extern DVDFileInfo* gFileInfo;
extern volatile int gDvdReadCallbackResult;

void dvdCheckError(void);
int DVDRead(DVDFileInfo* fileInfo, void* buf, int size, int offset);
void fileReadCb_80015954(s32 result, DVDFileInfo* fileInfo);
void setFileInfo(DVDFileInfo* fileInfo);
void* loadFileByPath(char* path, int* outSize);
void* loadFileByPathAsync(char* path, int* outSize, int unused, DVDCallback callback);

/* Compatibility view for callers recovered with the unused third argument. */
#define loadFileByPathLegacy3(path, outSize, unused) \
    ((void* (*)(char*, int*, int))loadFileByPath)((path), (outSize), (unused))

#endif /* MAIN_FILEIO_H_ */
