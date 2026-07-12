#ifndef MAIN_FILEIO_H_
#define MAIN_FILEIO_H_

#include "types.h"

extern u8 gDvdErrorPauseActive;
extern u8 gDvdCoverOpenErrorActive;
extern int gDvdLastDriveStatus;
extern u8 lbl_80339950[];
extern void* gFileInfo;
extern volatile int gDvdReadCallbackResult;

void dvdCheckError(void);
int DVDRead(void* fileInfo, void* buf, int size, int offset);
void fileReadCb_80015954(void* result);
void setFileInfo(void* fileInfo);
void* loadFileByPath(char* path, int* outSize);
void* loadFileByPathAsync(char* path, int* outSize, int unused, void (*callback)(void*));

/* Compatibility view for callers recovered with the unused third argument. */
#define loadFileByPathLegacy3(path, outSize, unused) \
    ((void* (*)(char*, int*, int))loadFileByPath)((path), (outSize), (unused))

#endif /* MAIN_FILEIO_H_ */
