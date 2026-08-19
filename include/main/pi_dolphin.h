#ifndef MAIN_PI_DOLPHIN_H_
#define MAIN_PI_DOLPHIN_H_

#include "types.h"
#include "dolphin/gx/GXStruct.h"
#include "dolphin/gx/GXFifo.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/os/OSStopwatch.h"
#include "main/model_engine.h"
#include "main/pi_dolphin_api.h"

void piRomLoadSection(int romOffset, int mapIndex, void* destBuf);
void mapsLoadTabOffsets(int firstWord, s32* offsets, int count);

/* extern-cleanup: defining-file public prototypes */
void setDisplayCopyFilter(void);
void gxDisableGpuHangRecovery(void);
void allocSomething32bytes(void);
void initViewport(void);
void tvInit(void);
void loadModelsBin(int fileOffset, int* animCount, int* headerSize, int* amapFlag, int* dataLen, int id);
void* fileLoad(int id, int heap);
void videoInit(void* rmode, int arg);
int fileLoadToBuffer(int id, void* buffer);
u8 initLoadFiles(void);
void videoBlackScreenForFrames(int frameCount);
void checkLoadBlock(int a, int* compressedSize, int* decompressedSize);

extern void** gDvdFileInfoPool;
extern GXRenderModeObj* gRenderModeObj;
extern s32 gObjLevelLockSlots[2];


#include "main/mldf_fileid.h"

extern volatile int gAssetLoadInFlightFlags;
extern s16 gDefragDelayFrames;
extern int gPendingDvdReadCount;
extern u8 gVideoRetracePending;
extern int gModelsArchiveLoadCount;
extern void* lbl_803DCD10;
extern char* lbl_803DCD08;
extern s16 gForceNextLoadSync;
extern u8 gLoadFilesInitDone;

extern volatile int gAssetLoadCompletedFlags;
extern u8 lbl_803DCD00;
extern int lbl_803DCCFC;
extern u8 lbl_803DCCF8;
extern int lbl_803DCCF4;
extern void* externalFrameBuffer0;
extern void* externalFrameBuffer1;
extern u32 gGxFifoSize;
extern char* lbl_803DCCE0;
extern void* gGxFifoBase;
extern void* renderFrameBuffer;
extern void* displayFrameBuffer;
extern char gVideoFlipWaitQueue;
extern int gDispCopyYScaleLines;
extern GXColor gEfbCopyClearColor;
extern u8 gDispCopyFilterWeights[8];
extern char gVideoFlipQueueBuffer[0x78];
extern f32 gFrameElapsedMs;
extern f32 gFrameStepRemainder;
extern u8 gGpuHangRecoveryEnabled;
extern volatile int gGpuStallRetraceCount;
extern u8 gGxBreakPtEnabled;
extern u8 gVideoBlackScreenFrameCount;
extern u16 gGxDrawSyncToken;
extern u32 gRomListLoadInFlight;
extern int gForceLoadImmediately;
extern int sMapFileNameIndexRemapTable[];
extern GXFifoObj* gGxFifoObj;
extern OSThread* gVideoWaitThread;
extern OSStopwatch gFrameStopwatch;
extern RingBufferQueue gVideoFlipQueue;
extern u8 gLoadingScreenTextures[];

#endif /* MAIN_PI_DOLPHIN_H_ */
