#ifndef MAIN_DLL_DLL_80136A40_H_
#define MAIN_DLL_DLL_80136A40_H_

#include "types.h"
#include "main/debug.h"

/* Debug text and fatal-error display services. */
void debugPrintInit(void);
void debugPrintReset(void);
void debugPrintfxy(int x, int y, char* fmt, ...);
void errDisplayInstallHandlers(void);
void* errorThreadFunc(void* unused);
void reportAllocFail(int region0SizeKb, int region0FreeKb, int region1SizeKb, int region1FreeKb, int region2SizeKb,
                     int region2FreeKb, int memoryState, int tickCount, int requestedSize, int largestFree0,
                     int largestFree1);
void debugPrintDraw(void* context);

#endif
