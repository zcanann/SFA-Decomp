#ifndef _DOLPHIN_DVDPRIV
#define _DOLPHIN_DVDPRIV

#include <dolphin/dvd.h>
#include <dolphin/hw_regs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DVDBB1 {
  u32 appLoaderLength;
  void* appLoaderFunc1;
  void* appLoaderFunc2;
  void* appLoaderFunc3;
} DVDBB1;

typedef void (*DVDOptionalCommandChecker)(DVDCommandBlock* block, void (*cb)(u32 intType));
DVDLowCallback DVDLowClearCallback();
void __DVDLowSetWAType(u32 type, u32 location);
DVDCommandBlock* __DVDPopWaitingQueue();

#ifdef __cplusplus
}
#endif

#endif /* _DOLPHIN_DVDPRIV */
