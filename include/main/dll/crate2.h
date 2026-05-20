#ifndef MAIN_DLL_CRATE2_H_
#define MAIN_DLL_CRATE2_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct DfpObjectInterface {
  u8 pad00[0x48];
  void (*refresh)(int mode, int obj, int arg);
} DfpObjectInterface;

typedef struct DfpStatue1State {
  s16 triggerSfxId;
  s16 loopSfxId;
  s16 loopSfxStopTimer;
  u8 loopActive;
  u8 effectPairCount;
  u8 stateFlags;
} DfpStatue1State;

typedef struct DfpStatue1MapData {
  u8 pad00[0x18];
  s8 yawByte;
  u8 effectPairCount;
  u8 pad1A[0x1E - 0x1A];
  s16 triggerSfxId;
  s16 loopSfxId;
} DfpStatue1MapData;

typedef struct DfpStatue1Object {
  s16 yaw;
  u8 pad02[0xB0 - 0x02];
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  DfpStatue1State *state;
  undefined4 (*updateState)(int obj, undefined4 param_2, int hitState);
} DfpStatue1Object;

void dfpstatue1_updateState(DfpStatue1Object *obj);

extern char sDfperchwitchInitNoLongerSupported[];
extern ObjectDescriptor gDfpstatue1ObjDescriptor;
extern ObjectDescriptor gDfperchwitchObjDescriptor;

int dfperchwitch_getExtraSize(void);
int dfperchwitch_func08(void);
void dfperchwitch_free(void);
void dfperchwitch_render(void);
void dfperchwitch_hitDetect(void);
void dfperchwitch_update(void);
void dfperchwitch_init(void);
void dfperchwitch_release(void);
void dfperchwitch_initialise(void);

int dfpstatue1_getExtraSize(void);
int dfpstatue1_func08(void);
void dfpstatue1_free(void);
void dfpstatue1_render(void);
void dfpstatue1_hitDetect(void);
void dfpstatue1_update(DfpStatue1Object *obj);
void dfpstatue1_init(DfpStatue1Object *obj, DfpStatue1MapData *mapData);
void dfpstatue1_release(void);
void dfpstatue1_initialise(void);

#endif /* MAIN_DLL_CRATE2_H_ */
