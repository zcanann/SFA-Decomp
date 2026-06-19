#ifndef MAIN_DLL_CRATE2_H_
#define MAIN_DLL_CRATE2_H_

#include "ghidra_import.h"
#include "main/objseq.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/objanim_internal.h"

typedef struct DfpStatue1State {
  s16 triggerSfxId;
  s16 loopSfxId;
  s16 loopSfxStopTimer;
  u8 loopActive;
  u8 effectPairCount;
  u8 stateFlags;
} DfpStatue1State;

typedef struct DfpStatue1MapData {
  ObjPlacement base;
  s8 yawByte;
  u8 effectPairCount;
  u8 pad1A[0x1E - 0x1A];
  s16 triggerSfxId;
  s16 loopSfxId;
} DfpStatue1MapData;

typedef struct DfpStatue1Object {
  union {
    ObjAnimComponent anim;
    struct {
      s16 yaw;
      u8 pad02[0xB0 - 0x02];
    };
  };
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  DfpStatue1State *state;
  u32 (*updateState)(int obj, u32 param_2, int hitState);
} DfpStatue1Object;

STATIC_ASSERT(offsetof(DfpStatue1MapData, yawByte) == 0x18);
STATIC_ASSERT(offsetof(DfpStatue1MapData, effectPairCount) == 0x19);
STATIC_ASSERT(offsetof(DfpStatue1MapData, triggerSfxId) == 0x1E);
STATIC_ASSERT(offsetof(DfpStatue1MapData, loopSfxId) == 0x20);
STATIC_ASSERT(offsetof(DfpStatue1Object, anim) == 0x00);
STATIC_ASSERT(offsetof(DfpStatue1Object, yaw) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(DfpStatue1Object, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(DfpStatue1Object, state) == 0xB8);
STATIC_ASSERT(offsetof(DfpStatue1Object, updateState) == 0xBC);

void dfpstatue1_updateState(DfpStatue1Object *obj);

extern char sDfperchwitchInitNoLongerSupported[];
extern ObjectDescriptor gDfpstatue1ObjDescriptor;
extern ObjectDescriptor gDfperchwitchObjDescriptor;

int dfperchwitch_getExtraSize(void);
int dfperchwitch_getObjectTypeId(void);
void dfperchwitch_free(void);
void dfperchwitch_render(void);
void dfperchwitch_hitDetect(void);
void dfperchwitch_update(void);
void dfperchwitch_init(void);
void dfperchwitch_release(void);
void dfperchwitch_initialise(void);

int dfpstatue1_getExtraSize(void);
int dfpstatue1_getObjectTypeId(void);
void dfpstatue1_free(void);
void dfpstatue1_render(void);
void dfpstatue1_hitDetect(void);
void dfpstatue1_update(DfpStatue1Object *obj);
void dfpstatue1_init(DfpStatue1Object *obj, DfpStatue1MapData *mapData);
void dfpstatue1_release(void);
void dfpstatue1_initialise(void);

#endif /* MAIN_DLL_CRATE2_H_ */
