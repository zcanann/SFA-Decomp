#ifndef MAIN_DLL_VF_PLATFORM1_H_
#define MAIN_DLL_VF_PLATFORM1_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

typedef struct Platform1State {
  int linkedObject;
  f32 motionValue0;
  f32 offsetVelocity;
  f32 savedPosX;
  f32 savedPosY;
  f32 savedPosZ;
  f32 playerSfxTimer;
  f32 platformSfxTimer;
  int currentTrackOffset;
  int loopSfxHandle;
  int prevTrackOffset;
  u8 pad2C[0x2E - 0x2C];
  s16 transitionStep;
  u8 flags;
} Platform1State;

STATIC_ASSERT(sizeof(Platform1State) == 0x34);
STATIC_ASSERT(offsetof(Platform1State, linkedObject) == 0x00);
STATIC_ASSERT(offsetof(Platform1State, motionValue0) == 0x04);
STATIC_ASSERT(offsetof(Platform1State, offsetVelocity) == 0x08);
STATIC_ASSERT(offsetof(Platform1State, savedPosX) == 0x0C);
STATIC_ASSERT(offsetof(Platform1State, playerSfxTimer) == 0x18);
STATIC_ASSERT(offsetof(Platform1State, currentTrackOffset) == 0x20);
STATIC_ASSERT(offsetof(Platform1State, loopSfxHandle) == 0x24);
STATIC_ASSERT(offsetof(Platform1State, prevTrackOffset) == 0x28);
STATIC_ASSERT(offsetof(Platform1State, transitionStep) == 0x2E);
STATIC_ASSERT(offsetof(Platform1State, flags) == 0x30);

#define PLATFORM1_TRIGGER_MASK 0x03
#define PLATFORM1_TRIGGER_FLAG_01 0x01
#define PLATFORM1_TRIGGER_FLAG_02 0x02
#define PLATFORM1_FLAG_ACTIVE 0x04
#define PLATFORM1_FLAG_EXIT_NEGATIVE 0x08
#define PLATFORM1_FLAG_EXIT_POSITIVE 0x10

extern char sPlatform1DrawNoLongerSupported[];
extern char sPlatform1ControlNoLongerSupported[];
extern char sPlatform1InitNoLongerSupported[];
extern ObjectDescriptor gPlatform1ObjDescriptor;

int platform1_getExtraSize(void);
int platform1_getObjectTypeId(void);
void platform1_free(void);
void platform1_drawUnsupported(void);
void platform1_hitDetect(void);
void platform1_controlUnsupported(void);
void platform1_init(void);
void platform1_release(void);
void platform1_initialise(void);
int platform1_control(int obj, int unused, ObjAnimUpdateState *animUpdate);
int PaymentKiosk_SeqFn(struct GameObject *obj, int unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_VF_PLATFORM1_H_ */
