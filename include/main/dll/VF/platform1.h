#ifndef MAIN_DLL_VF_PLATFORM1_H_
#define MAIN_DLL_VF_PLATFORM1_H_

#include "ghidra_import.h"

typedef struct Platform1State {
  int linkedObject;
  int motionValue0;
  int offsetVelocity;
  int savedPosXBits;
  int savedPosYBits;
  int savedPosZBits;
  int playerSfxTimer;
  int platformSfxTimer;
  int currentTrackOffset;
  int loopSfxHandle;
  int prevTrackOffset;
  u8 pad2C[0x2E - 0x2C];
  u16 transitionStep;
  u8 flags;
} Platform1State;

#define PLATFORM1_TRIGGER_MASK 0x03
#define PLATFORM1_TRIGGER_FLAG_01 0x01
#define PLATFORM1_TRIGGER_FLAG_02 0x02
#define PLATFORM1_FLAG_ACTIVE 0x04
#define PLATFORM1_FLAG_EXIT_NEGATIVE 0x08
#define PLATFORM1_FLAG_EXIT_POSITIVE 0x10

void platform1_control(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                       undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                       undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                       int *param_13,undefined4 param_14,undefined4 param_15,int param_16);

#endif /* MAIN_DLL_VF_PLATFORM1_H_ */
