#ifndef MAIN_WORLDPLANET_H_
#define MAIN_WORLDPLANET_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct WorldPlanetState {
  u8 pad00[0x06];
  s16 foxSpawnTimer;
  u8 flags;
  s8 selectionLocked;
  s8 prevStickX;
  s8 prevStickY;
  s8 stickXRepeatFrames;
  s8 stickYRepeatFrames;
  u8 pad0E[0x10 - 0x0E];
  s8 selectedPlanet;
  u8 unlockedPlanetMask;
  u8 pad12[0x18 - 0x12];
} WorldPlanetState;

STATIC_ASSERT(sizeof(WorldPlanetState) == 0x18);
STATIC_ASSERT(offsetof(WorldPlanetState, foxSpawnTimer) == 0x06);
STATIC_ASSERT(offsetof(WorldPlanetState, flags) == 0x08);
STATIC_ASSERT(offsetof(WorldPlanetState, selectionLocked) == 0x09);
STATIC_ASSERT(offsetof(WorldPlanetState, prevStickX) == 0x0A);
STATIC_ASSERT(offsetof(WorldPlanetState, prevStickY) == 0x0B);
STATIC_ASSERT(offsetof(WorldPlanetState, stickXRepeatFrames) == 0x0C);
STATIC_ASSERT(offsetof(WorldPlanetState, stickYRepeatFrames) == 0x0D);
STATIC_ASSERT(offsetof(WorldPlanetState, selectedPlanet) == 0x10);
STATIC_ASSERT(offsetof(WorldPlanetState, unlockedPlanetMask) == 0x11);

extern ObjectDescriptor gWorldPlanetObjDescriptor;

int worldplanet_getExtraSize(void);
int worldplanet_func08(void);
void worldplanet_free(void);
void worldplanet_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible);
void worldplanet_hitDetect(void);
void worldplanet_update(void);
void worldplanet_init(int obj);
void worldplanet_release(void);
void worldplanet_initialise(void);

#endif /* MAIN_WORLDPLANET_H_ */
