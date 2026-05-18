#ifndef MAIN_WORLDPLANET_H_
#define MAIN_WORLDPLANET_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct WorldPlanetState {
  u8 unk0[0x18];
} WorldPlanetState;

extern ObjectDescriptor gWorldPlanetObjDescriptor;

int worldplanet_getExtraSize(void);
int worldplanet_func08(void);
void worldplanet_free(void);
void worldplanet_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible);
void worldplanet_hitDetect(void);
void worldplanet_update(void);
void worldplanet_init(void);
void worldplanet_release(void);
void worldplanet_initialise(void);

#endif /* MAIN_WORLDPLANET_H_ */
