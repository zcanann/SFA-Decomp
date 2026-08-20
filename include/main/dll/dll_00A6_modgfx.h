#ifndef MAIN_DLL_DLL_00A6_MODGFX_H_
#define MAIN_DLL_DLL_00A6_MODGFX_H_

#include "global.h"
#include "game/objects/object_fwd.h"
#include "main/dll/partfx_interface.h"
#include "main/resource.h"

typedef void (*DllA6SpawnFn)(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags);

/* Two-slot view of the DLL 0xA6 resource used by DLL 0x299: only the spawn
   slot at +4 is reached, and it is called with two trailing arguments the
   DllA6SpawnFn prototype does not name. */
typedef struct DllA6Interface {
    ResourceDescriptorCallback reserved;
    void (*spawn)(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags, int unusedA,
                  int unusedB);
} DllA6Interface;

typedef struct DllA6ResourceDescriptor {
    u32 metadata[4];
    ResourceDescriptorCallback initialise;
    ResourceDescriptorCallback release;
    ResourceDescriptorCallback reserved18;
    DllA6SpawnFn spawn;
} DllA6ResourceDescriptor;

STATIC_ASSERT(offsetof(DllA6ResourceDescriptor, metadata) == 0x00);
STATIC_ASSERT(offsetof(DllA6ResourceDescriptor, initialise) == 0x10);
STATIC_ASSERT(offsetof(DllA6ResourceDescriptor, release) == 0x14);
STATIC_ASSERT(offsetof(DllA6ResourceDescriptor, reserved18) == 0x18);
STATIC_ASSERT(offsetof(DllA6ResourceDescriptor, spawn) == 0x1C);
STATIC_ASSERT(sizeof(DllA6ResourceDescriptor) == 0x20);

extern DllA6ResourceDescriptor gDllA6ResourceDescriptor;

void dll_A6_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags);
void dll_A6_release(void);
void dll_A6_initialise(void);

#endif /* MAIN_DLL_DLL_00A6_MODGFX_H_ */
