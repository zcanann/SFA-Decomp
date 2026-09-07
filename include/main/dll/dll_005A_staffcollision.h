#ifndef MAIN_DLL_DLL_005A_STAFFCOLLISION_H_
#define MAIN_DLL_DLL_005A_STAFFCOLLISION_H_

#include "global.h"
#include "game/objects/object_fwd.h"
#include "main/dll/partfx_interface.h"
#include "main/resource.h"

typedef struct StaffCollisionColorArgs {
    int count;
    int red;
    int green;
    int blue;
} StaffCollisionColorArgs;

STATIC_ASSERT(offsetof(StaffCollisionColorArgs, count) == 0x00);
STATIC_ASSERT(offsetof(StaffCollisionColorArgs, red) == 0x04);
STATIC_ASSERT(offsetof(StaffCollisionColorArgs, green) == 0x08);
STATIC_ASSERT(offsetof(StaffCollisionColorArgs, blue) == 0x0C);
STATIC_ASSERT(sizeof(StaffCollisionColorArgs) == 0x10);

typedef s16 (*StaffCollisionSpawnFn)(GameObject* sourceObj, int mode, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                                      int unusedModelId, const StaffCollisionColorArgs* colorArgs);

typedef struct StaffCollisionInterface {
    ResourceDescriptorCallback reserved;
    StaffCollisionSpawnFn spawn;
} StaffCollisionInterface;

STATIC_ASSERT(offsetof(StaffCollisionInterface, reserved) == 0x00);
STATIC_ASSERT(offsetof(StaffCollisionInterface, spawn) == 0x04);
STATIC_ASSERT(sizeof(StaffCollisionInterface) == 0x08);

typedef struct StaffCollisionResourceDescriptor {
    u32 metadata[4];
    ResourceDescriptorCallback initialise;
    ResourceDescriptorCallback release;
    ResourceDescriptorCallback reserved18;
    StaffCollisionSpawnFn spawn;
    u32 padding;
} StaffCollisionResourceDescriptor;

STATIC_ASSERT(offsetof(StaffCollisionResourceDescriptor, metadata) == 0x00);
STATIC_ASSERT(offsetof(StaffCollisionResourceDescriptor, initialise) == 0x10);
STATIC_ASSERT(offsetof(StaffCollisionResourceDescriptor, release) == 0x14);
STATIC_ASSERT(offsetof(StaffCollisionResourceDescriptor, reserved18) == 0x18);
STATIC_ASSERT(offsetof(StaffCollisionResourceDescriptor, spawn) == 0x1C);
STATIC_ASSERT(offsetof(StaffCollisionResourceDescriptor, padding) == 0x20);
STATIC_ASSERT(sizeof(StaffCollisionResourceDescriptor) == 0x24);

extern StaffCollisionResourceDescriptor gStaffCollisionResourceDescriptor;

/* Returns the last spawn result, or zero when the spawn count is nonpositive. */
s16 StaffCollision_spawn(GameObject* sourceObj, int mode, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                          int unusedModelId, const StaffCollisionColorArgs* colorArgs);

#endif /* MAIN_DLL_DLL_005A_STAFFCOLLISION_H_ */
