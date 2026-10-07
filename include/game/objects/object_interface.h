#ifndef GAME_OBJECTS_OBJECT_INTERFACE_H_
#define GAME_OBJECTS_OBJECT_INTERFACE_H_

#include "game/objects/object_fwd.h"
#include "global.h"

typedef void (*ObjectInterfaceCallback)(void);
typedef int (*ObjectInterfaceExtraSizeCallback)(void);

/* Engine init dispatch contract; individual slots retain their object-specific prototypes. */
typedef void (*ObjectInterfaceInitCallback)(GameObject* obj, void* placementData, int initFlags);

/*
 * Common prefix of every object DLL's runtime interface. Resource_Acquire
 * returns a handle to this table, starting at an ObjectDescriptor's slot02.
 * Object-specific callbacks extend this prefix.
 */
typedef struct ObjectInterface {
    ObjectInterfaceCallback slot02;
    ObjectInterfaceCallback init;
    ObjectInterfaceCallback update;
    ObjectInterfaceCallback hitDetect;
    ObjectInterfaceCallback render;
    ObjectInterfaceCallback free;
    ObjectInterfaceCallback getObjectTypeId;
    ObjectInterfaceExtraSizeCallback getExtraSize;
} ObjectInterface;

typedef ObjectInterfaceCallback** ObjectInterfaceHandle;

STATIC_ASSERT(offsetof(ObjectInterface, slot02) == 0x00);
STATIC_ASSERT(offsetof(ObjectInterface, init) == 0x04);
STATIC_ASSERT(offsetof(ObjectInterface, update) == 0x08);
STATIC_ASSERT(offsetof(ObjectInterface, hitDetect) == 0x0C);
STATIC_ASSERT(offsetof(ObjectInterface, render) == 0x10);
STATIC_ASSERT(offsetof(ObjectInterface, free) == 0x14);
STATIC_ASSERT(offsetof(ObjectInterface, getObjectTypeId) == 0x18);
STATIC_ASSERT(offsetof(ObjectInterface, getExtraSize) == 0x1C);
STATIC_ASSERT(sizeof(ObjectInterface) == 0x20);

#endif /* GAME_OBJECTS_OBJECT_INTERFACE_H_ */
