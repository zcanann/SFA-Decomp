#ifndef DLLS_OBJECTS_358_H_
#define DLLS_OBJECTS_358_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/vec_types.h"

/* Eleven advertised callbacks followed by opaque words. The later verified
 * revisions place the next descriptor after one tail word instead of five. */
typedef struct ExplodedDescriptor {
    ObjectDescriptor11ExtraSize descriptor;
#if defined(VERSION_GSAE01_rev1) || defined(VERSION_GSAP01_rev1)
    u32 unknown3C[1];
#else
    u32 unknown3C[5];
#endif
} ExplodedDescriptor;

STATIC_ASSERT(offsetof(ExplodedDescriptor, descriptor) == 0x00);
STATIC_ASSERT(offsetof(ExplodedDescriptor, descriptor.slot0A) == 0x38);
STATIC_ASSERT(offsetof(ExplodedDescriptor, unknown3C) == 0x3C);
#if defined(VERSION_GSAE01_rev1) || defined(VERSION_GSAP01_rev1)
STATIC_ASSERT(sizeof(ExplodedDescriptor) == 0x40);
#else
STATIC_ASSERT(sizeof(ExplodedDescriptor) == 0x50);
#endif

typedef enum ExplodedPhase {
    EXPLODED_PHASE_IDLE = 0,
    EXPLODED_PHASE_ACTIVE = 1,
    EXPLODED_PHASE_EXPIRED = 2,
} ExplodedPhase;

/* gExplodedObjDescriptor from slot02 onwards: the export table the spawning
   object reaches through obj->anim.dll. */
typedef struct ExplodedInterface {
    void* pad00[8];
    int (*getPhase)(GameObject* obj);
} ExplodedInterface;

#define EXPLODED_INTERFACE(fragment) ((ExplodedInterface*)*((GameObject*)(fragment))->anim.dll)

STATIC_ASSERT(offsetof(ExplodedInterface, getPhase) == 0x20);

typedef struct ExplodedPlacement {
    ObjPlacement base;
    u8 modelBankIndex;
    u8 pad19;
    Vec3s initialRotation;
    Vec3s initialVelocity;
    Vec3s acceleration;
    Vec3s spin;
    Vec3s spinVelocity;
    u16 lifetimeFrames;
    union {
        s16 floorOffset;
        u16 floorOffsetRaw;
    };
    u8 pad3C;
    s8 scaleByte;
    u8 pad3E[0x06];
} ExplodedPlacement;

typedef struct ExplodedState {
    Vec3f localCenter;
    Vec3f initialLocalCenter;
    Vec3f spin;
    Vec3f spinVelocity;
    Vec3f acceleration;
    u8 pad3C[0x18];
    f32 floorHeight;
    s32 elapsedFrames;
    s32 durationFrames;
    u8 pad60[0x06];
    u8 physicsFlags;
    u8 unknown67;
    u8 pad68;
    u8 phase; /* ExplodedPhase */
    u8 pad6A[0x02];
} ExplodedState;

STATIC_ASSERT(offsetof(ExplodedPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(ExplodedPlacement, modelBankIndex) == 0x18);
STATIC_ASSERT(offsetof(ExplodedPlacement, initialRotation) == 0x1A);
STATIC_ASSERT(offsetof(ExplodedPlacement, initialVelocity) == 0x20);
STATIC_ASSERT(offsetof(ExplodedPlacement, acceleration) == 0x26);
STATIC_ASSERT(offsetof(ExplodedPlacement, spin) == 0x2C);
STATIC_ASSERT(offsetof(ExplodedPlacement, spinVelocity) == 0x32);
STATIC_ASSERT(offsetof(ExplodedPlacement, lifetimeFrames) == 0x38);
STATIC_ASSERT(offsetof(ExplodedPlacement, floorOffset) == 0x3A);
STATIC_ASSERT(offsetof(ExplodedPlacement, floorOffsetRaw) == 0x3A);
STATIC_ASSERT(offsetof(ExplodedPlacement, scaleByte) == 0x3D);
STATIC_ASSERT(offsetof(ExplodedPlacement, pad3E) == 0x3E);
STATIC_ASSERT(sizeof(ExplodedPlacement) == 0x44);

STATIC_ASSERT(offsetof(ExplodedState, localCenter) == 0x00);
STATIC_ASSERT(offsetof(ExplodedState, initialLocalCenter) == 0x0C);
STATIC_ASSERT(offsetof(ExplodedState, spin) == 0x18);
STATIC_ASSERT(offsetof(ExplodedState, spinVelocity) == 0x24);
STATIC_ASSERT(offsetof(ExplodedState, acceleration) == 0x30);
STATIC_ASSERT(offsetof(ExplodedState, pad3C) == 0x3C);
STATIC_ASSERT(offsetof(ExplodedState, floorHeight) == 0x54);
STATIC_ASSERT(offsetof(ExplodedState, elapsedFrames) == 0x58);
STATIC_ASSERT(offsetof(ExplodedState, durationFrames) == 0x5C);
STATIC_ASSERT(offsetof(ExplodedState, pad60) == 0x60);
STATIC_ASSERT(offsetof(ExplodedState, physicsFlags) == 0x66);
STATIC_ASSERT(offsetof(ExplodedState, unknown67) == 0x67);
STATIC_ASSERT(offsetof(ExplodedState, pad68) == 0x68);
STATIC_ASSERT(offsetof(ExplodedState, phase) == 0x69);
STATIC_ASSERT(offsetof(ExplodedState, pad6A) == 0x6A);
STATIC_ASSERT(sizeof(ExplodedState) == 0x6C);


void exploded_initDebrisState(GameObject* obj, ExplodedPlacement* placement, int usePresetCenter,
                              ExplodedState* state);
void exploded_seedDebrisMotion(GameObject* obj, ExplodedState* state, ExplodedPlacement* placement);
u8 exploded_getPhase(GameObject* obj);
int exploded_getExtraSize(void);
u32 exploded_getObjectTypeId(GameObject* obj);
void exploded_free(void);
void exploded_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void exploded_hitDetect(void);
int exploded_stepDebrisPhysics(GameObject* obj, ExplodedState* state);
void exploded_update(GameObject* obj);
void exploded_init(GameObject* obj, ExplodedPlacement* placement, int usePresetCenter);
void exploded_release(void);
void exploded_initialise(void);

extern ExplodedDescriptor gExplodedObjDescriptor;

#endif /* DLLS_OBJECTS_358_H_ */
