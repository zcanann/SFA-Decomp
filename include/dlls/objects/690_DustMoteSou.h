#ifndef DLLS_OBJECTS_690_DUSTMOTESOU_H_
#define DLLS_OBJECTS_690_DUSTMOTESOU_H_

#include "global.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

/* Reader prefix through +0x2A; the active EN serialized extent is unproven.
 * Secondary EN rev1 / JP placements are 0x30 bytes. Do not use this reader
 * view's sizeof as a placement allocation or copy size. This DLL requests no
 * extra state: dustmotesou_getExtraSize returns zero. */
typedef struct DustMoteSouPlacementPrefix {
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 spawnTypeIndex;
    u8 effectParamIndex;
    union {
        u8 distributionMode; /* Ordinary burst distribution selector. */
        u8 frameMask;        /* TailLightSo: ANDed with the effect frame timer. */
        u8 burstCount;       /* FireWorkSou: number of particles requested. */
    } emission;
    u8 unknown1E[2];
    f32 scale;
    s16 gameBit;
    union {
        struct {
            u8 extentX;
            u8 extentY;
            u8 extentZ;
        } box;
        struct {
            u8 radiusEnd;
            u8 radiusStart;
            u8 height;
        } arced;
        struct {
            u8 distanceMultiplier;
            u8 unknown27[2];
        } directional;
    } geometry;
    u8 spawnChancePercent; /* Ordinary bursts: threshold for four 0..99 trials. */
    u8 burstMode;
} DustMoteSouPlacementPrefix;

STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, rotZ) == 0x18);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, rotY) == 0x19);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, rotX) == 0x1A);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, spawnTypeIndex) == 0x1B);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, effectParamIndex) == 0x1C);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, emission.distributionMode) == 0x1D);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, emission.frameMask) == 0x1D);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, emission.burstCount) == 0x1D);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, scale) == 0x20);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, gameBit) == 0x24);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.box.extentX) == 0x26);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.box.extentY) == 0x27);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.box.extentZ) == 0x28);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.arced.radiusEnd) == 0x26);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.arced.radiusStart) == 0x27);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.arced.height) == 0x28);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.directional.distanceMultiplier) == 0x26);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, geometry.directional.unknown27) == 0x27);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, spawnChancePercent) == 0x29);
STATIC_ASSERT(offsetof(DustMoteSouPlacementPrefix, burstMode) == 0x2A);

extern ObjectDescriptor gDustMoteSouObjDescriptor;

int dustmotesou_getExtraSize(void);
int dustmotesou_getObjectTypeId(void);
void dustmotesou_free(GameObject* obj);
void dustmotesou_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dustmotesou_hitDetect(void);
void dustmotesou_update(GameObject* obj);
void dustmotesou_init(GameObject* obj, DustMoteSouPlacementPrefix* setup);
void dustmotesou_release(void);
void dustmotesou_initialise(void);

#endif /* DLLS_OBJECTS_690_DUSTMOTESOU_H_ */
