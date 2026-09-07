#ifndef DLLS_OBJECTS_466_WORLDPLANET_H_
#define DLLS_OBJECTS_466_WORLDPLANET_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "global.h"

#define WORLDPLANET_PLANET_COUNT 5

typedef enum WorldPlanetSharedObjectId {
    WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID = 0x43077,
} WorldPlanetSharedObjectId;

typedef enum WorldPlanetSlot {
    WORLDPLANET_SLOT_WALLED_CITY = 0,
    WORLDPLANET_SLOT_CLOUDRUNNER = 1,
    WORLDPLANET_SLOT_DINOSAUR_PLANET = 2,
    WORLDPLANET_SLOT_DRAGON_ROCK = 3,
    WORLDPLANET_SLOT_DARKICE_MINES = 4,
} WorldPlanetSlot;

/* getExtraSize() allocates 0x18 bytes. */
typedef struct WorldPlanetState {
    u8 unknown00[0x06];
    s16 foxSpawnTimer;
    u8 flags;
    u8 selectionLocked;
    s8 previousStickX;
    s8 previousStickY;
    s8 stickXRepeatTimer;
    s8 stickYRepeatTimer;
    u8 unknown0E[0x02];
    s8 selectedPlanet;
    u8 unlockedPlanetMask;
    u8 unknown12[0x02];
    u32 orbitSoundFrameCount;
} WorldPlanetState;

typedef struct WorldPlanetColorRGBA8 {
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;
} WorldPlanetColorRGBA8;

/*
 * Retail emits this final color record as eight bytes. The trailing bytes are
 * kept opaque until another consumer establishes their purpose.
 */
typedef struct WorldPlanetPaddedColorRGBA8 {
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;
    u8 unknown04[0x04];
} WorldPlanetPaddedColorRGBA8;

STATIC_ASSERT(offsetof(WorldPlanetState, foxSpawnTimer) == 0x06);
STATIC_ASSERT(offsetof(WorldPlanetState, flags) == 0x08);
STATIC_ASSERT(offsetof(WorldPlanetState, selectionLocked) == 0x09);
STATIC_ASSERT(offsetof(WorldPlanetState, previousStickX) == 0x0A);
STATIC_ASSERT(offsetof(WorldPlanetState, previousStickY) == 0x0B);
STATIC_ASSERT(offsetof(WorldPlanetState, stickXRepeatTimer) == 0x0C);
STATIC_ASSERT(offsetof(WorldPlanetState, stickYRepeatTimer) == 0x0D);
STATIC_ASSERT(offsetof(WorldPlanetState, selectedPlanet) == 0x10);
STATIC_ASSERT(offsetof(WorldPlanetState, unlockedPlanetMask) == 0x11);
STATIC_ASSERT(offsetof(WorldPlanetState, orbitSoundFrameCount) == 0x14);
STATIC_ASSERT(sizeof(WorldPlanetState) == 0x18);

STATIC_ASSERT(sizeof(WorldPlanetColorRGBA8) == 0x04);
STATIC_ASSERT(offsetof(WorldPlanetPaddedColorRGBA8, unknown04) == 0x04);
STATIC_ASSERT(sizeof(WorldPlanetPaddedColorRGBA8) == 0x08);

extern u8 gWorldPlanetHintFlagTable[8];
extern u8 gWorldPlanetDefaultSelectOrder[8];
extern u8 gWorldPlanetSelectionToIndex[8];
extern u8 gWorldPlanetTitleStringIds[8];
extern u8 gWorldPlanetWarpMapIndices[6];
extern u8 gWorldPlanetLoadMapIndices[6];
extern u8 gWorldPlanetBriefingSpeakerModel[8];
extern int gWorldPlanetSavedSelection;
extern int gWorldPlanetGameBitTable[WORLDPLANET_PLANET_COUNT];

extern WorldPlanetColorRGBA8 gWorldPlanetAmbientFrom;
extern WorldPlanetColorRGBA8 gWorldPlanetAmbientTo;
extern WorldPlanetColorRGBA8 gWorldPlanetSkyColorFrom;
extern WorldPlanetColorRGBA8 gWorldPlanetSkyColorTo;
extern WorldPlanetColorRGBA8 gWorldPlanetMoonFrom;
extern WorldPlanetPaddedColorRGBA8 gWorldPlanetMoonTo;
extern WorldPlanetColorRGBA8 gWorldPlanetCurMoon;
extern WorldPlanetColorRGBA8 gWorldPlanetCurAmbient;
extern WorldPlanetColorRGBA8 gWorldPlanetCurSky;

void worldplanet_updateMapLighting(GameObject* obj);
int worldplanet_getExtraSize(void);
int worldplanet_getObjectTypeId(void);
void worldplanet_free(void);
void worldplanet_render(GameObject* obj, u32 renderArg2, u32 renderArg3, u32 renderArg4, u32 renderArg5, s8 visible);
void worldplanet_hitDetect(void);
void worldplanet_update(GameObject* obj);
void worldplanet_readMapInput(GameObject* obj, s8* outStickX, s8* outStickY);
void worldplanet_init(GameObject* obj);
void worldplanet_release(void);
void worldplanet_initialise(void);

extern ObjectDescriptor gWorldPlanetObjDescriptor;

#endif /* DLLS_OBJECTS_466_WORLDPLANET_H_ */
