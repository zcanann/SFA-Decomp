#ifndef MAIN_WORLDPLANET_LIGHTING_H_
#define MAIN_WORLDPLANET_LIGHTING_H_

#include "global.h"
#include "main/game_object.h"

typedef struct WorldPlanetColorRGB8
{
    u8 red;
    u8 green;
    u8 blue;
} WorldPlanetColorRGB8;

typedef struct WorldPlanetColorRGBA8
{
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;
} WorldPlanetColorRGBA8;

typedef struct WorldPlanetPaddedColorRGBA8
{
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;
    u8 padding[4];
} WorldPlanetPaddedColorRGBA8;

STATIC_ASSERT(sizeof(WorldPlanetColorRGB8) == 3);
STATIC_ASSERT(sizeof(WorldPlanetColorRGBA8) == 4);
STATIC_ASSERT(sizeof(WorldPlanetPaddedColorRGBA8) == 8);

extern WorldPlanetColorRGBA8 gWorldPlanetLightFrom;
extern WorldPlanetColorRGBA8 gWorldPlanetLightTo;
extern WorldPlanetColorRGBA8 gWorldPlanetSkyColorFrom;
extern WorldPlanetColorRGBA8 gWorldPlanetSkyColorTo;
extern WorldPlanetColorRGBA8 gWorldPlanetAmbientFrom;
extern WorldPlanetPaddedColorRGBA8 gWorldPlanetAmbientTo;

extern WorldPlanetColorRGB8 gWorldPlanetCurAmbient;
extern WorldPlanetColorRGB8 gWorldPlanetCurLight;
extern WorldPlanetColorRGB8 gWorldPlanetCurSky;

void worldplanet_updateMapLighting(GameObject* obj);

#endif /* MAIN_WORLDPLANET_LIGHTING_H_ */
