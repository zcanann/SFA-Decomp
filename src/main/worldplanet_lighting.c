#include "ghidra_import.h"
#include "main/worldplanet_lighting.h"
#include "main/sky.h"
#include "main/sky_api.h"

#define WORLDPLANET_SKY_LIGHT_MASK  7
#define WORLDPLANET_SKY_COLOR_SCALE 0x40

#define WORLDPLANET_LERP_CHANNEL(dst, from, to, channel, t)                                                            \
    {                                                                                                                  \
        int value = (from).channel;                                                                                    \
        (dst).channel = value + (t) * (f32)((to).channel - value);                                                     \
    }

extern f32 gWorldPlanetLightingLerpT;
extern u8 gWorldPlanetCurIntensity;
extern f32 gWorldPlanetLightingZero;
extern f32 gWorldPlanetLightingMinIntensity;
extern f32 gWorldPlanetLightingIntensityRange;
extern f32 gWorldPlanetLightingSkyDirX;
extern f32 gWorldPlanetLightingSkyDirZ;
void worldplanet_updateMapLighting(GameObject* obj)
{
    skyFn_80089710(WORLDPLANET_SKY_LIGHT_MASK, 1, 0);

    gWorldPlanetLightingLerpT = gWorldPlanetLightingZero;

    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, red,
                            gWorldPlanetLightingZero)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, green,
                            gWorldPlanetLightingZero)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, blue,
                            gWorldPlanetLightingZero)
    skySetBaseColor(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetCurSky.red, gWorldPlanetCurSky.green,
                    gWorldPlanetCurSky.blue, WORLDPLANET_SKY_COLOR_SCALE, WORLDPLANET_SKY_COLOR_SCALE);

    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurLight, gWorldPlanetLightFrom, gWorldPlanetLightTo, red,
                            gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurLight, gWorldPlanetLightFrom, gWorldPlanetLightTo, green,
                            gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurLight, gWorldPlanetLightFrom, gWorldPlanetLightTo, blue,
                            gWorldPlanetLightingLerpT)
    skySetLightColor(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetCurLight.red, gWorldPlanetCurLight.green,
                     gWorldPlanetCurLight.blue);

    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, red,
                            gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, green,
                            gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, blue,
                            gWorldPlanetLightingLerpT)
    skySetAmbientColor(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetCurAmbient.red, gWorldPlanetCurAmbient.green,
                       gWorldPlanetCurAmbient.blue);

    gWorldPlanetCurIntensity =
        (u8)(s32)(gWorldPlanetLightingLerpT * gWorldPlanetLightingIntensityRange + gWorldPlanetLightingMinIntensity);
    skySetLightDirection(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetLightingSkyDirX, gWorldPlanetLightingZero,
                         gWorldPlanetLightingSkyDirZ);
}
