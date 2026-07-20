#include "ghidra_import.h"
#include "main/worldplanet_lighting.h"
#include "main/sky.h"
#include "main/sky_api.h"

extern u8 gWorldPlanetLightFrom[4];
extern u8 gWorldPlanetLightTo[4];
extern u8 gWorldPlanetSkyColorFrom[4];
extern u8 gWorldPlanetSkyColorTo[4];
extern u8 gWorldPlanetAmbientFrom[4];
extern u8 gWorldPlanetAmbientTo[8];

#define WORLDPLANET_LERP_BYTE(dst, from, to, idx, t)                                                                   \
    {                                                                                                                  \
        int v = (from)[idx];                                                                                           \
        (dst)[idx] = v + (t) * (f32)((to)[idx] - v);                                                                   \
    }

extern f32 gWorldPlanetLightingLerpT;
extern u8 gWorldPlanetCurIntensity;
extern u8 gWorldPlanetCurAmbient[3];
extern u8 gWorldPlanetCurLight[3];
extern u8 gWorldPlanetCurSky[3];
extern f32 lbl_803E65F8;
extern f32 lbl_803E65FC;
extern f32 lbl_803E6600;
extern f32 gWorldPlanetLightingSkyDirX;
extern f32 gWorldPlanetLightingSkyDirZ;
void worldplanet_updateMapLighting(int a)
{
    skyFn_80089710(7, 1, 0);

    gWorldPlanetLightingLerpT = lbl_803E65F8;

    WORLDPLANET_LERP_BYTE(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, 0, lbl_803E65F8)
    WORLDPLANET_LERP_BYTE(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, 1, lbl_803E65F8)
    WORLDPLANET_LERP_BYTE(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, 2, lbl_803E65F8)
    skySetBaseColor(7, gWorldPlanetCurSky[0], gWorldPlanetCurSky[1],
                   gWorldPlanetCurSky[2], 0x40, 0x40);

    WORLDPLANET_LERP_BYTE(gWorldPlanetCurLight, gWorldPlanetLightFrom, gWorldPlanetLightTo, 0, gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_BYTE(gWorldPlanetCurLight, gWorldPlanetLightFrom, gWorldPlanetLightTo, 1, gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_BYTE(gWorldPlanetCurLight, gWorldPlanetLightFrom, gWorldPlanetLightTo, 2, gWorldPlanetLightingLerpT)
    skySetLightColor(7, gWorldPlanetCurLight[0], gWorldPlanetCurLight[1],
                gWorldPlanetCurLight[2]);

    WORLDPLANET_LERP_BYTE(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, 0, gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_BYTE(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, 1, gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_BYTE(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, 2, gWorldPlanetLightingLerpT)
    skySetAmbientColor(7, gWorldPlanetCurAmbient[0], gWorldPlanetCurAmbient[1],
                gWorldPlanetCurAmbient[2]);

    gWorldPlanetCurIntensity = (u8)(s32)(gWorldPlanetLightingLerpT * lbl_803E6600 + lbl_803E65FC);
    skySetLightDirection(7, gWorldPlanetLightingSkyDirX, lbl_803E65F8, gWorldPlanetLightingSkyDirZ);
}
