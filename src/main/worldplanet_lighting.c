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

#define WORLDPLANET_LERP_BYTE(from, to, idx, t)                                                                        \
    ((u8)(s32)((t) * (f32)((s32)(to)[idx] - (s32)(from)[idx]) + (f32)(s32)(from)[idx]))

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

    gWorldPlanetCurSky[0] = WORLDPLANET_LERP_BYTE(gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, 0, lbl_803E65F8);
    gWorldPlanetCurSky[1] = WORLDPLANET_LERP_BYTE(gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, 1, lbl_803E65F8);
    gWorldPlanetCurSky[2] = WORLDPLANET_LERP_BYTE(gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, 2, lbl_803E65F8);
    skyFn_800895e0(7, ((u8*)gWorldPlanetCurSky)[0], ((u8*)gWorldPlanetCurSky)[1],
                   ((u8*)gWorldPlanetCurSky)[2], 0x40, 0x40);

    gWorldPlanetCurLight[0] = WORLDPLANET_LERP_BYTE(gWorldPlanetLightFrom, gWorldPlanetLightTo, 0, gWorldPlanetLightingLerpT);
    gWorldPlanetCurLight[1] = WORLDPLANET_LERP_BYTE(gWorldPlanetLightFrom, gWorldPlanetLightTo, 1, gWorldPlanetLightingLerpT);
    gWorldPlanetCurLight[2] = WORLDPLANET_LERP_BYTE(gWorldPlanetLightFrom, gWorldPlanetLightTo, 2, gWorldPlanetLightingLerpT);
    fn_80089510(7, ((u8*)gWorldPlanetCurLight)[0], ((u8*)gWorldPlanetCurLight)[1],
                ((u8*)gWorldPlanetCurLight)[2]);

    gWorldPlanetCurAmbient[0] = WORLDPLANET_LERP_BYTE(gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, 0, gWorldPlanetLightingLerpT);
    gWorldPlanetCurAmbient[1] = WORLDPLANET_LERP_BYTE(gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, 1, gWorldPlanetLightingLerpT);
    gWorldPlanetCurAmbient[2] = WORLDPLANET_LERP_BYTE(gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, 2, gWorldPlanetLightingLerpT);
    fn_80089578(7, ((u8*)gWorldPlanetCurAmbient)[0], ((u8*)gWorldPlanetCurAmbient)[1],
                ((u8*)gWorldPlanetCurAmbient)[2]);

    gWorldPlanetCurIntensity = (u8)(s32)(gWorldPlanetLightingLerpT * lbl_803E6600 + lbl_803E65FC);
    skyFn_800894a8(7, gWorldPlanetLightingSkyDirX, lbl_803E65F8, gWorldPlanetLightingSkyDirZ);
}
