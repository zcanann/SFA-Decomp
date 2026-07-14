#include "ghidra_import.h"
#include "main/worldplanet_lighting.h"
#include "main/sky_api.h"

extern u8 lbl_803DC1F4[4];
extern u8 lbl_803DC1F8[4];
extern u8 lbl_803DC1FC[4];
extern u8 lbl_803DC200[4];
extern u8 lbl_803DC204[4];
extern u8 lbl_803DC208[8];

#define WORLDPLANET_LERP_BYTE(from, to, idx, t)                                                                        \
    ((u8)(s32)((t) * (f32)((s32)(to)[idx] - (s32)(from)[idx]) + (f32)(s32)(from)[idx]))

extern f32 gWorldPlanetLightingLerpT;
extern u8 lbl_803DDD18;
extern u8 lbl_803DDD1C;
extern u8 lbl_803DDD20;
extern u8 lbl_803DDD24;
extern f32 lbl_803E65F8;
extern f32 lbl_803E65FC;
extern f32 lbl_803E6600;
extern f32 gWorldPlanetLightingSkyDirX;
extern f32 gWorldPlanetLightingSkyDirZ;
extern void fn_80089510(int flags, u8 red, u8 green, u8 blue);
extern void fn_80089578(int flags, u8 red, u8 green, u8 blue);

#pragma peephole on
void worldplanet_updateMapLighting(void)
{
    skyFn_80089710(7, 1, 0);

    gWorldPlanetLightingLerpT = lbl_803E65F8;

    (&lbl_803DDD24)[0] = WORLDPLANET_LERP_BYTE(lbl_803DC1FC, lbl_803DC200, 0, lbl_803E65F8);
    (&lbl_803DDD24)[1] = WORLDPLANET_LERP_BYTE(lbl_803DC1FC, lbl_803DC200, 1, lbl_803E65F8);
    (&lbl_803DDD24)[2] = WORLDPLANET_LERP_BYTE(lbl_803DC1FC, lbl_803DC200, 2, lbl_803E65F8);
    skyFn_800895e0(7, ((volatile u8*)&lbl_803DDD24)[0], ((volatile u8*)&lbl_803DDD24)[1],
                   ((volatile u8*)&lbl_803DDD24)[2], 0x40, 0x40);

    (&lbl_803DDD20)[0] = WORLDPLANET_LERP_BYTE(lbl_803DC1F4, lbl_803DC1F8, 0, gWorldPlanetLightingLerpT);
    (&lbl_803DDD20)[1] = WORLDPLANET_LERP_BYTE(lbl_803DC1F4, lbl_803DC1F8, 1, gWorldPlanetLightingLerpT);
    (&lbl_803DDD20)[2] = WORLDPLANET_LERP_BYTE(lbl_803DC1F4, lbl_803DC1F8, 2, gWorldPlanetLightingLerpT);
    fn_80089510(7, ((volatile u8*)&lbl_803DDD20)[0], ((volatile u8*)&lbl_803DDD20)[1],
                ((volatile u8*)&lbl_803DDD20)[2]);

    (&lbl_803DDD1C)[0] = WORLDPLANET_LERP_BYTE(lbl_803DC204, lbl_803DC208, 0, gWorldPlanetLightingLerpT);
    (&lbl_803DDD1C)[1] = WORLDPLANET_LERP_BYTE(lbl_803DC204, lbl_803DC208, 1, gWorldPlanetLightingLerpT);
    (&lbl_803DDD1C)[2] = WORLDPLANET_LERP_BYTE(lbl_803DC204, lbl_803DC208, 2, gWorldPlanetLightingLerpT);
    fn_80089578(7, ((volatile u8*)&lbl_803DDD1C)[0], ((volatile u8*)&lbl_803DDD1C)[1],
                ((volatile u8*)&lbl_803DDD1C)[2]);

    lbl_803DDD18 = (u8)(s32)(gWorldPlanetLightingLerpT * lbl_803E6600 + lbl_803E65FC);
    skyFn_800894a8(7, gWorldPlanetLightingSkyDirX, lbl_803E65F8, gWorldPlanetLightingSkyDirZ);
}
