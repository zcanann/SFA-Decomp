/*
 * viewfinder - camera zoom control for the photo/viewfinder mode.
 *
 * Maintains the shared zoom scalar lbl_803DB790, derived by scaling a
 * base reference value (lbl_803DF348) by the inverse of the current
 * camera FOV. viewFinderSetZoomTo50 snaps it to a fixed preset
 * (lbl_803DF34C). The result is consumed elsewhere (dll_000A_expgfx)
 * as a view-projection W threshold gating effect rendering.
 *
 * Driven from the player viewfinder/camera-mode code (player.c,
 * dll_0044_cameramodeviewfinder.c).
 */
#include "main/dll/fx_800944A0_shared.h" /* lbl_803DB790/DF348/DF34C + own forward-decls live only here */

void viewFinderSetZoom(f32 zoom)
{
    lbl_803DB790 = lbl_803DF348 / zoom;
}

void viewFinderSetZoomTo50(void)
{
    lbl_803DB790 = lbl_803DF34C;
}
