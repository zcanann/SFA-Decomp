/*
 * viewfinder - camera zoom control for the photo/viewfinder mode.
 *
 * Maintains the shared zoom scalar lbl_803DB790, derived by scaling a
 * base reference value by the inverse of the current
 * camera FOV. viewFinderSetZoomTo50 snaps it to a fixed preset
 * (lbl_803DF34C). The result is consumed elsewhere (dll_000A_expgfx)
 * as a view-projection W threshold gating effect rendering.
 *
 * Driven from the player viewfinder/camera-mode code (player.c,
 * dll_0044_cameramodeviewfinder.c).
 */
#include "main/dll/viewfinder.h"

void viewFinderSetZoom(f32 zoom)
{
    lbl_803DB790 = -3000.0f / zoom;
}

__declspec(section ".sdata2") f32 lbl_803DF34C = 50.0f;

void viewFinderSetZoomTo50(void)
{
    lbl_803DB790 = lbl_803DF34C;
}
