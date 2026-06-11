#include "main/dll/fx_800944A0_shared.h"

void viewFinderSetZoom(f32 zoom)
{
    lbl_803DB790 = lbl_803DF348 / zoom;
}

void viewFinderSetZoomTo50(void)
{
    lbl_803DB790 = lbl_803DF34C;
}

