#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"

#pragma scheduling off
#pragma peephole off
void viewFinderSetZoom(f32 zoom) {
    lbl_803DB790 = lbl_803DF348 / zoom;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void viewFinderSetZoomTo50(void) {
    lbl_803DB790 = lbl_803DF34C;
}
#pragma peephole reset
#pragma scheduling reset

