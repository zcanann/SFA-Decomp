#include <math.h>

#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

static struct {
    GXVtxDescList vcd[27];
    GXVtxAttrFmtList vat[27];
} lbl_803AF698;

#define vcd lbl_803AF698.vcd
#define vat lbl_803AF698.vat

void GXDrawTorus(f32 rc, u8 numc, u8 numt) {
    (void)rc;
    (void)numc;
    (void)numt;
}
