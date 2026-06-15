#include "main/map_block.h"
#include "main/dll/mmp_moonrock.h"

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F38;

void texscroll_free(void)
{
}

void texscroll_hitDetect(void)
{
}

void texscroll_update(void)
{
}

void texscroll_release(void)
{
}

void texscroll_initialise(void)
{
}

int texscroll2_getExtraSize(void);
int texscroll_getExtraSize(void) { return 0x1c; }
int texscroll_getObjectTypeId(void) { return 0x0; }

void waveanimator_modelMtxFn(int obj, int a, int b, int c);

void texscroll_init(TexScrollObject* obj, TexScrollPlacement* placement, int loadFlags)
{
    TexScrollState* state = obj->state;
    if (state == NULL) return;
    state->initLock = 1;
    state->stepX = (s16)(s32)
    placement->stepX;
    state->stepY = (s16)(s32)
    placement->stepY;
    state->scrollSlot = 0;
    state->flags = 0;
    state->gameBit = placement->gameBit;
    if (loadFlags == 0)
    {
        state->offsetX = 0;
        state->offsetY = 0;
    }
    state->initLock = 0;
}

void texscroll_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F38);
}
