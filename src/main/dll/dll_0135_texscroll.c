#include "main/map_block.h"
#include "main/dll/mmp_moonrock.h"



extern uint GameBit_Get(int eventId);

void texscroll2_setScale(TexScroll2Object* obj, s8 scale);

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void* mapGetBlock(int idx);
extern int* getTablesBinEntry(int id);
extern void* getLoadedTexture(int id);
extern void* fn_8006070C(void* block, int idx);
extern void mapTextureScrollSetStep(int slot, int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                                    int unusedXStep, int unusedYStep, int unusedWidthFixed, int unusedHeightFixed);
extern int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed, int unusedXStep,
                                   int unusedYStep, int unusedWidthFixed, int unusedHeightFixed);

typedef struct TexScrollMapBlock
{
    u8 pad00[0xA2];
    u8 layerCount;
} TexScrollMapBlock;


void texscroll2_applyMapTextureScroll(int obj, TexScroll2State* state);

void texscroll2_free(void);

void texscroll2_hitDetect(void);

void texscroll2_release(void);

void texscroll2_initialise(void);


void texscroll2_update(TexScroll2Object* obj);

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
int texscroll2_getObjectTypeId(void);
int texscroll_getExtraSize(void) { return 0x1c; }
int texscroll_getObjectTypeId(void) { return 0x0; }

void waveanimator_modelMtxFn(int obj, int a, int b, int c);

void texscroll2_init(TexScroll2Object* obj, TexScrollPlacement* placement, int loadFlags);

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

extern f32 lbl_803E3F30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F38;

void texscroll2_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void texscroll_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F38);
}
