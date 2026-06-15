#include "main/map_block.h"
#include "main/dll/mmp_moonrock.h"

extern uint GameBit_Get(int eventId);

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void* mapGetBlock(int idx);
extern int* getTablesBinEntry(int id);
extern void* getLoadedTexture(int id);
extern void* fn_8006070C(void* block, int idx);
extern void mapTextureScrollSetStep(int slot, int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                                    int unusedXStep, int unusedYStep, int unusedWidthFixed, int unusedHeightFixed);
extern int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed, int unusedXStep,
                                   int unusedYStep, int unusedWidthFixed, int unusedHeightFixed);
extern f32 lbl_803E3F30;
extern void objRenderFn_8003b8f4(f32);

void texscroll2_setScale(TexScroll2Object* obj, s8 scale)
{
    TexScroll2State* state = obj->state;

    if (state->stepY == scale)
    {
        return;
    }
    state->stepY = scale;
    state->needsApply = 1;
}

typedef struct TexScrollMapBlock
{
    u8 pad00[0xA2];
    u8 layerCount;
} TexScrollMapBlock;

void texscroll2_applyMapTextureScroll(int obj, TexScroll2State* state)
{
    int* placement;
    void* block;
    int* tables;
    void* tex;
    int i;
    void* material;
    void* layer;
    int j;
    int t1, t2;

    placement = *(int**)(obj + 0x4c);
    block = mapGetBlock(objPosToMapBlockIdx(
        ((GameObject*)obj)->anim.localPosX,
        ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ));
    if (block == NULL)
    {
        state->needsApply = 1;
        return;
    }
    tables = (int*)getTablesBinEntry(TEXSCROLL_TABLE_ID);
    if (tables == NULL) return;
    tex = getLoadedTexture(-tables[(s32) * (s16*)((char*)placement + 0x18)]);
    if (tex == NULL) return;

    for (i = 0; i < (s32)((MapBlockData*)block)->unkA2; i++)
    {
        layer = fn_8006070C(block, i);
        for (j = 0, material = layer; j < (s32) * (u8*)((char*)layer + 0x41); j++)
        {
            if (*(void**)((char*)material + 0x24) == tex)
            {
                t1 = (s32)(u32) * (u16*)((char*)tex + 0xa) << 6;
                t2 = (s32)(u32) * (u16*)((char*)tex + 0xc) << 6;
                if (*(u8*)((char*)material + 0x2a) != TEXSCROLL_SLOT_UNALLOCATED)
                {
                    int v = *(int*)((char*)*(int**)&((GameObject*)obj)->anim.placementData + 0x14);
                    if (v == TEXSCROLL_GAMEBIT_GATED_MAP_A || v == TEXSCROLL_GAMEBIT_GATED_MAP_B)
                    {
                        if (GameBit_Get(state->gameBit) != 0)
                        {
                            mapTextureScrollSetStep(
                                (s32) * (u8*)((char*)material + 0x2a),
                                (s32)state->stepX,
                                (s32)state->stepY,
                                t1, t2,
                                (s32)state->secondaryStepX,
                                (s32)state->secondaryStepY,
                                t1, t2);
                        }
                    }
                    else
                    {
                        mapTextureScrollSetStep(
                            (s32) * (u8*)((char*)material + 0x2a),
                            (s32)state->stepX,
                            (s32)state->stepY,
                            t1, t2,
                            (s32)state->secondaryStepX,
                            (s32)state->secondaryStepY,
                            t1, t2);
                    }
                }
                else
                {
                    *(u8*)((char*)material + 0x2a) = (u8)mapTextureScrollAcquire(
                        (s32)state->stepX,
                        (s32)state->stepY,
                        t1, t2,
                        (s32)state->secondaryStepX,
                        (s32)state->secondaryStepY,
                        t1, t2);
                }
            }
            material = (void*)((char*)material + 8);
        }
    }
}

void texscroll2_free(void)
{
}

void texscroll2_hitDetect(void)
{
}

void texscroll2_release(void)
{
}

void texscroll2_initialise(void)
{
}

void texscroll2_update(TexScroll2Object* obj)
{
    TexScroll2State* state;
    TexScrollMapBlock* block;

    state = obj->state;
    block = mapGetBlock(objPosToMapBlockIdx(obj->objAnim.localPosX, obj->objAnim.localPosY, obj->objAnim.localPosZ));
    {
        TexScrollPlacement* placement = (TexScrollPlacement*)obj->objAnim.placementData;
        int mapId = placement->mapId;
        if (mapId == TEXSCROLL_GAMEBIT_GATED_MAP_A || mapId == TEXSCROLL_GAMEBIT_GATED_MAP_B)
        {
            if (block != NULL)
            {
                if (GameBit_Get(state->gameBit) != *(uint*)&state->previousGameBitValue && state->needsApply == 0)
                {
                    texscroll2_applyMapTextureScroll((int)obj, state);
                    state->needsApply = 0;
                }
            }
        }
    }
    state->previousGameBitValue = GameBit_Get(state->gameBit);
    if (block == NULL)
    {
        state->needsApply = 1;
    }
    else
    {
        if (state->needsApply != 0)
        {
            texscroll2_applyMapTextureScroll((int)obj, state);
            state->needsApply = 0;
        }
    }
}

void texscroll_free(void);

int texscroll2_getExtraSize(void) { return 0x18; }
int texscroll2_getObjectTypeId(void) { return 0x0; }
int texscroll_getExtraSize(void);

void texscroll2_init(TexScroll2Object* obj, TexScrollPlacement* placement, int loadFlags)
{
    TexScroll2State* state = obj->state;
    *(u8*)&state->stepX = placement->stepX;
    *(u8*)&state->stepY = placement->stepY;
    *(u8*)&state->secondaryStepX = placement->secondaryStepX;
    *(u8*)&state->secondaryStepY = placement->secondaryStepY;
    if (loadFlags == 0)
    {
        texscroll2_applyMapTextureScroll((int)obj, state);
    }
    state->gameBit = placement->gameBit;
    state->previousGameBitValue = -1;
}


void texscroll2_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F30);
}

void texscroll_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
