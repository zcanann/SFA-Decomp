/*
 * texscroll2 (DLL 0x134) - per-placement animated UV scroll for a map
 * texture. The placed object resolves the map block under its world
 * position, finds every material layer whose texture matches the one
 * named by its placement (texture table TEXSCROLL_TABLE_ID), and either
 * acquires a hardware scroll slot for it or feeds the current
 * step/secondary-step rates into the existing slot via
 * mapTextureScroll*.
 *
 * On the two gated maps (TEXSCROLL_GAMEBIT_GATED_MAP_A/B) the scroll is
 * conditioned on a placement game bit (state->gameBit): the rates are
 * (re)applied whenever the bit's value changes. Off those maps the
 * scroll is applied unconditionally whenever a re-apply is pending
 * (needsApply), e.g. after the block streams back in.
 */
#include "main/gamebits.h"
#include "main/map_block.h"
#include "main/dll/mmp_moonrock.h"
#include "main/dll/VF/vf_shared.h"
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void* mapGetBlock(int i);
extern void* getTablesBinEntry(int i);
extern void* getLoadedTexture(int key);
extern void* fn_8006070C(int* obj, int idx);
extern void mapTextureScrollSetStep(int slot, int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                                    int secondaryXStep, int secondaryYStep, int texWidthFixed2, int texHeightFixed2);
extern int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed, int secondaryXStep,
                                   int secondaryYStep, int texWidthFixed2, int texHeightFixed2);
extern f32 lbl_803E3F30;

void texscroll2_setScale(TexScroll2Object* obj, s8 stepY)
{
    TexScroll2State* state = obj->state;

    if (state->stepY == stepY)
    {
        return;
    }
    state->stepY = stepY;
    state->needsApply = 1;
}

void texscroll2_applyMapTextureScroll(TexScroll2Object* obj, TexScroll2State* state)
{
    void* material;
    void* layer;
    int* tables;
    void* tex;
    int matIdx;
    int texWidthFixed, texHeightFixed;
    void* block;
    int layerIdx;
    s16* placement;

    placement = obj->objAnim.placementData;
    block = mapGetBlock(objPosToMapBlockIdx(
        obj->objAnim.localPosX,
        obj->objAnim.localPosY,
        obj->objAnim.localPosZ));
    if (block == NULL)
    {
        state->needsApply = 1;
        return;
    }
    tables = getTablesBinEntry(TEXSCROLL_TABLE_ID);
    if (tables == NULL) return;
    tex = getLoadedTexture(-tables[(s32) * (s16*)((char*)placement + 0x18)]);
    if (tex == NULL) return;

    /* layer/material/texture inner types are opaque (no struct defined for
       them, as in tex_dolphin.c's shader walk): layer+0x41 = material count,
       material+0x24 = texture ptr, material+0x2a = scroll slot (0xFF=free),
       tex+0xA/+0xC = u16 width/height. */
    for (layerIdx = 0; layerIdx < (s32)((MapBlockData*)block)->layerCount; layerIdx++)
    {
        layer = fn_8006070C(block, layerIdx);
        for (matIdx = 0, material = layer; matIdx < (s32) * (u8*)((char*)layer + 0x41); matIdx++)
        {
            if (*(void**)((char*)material + 0x24) == tex)
            {
                texWidthFixed = (s32)(u32) * (u16*)((char*)tex + 0xa) << 6;
                texHeightFixed = (s32)(u32) * (u16*)((char*)tex + 0xc) << 6;
                if (*(u8*)((char*)material + 0x2a) != TEXSCROLL_SLOT_UNALLOCATED)
                {
                    int mapId = ((TexScrollPlacement*)obj->objAnim.placementData)->mapId;
                    if (mapId == TEXSCROLL_GAMEBIT_GATED_MAP_A || mapId == TEXSCROLL_GAMEBIT_GATED_MAP_B)
                    {
                        if (GameBit_Get(state->gameBit) != 0)
                        {
                            mapTextureScrollSetStep(
                                (s32) * (u8*)((char*)material + 0x2a),
                                state->stepX,
                                state->stepY,
                                texWidthFixed, texHeightFixed,
                                state->secondaryStepX,
                                state->secondaryStepY,
                                texWidthFixed, texHeightFixed);
                        }
                    }
                    else
                    {
                        mapTextureScrollSetStep(
                            (s32) * (u8*)((char*)material + 0x2a),
                            state->stepX,
                            state->stepY,
                            texWidthFixed, texHeightFixed,
                            state->secondaryStepX,
                            state->secondaryStepY,
                            texWidthFixed, texHeightFixed);
                    }
                }
                else
                {
                    *(u8*)((char*)material + 0x2a) = mapTextureScrollAcquire(
                        state->stepX,
                        state->stepY,
                        texWidthFixed, texHeightFixed,
                        state->secondaryStepX,
                        state->secondaryStepY,
                        texWidthFixed, texHeightFixed);
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
    void* block;
    TexScrollPlacement* placement;
    int mapId;

    state = obj->state;
    block = mapGetBlock(objPosToMapBlockIdx(obj->objAnim.localPosX, obj->objAnim.localPosY, obj->objAnim.localPosZ));
    placement = (TexScrollPlacement*)obj->objAnim.placementData;
    mapId = placement->mapId;
    if (mapId == TEXSCROLL_GAMEBIT_GATED_MAP_A || mapId == TEXSCROLL_GAMEBIT_GATED_MAP_B)
    {
        if (block != NULL)
        {
            if (GameBit_Get(state->gameBit) != *(u32*)&state->previousGameBitValue && state->needsApply == 0)
            {
                texscroll2_applyMapTextureScroll(obj, state);
                state->needsApply = 0;
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
            texscroll2_applyMapTextureScroll(obj, state);
            state->needsApply = 0;
        }
    }
}

int texscroll2_getExtraSize(void) { return TEXSCROLL2_EXTRA_STATE_BYTES; }
int texscroll2_getObjectTypeId(void) { return 0x0; }

void texscroll2_init(TexScroll2Object* obj, TexScrollPlacement* placement, int loadFlags)
{
    TexScroll2State* state = obj->state;
    state->stepX = placement->stepX;
    state->stepY = placement->stepY;
    state->secondaryStepX = placement->secondaryStepX;
    state->secondaryStepY = placement->secondaryStepY;
    if (loadFlags == 0)
    {
        texscroll2_applyMapTextureScroll(obj, state);
    }
    state->gameBit = placement->gameBit;
    state->previousGameBitValue = -1;
}

void texscroll2_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E3F30);
}
