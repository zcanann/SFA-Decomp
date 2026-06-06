#include "main/dll/dll_80220608_shared.h"

typedef struct WCTileIface WCTileIface;
struct WCTileIface {
    int pad00[8];                                                              /* 0x00 */
    void (*moveToTileA)(int obj, int x, int y, int px, int pz, WCTileIface *); /* 0x20 */
    int pad24[2];                                                              /* 0x24 */
    int (*getTileIndexA)(int x, int y, WCTileIface *);                         /* 0x2c */
    void (*getTileXYA)(int idx, void *xOut, void *yOut, WCTileIface *);        /* 0x30 */
    int pad34[2];                                                              /* 0x34 */
    void (*moveToTileB)(int obj, int x, int y, int px, int pz, WCTileIface *); /* 0x3c */
    int pad40[2];                                                              /* 0x40 */
    int (*getTileIndexB)(int x, int y, WCTileIface *);                         /* 0x48 */
    void (*getTileXYB)(int idx, void *xOut, void *yOut, WCTileIface *);        /* 0x4c */
};

#define WCTILE_EXTRA_SIZE 0xc
#define WCTILE_RENDER_TYPE_BASE 0x400
#define WCTILE_RENDER_TYPE_SHIFT 0xb
#define WCTILE_CONTROLLER_GROUP 9
#define WCTILE_MODEL_INDEX_OFFSET 0x19
#define WCTILE_INITIAL_TILE_OFFSET 0x1a

#define WCTILE_STATE_CONTROLLER 0x00
#define WCTILE_STATE_TILE_X 0x04
#define WCTILE_STATE_TILE_Y 0x06
#define WCTILE_STATE_TARGET_TILE 0x08
#define WCTILE_STATE_MODE 0x0a

#define WCTILE_MODE_INIT_MOVE 0
#define WCTILE_MODE_SOLID 1
#define WCTILE_MODE_INACTIVE 2
#define WCTILE_MODE_FADE_OUT 3
#define WCTILE_MODE_FADE_IN 4
#define WCTILE_MODE_HIDDEN 5

#define WCTILE_VARIANT_A 1
#define WCTILE_ALPHA_STEP_SHIFT 3
#define WCTILE_ALPHA_OPAQUE 0xff

#define WCTILE_GAMEBIT_A_HIDE 0x812
#define WCTILE_GAMEBIT_A_FADE 0x808
#define WCTILE_GAMEBIT_B_HIDE 0x813
#define WCTILE_GAMEBIT_B_FADE 0x809

#define WCTILE_IFACE(state) (*(WCTileIface **)(*(int *)(WCTILE_CONTROLLER(state) + 0x68)))
#define WCTILE_CONTROLLER(state) (*(int *)((u8 *)(state) + WCTILE_STATE_CONTROLLER))
#define WCTILE_TILE_X(state) (*(s16 *)((u8 *)(state) + WCTILE_STATE_TILE_X))
#define WCTILE_TILE_Y(state) (*(s16 *)((u8 *)(state) + WCTILE_STATE_TILE_Y))
#define WCTILE_TARGET_TILE(state) (*(s16 *)((u8 *)(state) + WCTILE_STATE_TARGET_TILE))
#define WCTILE_MODE(state) (*(s16 *)((u8 *)(state) + WCTILE_STATE_MODE))

typedef struct WCTileState {
    int controller;
    s16 tileX;
    s16 tileY;
    s16 targetTile;
    s16 mode;
} WCTileState;

typedef struct WCTileSetup {
    u8 pad00[0x0C];
    f32 yOffset;
    u8 pad10[WCTILE_MODEL_INDEX_OFFSET - 0x10];
    s8 modelIndex;
    s16 initialTile;
} WCTileSetup;

STATIC_ASSERT(sizeof(WCTileState) == WCTILE_EXTRA_SIZE);
STATIC_ASSERT(offsetof(WCTileState, controller) == WCTILE_STATE_CONTROLLER);
STATIC_ASSERT(offsetof(WCTileState, tileX) == WCTILE_STATE_TILE_X);
STATIC_ASSERT(offsetof(WCTileState, tileY) == WCTILE_STATE_TILE_Y);
STATIC_ASSERT(offsetof(WCTileState, targetTile) == WCTILE_STATE_TARGET_TILE);
STATIC_ASSERT(offsetof(WCTileState, mode) == WCTILE_STATE_MODE);
STATIC_ASSERT(offsetof(WCTileSetup, yOffset) == 0x0c);
STATIC_ASSERT(offsetof(WCTileSetup, modelIndex) == WCTILE_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCTileSetup, initialTile) == WCTILE_INITIAL_TILE_OFFSET);

#define WCTILE_STATE_IFACE(state) (*(WCTileIface **)(*(int *)((state)->controller + 0x68)))

#pragma peephole on
#pragma scheduling on
int wctile_getExtraSize(void) { return WCTILE_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wctile_getObjectTypeId(int obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + WCTILE_MODEL_INDEX_OFFSET);
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCTILE_RENDER_TYPE_SHIFT) | WCTILE_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DF0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctile_init(u8 *obj, u8 *setupBytes)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    WCTileState *state = *(WCTileState **)(obj + 0xb8);
    WCTileSetup *setup = (WCTileSetup *)setupBytes;

    *(f32 *)(obj + 0x10) = lbl_803E6DFC + setup->yOffset;
    objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    state->targetTile = setup->initialTile;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel((int)obj), postRenderSetAlphaBlendState);
    obj[0x36] = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctile_update(int obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    f32 nearest = lbl_803E6DF4;
    WCTileState *state = *(WCTileState **)(obj + 0xb8);

    if ((void *)state->controller == NULL) {
        state->controller = ObjGroup_FindNearestObject(WCTILE_CONTROLLER_GROUP, obj, &nearest);
        *(u8 *)(obj + 0x36) = 0;
        return;
    }
    *(s16 *)(obj + 0) += (s16)(lbl_803E6DF8 * timeDelta);
    if (state->mode != WCTILE_MODE_HIDDEN) {
        if (objAnim->bankIndex == WCTILE_VARIANT_A) {
            if ((u32)GameBit_Get(WCTILE_GAMEBIT_A_HIDE) != 0)
                state->mode = WCTILE_MODE_HIDDEN;
            else if ((u32)GameBit_Get(WCTILE_GAMEBIT_A_FADE) != 0)
                state->mode = WCTILE_MODE_FADE_OUT;
        } else {
            if ((u32)GameBit_Get(WCTILE_GAMEBIT_B_HIDE) != 0)
                state->mode = WCTILE_MODE_HIDDEN;
            else if ((u32)GameBit_Get(WCTILE_GAMEBIT_B_FADE) != 0)
                state->mode = WCTILE_MODE_FADE_OUT;
        }
    }
    switch (state->mode) {
    case WCTILE_MODE_INIT_MOVE:
        if (objAnim->bankIndex == WCTILE_VARIANT_A) {
            WCTILE_STATE_IFACE(state)->getTileXYA(state->targetTile, &state->tileX,
                                                  &state->tileY, WCTILE_STATE_IFACE(state));
            WCTILE_STATE_IFACE(state)->moveToTileA(obj, state->tileX, state->tileY, obj + 0xc,
                                                   obj + 0x14, WCTILE_STATE_IFACE(state));
        } else {
            WCTILE_STATE_IFACE(state)->getTileXYB(state->targetTile, &state->tileX,
                                                  &state->tileY, WCTILE_STATE_IFACE(state));
            WCTILE_STATE_IFACE(state)->moveToTileB(obj, state->tileX, state->tileY, obj + 0xc,
                                                   obj + 0x14, WCTILE_STATE_IFACE(state));
        }
        *(u8 *)(obj + 0x36) = WCTILE_ALPHA_OPAQUE;
        state->mode = WCTILE_MODE_SOLID;
        break;
    case WCTILE_MODE_INACTIVE:
        *(u8 *)(obj + 0x36) = 0;
        break;
    case WCTILE_MODE_HIDDEN:
        *(u8 *)(obj + 0x36) = 0;
        break;
    case WCTILE_MODE_FADE_OUT:
        {
            int v = *(u8 *)(obj + 0x36) - (framesThisStep << WCTILE_ALPHA_STEP_SHIFT);
            if (v < 0)
                v = 0;
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            if (objAnim->bankIndex == WCTILE_VARIANT_A) {
                WCTILE_STATE_IFACE(state)->getTileXYA(state->targetTile, &state->tileX,
                                                      &state->tileY, WCTILE_STATE_IFACE(state));
                WCTILE_STATE_IFACE(state)->moveToTileA(obj, state->tileX, state->tileY, obj + 0xc,
                                                       obj + 0x14, WCTILE_STATE_IFACE(state));
                state->mode = WCTILE_MODE_FADE_IN;
            } else {
                WCTILE_STATE_IFACE(state)->getTileXYB(state->targetTile, &state->tileX,
                                                      &state->tileY, WCTILE_STATE_IFACE(state));
                WCTILE_STATE_IFACE(state)->moveToTileB(obj, state->tileX, state->tileY, obj + 0xc,
                                                       obj + 0x14, WCTILE_STATE_IFACE(state));
                state->mode = WCTILE_MODE_FADE_IN;
            }
        }
        break;
    case WCTILE_MODE_FADE_IN:
        {
            int v = *(u8 *)(obj + 0x36) + (framesThisStep << WCTILE_ALPHA_STEP_SHIFT);
            if (v > WCTILE_ALPHA_OPAQUE)
                v = WCTILE_ALPHA_OPAQUE;
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(u8 *)(obj + 0x36) >= WCTILE_ALPHA_OPAQUE)
            state->mode = WCTILE_MODE_SOLID;
        break;
    case WCTILE_MODE_SOLID:
    default:
        {
            int v = *(u8 *)(obj + 0x36) + (framesThisStep << WCTILE_ALPHA_STEP_SHIFT);
            if (v > WCTILE_ALPHA_OPAQUE)
                v = WCTILE_ALPHA_OPAQUE;
            *(u8 *)(obj + 0x36) = v;
        }
        if (objAnim->bankIndex == WCTILE_VARIANT_A) {
            if (state->targetTile !=
                (u8)WCTILE_STATE_IFACE(state)->getTileIndexA(state->tileX, state->tileY,
                                                             WCTILE_STATE_IFACE(state)))
                state->mode = WCTILE_MODE_INACTIVE;
        } else {
            if (state->targetTile !=
                (u8)WCTILE_STATE_IFACE(state)->getTileIndexB(state->tileX, state->tileY,
                                                             WCTILE_STATE_IFACE(state)))
                state->mode = WCTILE_MODE_INACTIVE;
        }
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
