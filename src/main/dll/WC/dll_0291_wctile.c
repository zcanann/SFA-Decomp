/*
 * wctile (DLL 0x291) - one cell of a sliding-tile grid puzzle in the
 * Walled City (WC). On its first update it has no controller, so it
 * locates the nearest level-controller object (ObjGroup group
 * WCTILE_CONTROLLER_GROUP) and caches it in state->controller; all grid
 * queries then route through the controller's WCLevelContInterface (the
 * vtable shared with wcpushblock / wcbouncycra). setup->modelIndex picks
 * the model bank and the A/B tile family (bankIndex == WCTILE_VARIANT_A
 * uses the "A" accessors, else "B"). The tile spins continuously and runs
 * a small alpha state machine (state->mode): INIT_MOVE snaps to its
 * initialTile cell and fades in; SOLID drops to INACTIVE when its target
 * tile stops matching; the A/B hide/fade game bits force HIDDEN/FADE_OUT;
 * FADE_OUT -> FADE_IN re-snaps the position. Bit meanings inferred.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

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


typedef struct WCTileState
{
    int controller;
    s16 tileX;
    s16 tileY;
    s16 targetTile;
    s16 mode;
} WCTileState;

typedef struct WCTileSetup
{
    ObjPlacement base;
    u8 unk18;
    s8 modelIndex;
    s16 initialTile;
    u8 pad1C[0x24 - 0x1C];
} WCTileSetup;

STATIC_ASSERT(sizeof(WCTileState) == WCTILE_EXTRA_SIZE);
STATIC_ASSERT(offsetof(WCTileState, controller) == WCTILE_STATE_CONTROLLER);
STATIC_ASSERT(offsetof(WCTileState, tileX) == WCTILE_STATE_TILE_X);
STATIC_ASSERT(offsetof(WCTileState, tileY) == WCTILE_STATE_TILE_Y);
STATIC_ASSERT(offsetof(WCTileState, targetTile) == WCTILE_STATE_TARGET_TILE);
STATIC_ASSERT(offsetof(WCTileState, mode) == WCTILE_STATE_MODE);
STATIC_ASSERT(sizeof(WCTileSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTileSetup, base.posY) == 0x0c);
STATIC_ASSERT(offsetof(WCTileSetup, modelIndex) == WCTILE_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCTileSetup, initialTile) == WCTILE_INITIAL_TILE_OFFSET);

#define WCTILE_STATE_IFACE(state) (*(WCLevelContInterface **)(*(int *)((state)->controller + 0x68)))

int wctile_getExtraSize(void) { return WCTILE_EXTRA_SIZE; }

int wctile_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)(*(int*)&((GameObject*)obj)->anim.placementData + WCTILE_MODEL_INDEX_OFFSET);
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCTILE_RENDER_TYPE_SHIFT) | WCTILE_RENDER_TYPE_BASE;
}

void wctile_free(void)
{
}

void wctile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6DF0);
    }
}

void wctile_hitDetect(void)
{
}

void wctile_init(u8* obj, u8* setupBytes)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCTileState* state = ((GameObject*)obj)->extra;
    WCTileSetup* setup = (WCTileSetup*)setupBytes;

    ((GameObject*)obj)->anim.localPosY = lbl_803E6DFC + setup->base.posY;
    objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    state->targetTile = setup->initialTile;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel((int)obj), postRenderSetAlphaBlendState);
    objAnim->alpha = 0;
}

void wctile_release(void)
{
}

void wctile_initialise(void)
{
}

#pragma opt_common_subs off
void wctile_update(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    f32 nearest = lbl_803E6DF4;
    WCTileState* state = ((GameObject*)obj)->extra;

    if ((void*)state->controller == NULL)
    {
        state->controller = ObjGroup_FindNearestObject(WCTILE_CONTROLLER_GROUP, obj, &nearest);
        objAnim->alpha = 0;
        return;
    }
    ((GameObject*)obj)->anim.rotX += (s16)(lbl_803E6DF8 * timeDelta);
    if (state->mode != WCTILE_MODE_HIDDEN)
    {
        if (objAnim->bankIndex == WCTILE_VARIANT_A)
        {
            if ((u32)GameBit_Get(WCTILE_GAMEBIT_A_HIDE) != 0)
                state->mode = WCTILE_MODE_HIDDEN;
            else if ((u32)GameBit_Get(WCTILE_GAMEBIT_A_FADE) != 0)
                state->mode = WCTILE_MODE_FADE_OUT;
        }
        else
        {
            if ((u32)GameBit_Get(WCTILE_GAMEBIT_B_HIDE) != 0)
                state->mode = WCTILE_MODE_HIDDEN;
            else if ((u32)GameBit_Get(WCTILE_GAMEBIT_B_FADE) != 0)
                state->mode = WCTILE_MODE_FADE_OUT;
        }
    }
    switch (state->mode)
    {
    case WCTILE_MODE_INIT_MOVE:
        if (objAnim->bankIndex == WCTILE_VARIANT_A)
        {
            WCTILE_STATE_IFACE(state)->getInitialTileXYA(state->targetTile, &state->tileX,
                                                         &state->tileY, WCTILE_STATE_IFACE(state));
            WCTILE_STATE_IFACE(state)->tileAToWorldPos(obj, state->tileX, state->tileY,
                                                       &((GameObject*)obj)->anim.localPosX,
                                                       &((GameObject*)obj)->anim.localPosZ,
                                                       WCTILE_STATE_IFACE(state));
        }
        else
        {
            WCTILE_STATE_IFACE(state)->getInitialTileXYB(state->targetTile, &state->tileX,
                                                         &state->tileY, WCTILE_STATE_IFACE(state));
            WCTILE_STATE_IFACE(state)->tileBToWorldPos(obj, state->tileX, state->tileY,
                                                       &((GameObject*)obj)->anim.localPosX,
                                                       &((GameObject*)obj)->anim.localPosZ,
                                                       WCTILE_STATE_IFACE(state));
        }
        objAnim->alpha = WCTILE_ALPHA_OPAQUE;
        state->mode = WCTILE_MODE_SOLID;
        break;
    case WCTILE_MODE_INACTIVE:
        objAnim->alpha = 0;
        break;
    case WCTILE_MODE_HIDDEN:
        objAnim->alpha = 0;
        break;
    case WCTILE_MODE_FADE_OUT:
        {
            int v = objAnim->alpha - (framesThisStep << WCTILE_ALPHA_STEP_SHIFT);
            if (v < 0)
                v = 0;
            objAnim->alpha = v;
        }
        if (objAnim->alpha == 0)
        {
            if (objAnim->bankIndex == WCTILE_VARIANT_A)
            {
                WCTILE_STATE_IFACE(state)->getInitialTileXYA(state->targetTile, &state->tileX,
                                                             &state->tileY, WCTILE_STATE_IFACE(state));
                WCTILE_STATE_IFACE(state)->tileAToWorldPos(obj, state->tileX, state->tileY,
                                                           &((GameObject*)obj)->anim.localPosX,
                                                           &((GameObject*)obj)->anim.localPosZ,
                                                           WCTILE_STATE_IFACE(state));
                state->mode = WCTILE_MODE_FADE_IN;
            }
            else
            {
                WCTILE_STATE_IFACE(state)->getInitialTileXYB(state->targetTile, &state->tileX,
                                                             &state->tileY, WCTILE_STATE_IFACE(state));
                WCTILE_STATE_IFACE(state)->tileBToWorldPos(obj, state->tileX, state->tileY,
                                                           &((GameObject*)obj)->anim.localPosX,
                                                           &((GameObject*)obj)->anim.localPosZ,
                                                           WCTILE_STATE_IFACE(state));
                state->mode = WCTILE_MODE_FADE_IN;
            }
        }
        break;
    case WCTILE_MODE_FADE_IN:
        {
            int v = objAnim->alpha + (framesThisStep << WCTILE_ALPHA_STEP_SHIFT);
            if (v > WCTILE_ALPHA_OPAQUE)
                v = WCTILE_ALPHA_OPAQUE;
            objAnim->alpha = v;
        }
        if (objAnim->alpha >= WCTILE_ALPHA_OPAQUE)
            state->mode = WCTILE_MODE_SOLID;
        break;
    case WCTILE_MODE_SOLID:
    default:
        {
            int v = objAnim->alpha + (framesThisStep << WCTILE_ALPHA_STEP_SHIFT);
            if (v > WCTILE_ALPHA_OPAQUE)
                v = WCTILE_ALPHA_OPAQUE;
            objAnim->alpha = v;
        }
        if (objAnim->bankIndex == WCTILE_VARIANT_A)
        {
            if (state->targetTile !=
                (u8)WCTILE_STATE_IFACE(state)->getTileA(state->tileX, state->tileY,
                                                        WCTILE_STATE_IFACE(state)))
                state->mode = WCTILE_MODE_INACTIVE;
        }
        else
        {
            if (state->targetTile !=
                (u8)WCTILE_STATE_IFACE(state)->getTileB(state->tileX, state->tileY,
                                                        WCTILE_STATE_IFACE(state)))
                state->mode = WCTILE_MODE_INACTIVE;
        }
        break;
    }
}
#pragma reset
