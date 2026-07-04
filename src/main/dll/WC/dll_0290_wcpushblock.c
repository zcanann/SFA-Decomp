/*
 * wcpushblock (DLL 0x290) - the sliding push-block puzzle object in the
 * Walled City (WC). Two block variants (anim.bankIndex: VARIANT_A vs B)
 * ride a shared tile grid owned by a separate level-controller object,
 * found via ObjGroup_FindNearestObject on controller group
 * WCPUSHBLOCK_CONTROLLER_GROUP; the controller's WCLevelContInterface
 * (vtable at controller+0x68) does all tile<->world mapping, move tracing
 * and tile-occupancy writes (A/B method pairs).
 *
 * Per-frame phase machine: INIT_MOVE places the block at its initial tile;
 * IDLE fades in, polls the player push and traces a move; SLIDING eases
 * toward the target tile with a looped sliding sfx and clamps; FADE_OUT/
 * FADE_IN reset to the initial cell when a move is rejected; LOCKED/SOLVED
 * swap to the locked texture. A vertical bob is applied each frame. Per-
 * variant solved/fade/count game bits drive the puzzle; reaching
 * WCPUSHBLOCK_REQUIRED_LOCK_COUNT latches the solved bit.
 *
 * wcpushblock_updateLevelControlState / fn_802251B4 are the WC level
 * controller's own mode machine (timers, save points, map gating, music),
 * co-located in this TU. Offsets/bit values inferred from code.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"

#define WCPUSHBLOCK_EXTRA_SIZE 0x288
#define WCPUSHBLOCK_RENDER_TYPE_BASE 0x400
#define WCPUSHBLOCK_RENDER_TYPE_SHIFT 0xb
#define WCPUSHBLOCK_CONTROLLER_GROUP 9
#define WCPUSHBLOCK_MODEL_INDEX_OFFSET 0x19
#define WCPUSHBLOCK_INITIAL_TILE_OFFSET 0x1a

#define WCPUSHBLOCK_STATE_TARGET_X 0x26c
#define WCPUSHBLOCK_STATE_TARGET_Z 0x270
#define WCPUSHBLOCK_STATE_BASE_Y 0x274
#define WCPUSHBLOCK_STATE_BOB_Y 0x278
#define WCPUSHBLOCK_STATE_BOB_ANGLE 0x27c
#define WCPUSHBLOCK_STATE_TILE_X 0x27e
#define WCPUSHBLOCK_STATE_TILE_Y 0x280
#define WCPUSHBLOCK_STATE_PUSH_DIR 0x282
#define WCPUSHBLOCK_STATE_INITIAL_TILE 0x283
#define WCPUSHBLOCK_STATE_MOVE_RESULT 0x284
#define WCPUSHBLOCK_STATE_FLAGS 0x285
#define WCPUSHBLOCK_STATE_CONTROLLER 0x268

#define WCPUSHBLOCK_PHASE_INIT_MOVE 0
#define WCPUSHBLOCK_PHASE_IDLE 1
#define WCPUSHBLOCK_PHASE_SLIDING 2
#define WCPUSHBLOCK_PHASE_FADE_OUT 3
#define WCPUSHBLOCK_PHASE_LOCKED 4
#define WCPUSHBLOCK_PHASE_FADE_IN 5
#define WCPUSHBLOCK_PHASE_SOLVED 6

#define WCPUSHBLOCK_VARIANT_A 1
#define WCPUSHBLOCK_ALPHA_STEP_SHIFT 3
#define WCPUSHBLOCK_ALPHA_OPAQUE 0xff
#define WCPUSHBLOCK_TEXTURE_DEFAULT 0
#define WCPUSHBLOCK_TEXTURE_LOCKED 0x100
#define WCPUSHBLOCK_OBJFLAG_LOCKED 0x100
#define WCPUSHBLOCK_BOX_BURST_VARIANT_A 3
#define WCPUSHBLOCK_BOX_BURST_VARIANT_B 1

#define WCPUSHBLOCK_DIR_POS_X 0
#define WCPUSHBLOCK_DIR_NEG_X 1
#define WCPUSHBLOCK_DIR_POS_Z 2
#define WCPUSHBLOCK_DIR_NEG_Z 3
#define WCPUSHBLOCK_MOVE_RESULT_CONTINUE 1
#define WCPUSHBLOCK_MOVE_RESULT_LOCKED 2

#define WCPUSHBLOCK_GAMEBIT_A_SOLVED 0x812
#define WCPUSHBLOCK_GAMEBIT_A_FADE 0x808
#define WCPUSHBLOCK_GAMEBIT_A_COUNT 0x810
#define WCPUSHBLOCK_GAMEBIT_B_SOLVED 0x813
#define WCPUSHBLOCK_GAMEBIT_B_FADE 0x809
#define WCPUSHBLOCK_GAMEBIT_B_COUNT 0x811
#define WCPUSHBLOCK_REQUIRED_LOCK_COUNT 4U

typedef struct WCPushBlockSetup
{
    ObjPlacement base;
    u8 unk18;
    u8 modelIndex;
    s16 initialTile;
    u8 pad1C[0x24 - 0x1C];
} WCPushBlockSetup;

typedef struct WCPushBlockRuntimeState
{
    u8 pad00[WCPUSHBLOCK_STATE_CONTROLLER];
    int controller;
    f32 targetX;
    f32 targetZ;
    f32 baseY;
    f32 bobY;
    u16 bobAngle;
    s16 tileX;
    s16 tileY;
    u8 pushDir;
    u8 initialTile;
    u8 moveResult;
    PushBlockFlags flags;
    u8 pad286[2];
} WCPushBlockRuntimeState;

STATIC_ASSERT(sizeof(PushBlockFlags) == 1);
STATIC_ASSERT(sizeof(WCPushBlockRuntimeState) == WCPUSHBLOCK_EXTRA_SIZE);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, controller) == WCPUSHBLOCK_STATE_CONTROLLER);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, targetX) == WCPUSHBLOCK_STATE_TARGET_X);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, targetZ) == WCPUSHBLOCK_STATE_TARGET_Z);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, baseY) == WCPUSHBLOCK_STATE_BASE_Y);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, bobY) == WCPUSHBLOCK_STATE_BOB_Y);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, bobAngle) == WCPUSHBLOCK_STATE_BOB_ANGLE);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, tileX) == WCPUSHBLOCK_STATE_TILE_X);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, tileY) == WCPUSHBLOCK_STATE_TILE_Y);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, pushDir) == WCPUSHBLOCK_STATE_PUSH_DIR);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, initialTile) == WCPUSHBLOCK_STATE_INITIAL_TILE);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, moveResult) == WCPUSHBLOCK_STATE_MOVE_RESULT);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, flags) == WCPUSHBLOCK_STATE_FLAGS);
STATIC_ASSERT(sizeof(WCPushBlockSetup) == 0x24);
STATIC_ASSERT(offsetof(WCPushBlockSetup, base.posY) == 0xc);
STATIC_ASSERT(offsetof(WCPushBlockSetup, modelIndex) == WCPUSHBLOCK_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCPushBlockSetup, initialTile) == WCPUSHBLOCK_INITIAL_TILE_OFFSET);

#define WCPUSHBLOCK_CONTROLLER(state) (((WCPushBlockRuntimeState *)(state))->controller)
#define WCPUSHBLOCK_IFACE (*(WCLevelContInterface **)(*(int *)(WCPUSHBLOCK_CONTROLLER(state) + 0x68)))
#define WCPUSHBLOCK_TARGET_X(state) (((WCPushBlockRuntimeState *)(state))->targetX)
#define WCPUSHBLOCK_TARGET_Z(state) (((WCPushBlockRuntimeState *)(state))->targetZ)
#define WCPUSHBLOCK_BASE_Y(state) (((WCPushBlockRuntimeState *)(state))->baseY)
#define WCPUSHBLOCK_BOB_Y(state) (((WCPushBlockRuntimeState *)(state))->bobY)
#define WCPUSHBLOCK_BOB_ANGLE(state) (((WCPushBlockRuntimeState *)(state))->bobAngle)
#define WCPUSHBLOCK_TILE_X(state) (((WCPushBlockRuntimeState *)(state))->tileX)
#define WCPUSHBLOCK_TILE_Y(state) (((WCPushBlockRuntimeState *)(state))->tileY)
#define WCPUSHBLOCK_PUSH_DIR(state) (((WCPushBlockRuntimeState *)(state))->pushDir)
#define WCPUSHBLOCK_INITIAL_TILE(state) (((WCPushBlockRuntimeState *)(state))->initialTile)
#define WCPUSHBLOCK_MOVE_RESULT(state) (((WCPushBlockRuntimeState *)(state))->moveResult)
#define WCPUSHBLOCK_FLAGS(state) (((WCPushBlockRuntimeState *)(state))->flags)

int wcpushblock_getExtraSize(void) { return WCPUSHBLOCK_EXTRA_SIZE; }

int wcpushblock_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)(*(int*)&((GameObject*)obj)->anim.placementData + WCPUSHBLOCK_MODEL_INDEX_OFFSET);
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCPUSHBLOCK_RENDER_TYPE_SHIFT) | WCPUSHBLOCK_RENDER_TYPE_BASE;
}

void wcpushblock_free(void)
{
}

void wcpushblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D54);
    }
}

void wcpushblock_hitDetect(void)
{
}

void wcpushblock_init(int obj, int setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCPushBlockRuntimeState* state = ((GameObject*)obj)->extra;
    WCPushBlockSetup* setupData = (WCPushBlockSetup*)setup;

    objAnim->alpha = 0;
    *(u8*)&objAnim->bankIndex = setupData->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjHitbox_SetStateIndex(obj, *(int*)&((GameObject*)obj)->anim.hitReactState, objAnim->bankIndex);
    state->initialTile = setupData->initialTile;
    state->baseY = lbl_803E6DA0 + setupData->base.posY;
}

void wcpushblock_release(void)
{
}

void wcpushblock_initialise(void)
{
}

#pragma opt_common_subs off
void wcpushblock_update(int obj)
{

    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCPushBlockRuntimeState* state = ((GameObject*)obj)->extra;
    GameObject* player = (GameObject*)Obj_GetPlayerObject();
    f32 range = gWcPushBlockControllerSearchRange;
    f32 dist;
    ObjTextureRuntimeSlot *tex;
    int moved;

    if ((void*)WCPUSHBLOCK_CONTROLLER(state) == 0)
    {
        WCPUSHBLOCK_CONTROLLER(state) = ObjGroup_FindNearestObject(WCPUSHBLOCK_CONTROLLER_GROUP, obj, &range);
        objAnim->alpha = 0;
        return;
    }
    tex = objFindTexture((void *)obj, 0, 0);
    if (tex != 0) {
        tex->textureId = WCPUSHBLOCK_TEXTURE_DEFAULT;
    }
    ((GameObject*)obj)->objectFlags &= ~WCPUSHBLOCK_OBJFLAG_LOCKED;

    if (WCPUSHBLOCK_FLAGS(state).phase != WCPUSHBLOCK_PHASE_SOLVED)
    {
        if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
        {
            if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_A_SOLVED) != 0)
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_SOLVED;
                WCPUSHBLOCK_IFACE->getSolvedTileXYA(WCPUSHBLOCK_INITIAL_TILE(state), &state->tileX, &state->tileY,
                                                    WCPUSHBLOCK_IFACE);
                WCPUSHBLOCK_IFACE->tileAToWorldPos(
                    obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                    &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosZ, WCPUSHBLOCK_IFACE);
            }
            else if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_A_FADE) != 0)
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_FADE_OUT;
            }
        }
        else
        {
            if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_B_SOLVED) != 0)
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_SOLVED;
                WCPUSHBLOCK_IFACE->getSolvedTileXYB(WCPUSHBLOCK_INITIAL_TILE(state), &state->tileX, &state->tileY,
                                                    WCPUSHBLOCK_IFACE);
                WCPUSHBLOCK_IFACE->tileBToWorldPos(
                    obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                    &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosZ, WCPUSHBLOCK_IFACE);
            }
            else if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_B_FADE) != 0)
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_FADE_OUT;
            }
        }
    }

    {
        u32 ph = WCPUSHBLOCK_FLAGS(state).phase;
        if (ph != WCPUSHBLOCK_PHASE_FADE_OUT && ph != WCPUSHBLOCK_PHASE_FADE_IN)
        {
            if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
            {
                ((void (*)(int, int, f32, int, int, int, f32, f32, f32, int, int))objfx_spawnBoxBurst)(
                    obj, 1, lbl_803E6D5C, WCPUSHBLOCK_BOX_BURST_VARIANT_A, 1, 50, lbl_803E6D60,
                    lbl_803E6D5C, lbl_803E6D60, 0, 0);
            }
            else
            {
                ((void (*)(int, int, f32, int, int, int, f32, f32, f32, int, int))objfx_spawnBoxBurst)(
                    obj, 1, lbl_803E6D5C, WCPUSHBLOCK_BOX_BURST_VARIANT_B, 1, 50, lbl_803E6D60,
                    lbl_803E6D5C, lbl_803E6D60, 0, 0);
            }
        }
    }

    switch (WCPUSHBLOCK_FLAGS(state).phase)
    {
    case WCPUSHBLOCK_PHASE_INIT_MOVE:
        if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
        {
            WCPUSHBLOCK_IFACE->getInitialTileXYA(WCPUSHBLOCK_INITIAL_TILE(state), &state->tileX, &state->tileY,
                                                 WCPUSHBLOCK_IFACE);
            WCPUSHBLOCK_IFACE->tileAToWorldPos(
                obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosZ, WCPUSHBLOCK_IFACE);
        }
        else
        {
            WCPUSHBLOCK_IFACE->getInitialTileXYB(WCPUSHBLOCK_INITIAL_TILE(state), &state->tileX, &state->tileY,
                                                 WCPUSHBLOCK_IFACE);
            WCPUSHBLOCK_IFACE->tileBToWorldPos(
                obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosZ, WCPUSHBLOCK_IFACE);
        }
        WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_IDLE;
        break;
    case WCPUSHBLOCK_PHASE_IDLE:
        {
            int a = objAnim->alpha + framesThisStep * 8;
            if (a > WCPUSHBLOCK_ALPHA_OPAQUE)
            {
                a = WCPUSHBLOCK_ALPHA_OPAQUE;
            }
            objAnim->alpha = a;
        }
        {
            f32 zero = lbl_803E6D64;
            ((GameObject*)obj)->anim.velocityX = zero;
            ((GameObject*)obj)->anim.velocityZ = zero;
        }
        if (fn_80296414((int)player, obj, (int)&state->pushDir) != 0)
        {
            if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
            {
                if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_POS_X)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveA(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, -1, 0, WCPUSHBLOCK_IFACE);
                }
                else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_NEG_X)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveA(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, 1, 0, WCPUSHBLOCK_IFACE);
                }
                else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_POS_Z)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveA(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, 0, -1, WCPUSHBLOCK_IFACE);
                }
                else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_NEG_Z)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveA(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, 0, 1, WCPUSHBLOCK_IFACE);
                }
            }
            else
            {
                if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_POS_X)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveB(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, -1, 0, WCPUSHBLOCK_IFACE);
                }
                else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_NEG_X)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveB(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, 1, 0, WCPUSHBLOCK_IFACE);
                }
                else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_POS_Z)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveB(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, 0, -1, WCPUSHBLOCK_IFACE);
                }
                else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_NEG_Z)
                {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        WCPUSHBLOCK_IFACE->traceMoveB(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            &state->targetX, &state->targetZ, 0, 1, WCPUSHBLOCK_IFACE);
                }
            }
            if (WCPUSHBLOCK_TARGET_X(state) == ((GameObject*)obj)->anim.localPosX &&
                WCPUSHBLOCK_TARGET_Z(state) == ((GameObject*)obj)->anim.localPosY)
            {
                ;
            }
            else
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_SLIDING;
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_SLIDING:
        {
        f32 zero = lbl_803E6D64;
        f32 vx = ((GameObject*)obj)->anim.velocityX;
        if (zero != vx || zero != ((GameObject*)obj)->anim.velocityZ)
        {
            f32 speed = sqrtf(vx * vx +
                    ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ) -
                lbl_803E6D68;
            if (speed < lbl_803E6D64)
            {
                speed = lbl_803E6D64;
            }
            dist = lbl_803E6D54 + lbl_803E6D6C * speed / lbl_803E6D70;
            if (dist > gWcPushBlockSlideSfxMaxVolume)
            {
                dist = gWcPushBlockSlideSfxMaxVolume;
            }
            Sfx_KeepAliveLoopedObjectSound(obj, SFXsc_lockon2_off);
            Sfx_SetObjectSfxVolume(obj, SFXsc_lockon2_off, dist, lbl_803E6D78);
            WCPUSHBLOCK_FLAGS(state).sfxActive = 1;
        }
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, lbl_803E6D64,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        moved = 0;
        {
            if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_POS_X)
            {
                if (((GameObject*)obj)->anim.velocityX < gWcPushBlockMaxSlideSpeed)
                {
                    ((GameObject*)obj)->anim.velocityX = gWcPushBlockSlideAccel * timeDelta + ((GameObject*)obj)->anim.velocityX;
                }
                {
                    f32 tx;
                    if (((GameObject*)obj)->anim.localPosX >= (tx = WCPUSHBLOCK_TARGET_X(state)))
                    {
                        ((GameObject*)obj)->anim.localPosX = tx;
                        moved = 1;
                    }
                }
            }
            else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_NEG_X)
            {
                if (((GameObject*)obj)->anim.velocityX > gWcPushBlockMinSlideSpeed)
                {
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - gWcPushBlockSlideAccel * timeDelta;
                }
                {
                    f32 tx;
                    if (((GameObject*)obj)->anim.localPosX <= (tx = WCPUSHBLOCK_TARGET_X(state)))
                    {
                        ((GameObject*)obj)->anim.localPosX = tx;
                        moved = 1;
                    }
                }
            }
            else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_POS_Z)
            {
                if (((GameObject*)obj)->anim.velocityZ < gWcPushBlockMaxSlideSpeed)
                {
                    ((GameObject*)obj)->anim.velocityZ = gWcPushBlockSlideAccel * timeDelta + ((GameObject*)obj)->anim.velocityZ;
                }
                {
                    f32 tz;
                    if (((GameObject*)obj)->anim.localPosZ >= (tz = WCPUSHBLOCK_TARGET_Z(state)))
                    {
                        ((GameObject*)obj)->anim.localPosZ = tz;
                        moved = 1;
                    }
                }
            }
            else if (WCPUSHBLOCK_PUSH_DIR(state) == WCPUSHBLOCK_DIR_NEG_Z)
            {
                if (((GameObject*)obj)->anim.velocityZ > gWcPushBlockMinSlideSpeed)
                {
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - gWcPushBlockSlideAccel * timeDelta;
                }
                {
                    f32 tz;
                    if (((GameObject*)obj)->anim.localPosZ <= (tz = WCPUSHBLOCK_TARGET_Z(state)))
                    {
                        ((GameObject*)obj)->anim.localPosZ = tz;
                        moved = 1;
                    }
                }
            }
        }
        if (((GameObject*)obj)->anim.velocityX > gWcPushBlockMaxSlideSpeed)
        {
            ((GameObject*)obj)->anim.velocityX = gWcPushBlockMaxSlideSpeed;
        }
        if (((GameObject*)obj)->anim.velocityX < gWcPushBlockMinSlideSpeed)
        {
            ((GameObject*)obj)->anim.velocityX = gWcPushBlockMinSlideSpeed;
        }
        if (((GameObject*)obj)->anim.velocityZ > gWcPushBlockMaxSlideSpeed)
        {
            ((GameObject*)obj)->anim.velocityZ = gWcPushBlockMaxSlideSpeed;
        }
        if (((GameObject*)obj)->anim.velocityZ < gWcPushBlockMinSlideSpeed)
        {
            ((GameObject*)obj)->anim.velocityZ = gWcPushBlockMinSlideSpeed;
        }
        if (moved == 0)
        {
            break;
        }
        {
            f32 zero = lbl_803E6D64;
            ((GameObject*)obj)->anim.velocityX = zero;
            ((GameObject*)obj)->anim.velocityZ = zero;
        }
        {
            u32 r = WCPUSHBLOCK_MOVE_RESULT(state);
            if (r == WCPUSHBLOCK_MOVE_RESULT_LOCKED)
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_LOCKED;
                if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
                {
                    if (gameBitIncrement(WCPUSHBLOCK_GAMEBIT_A_COUNT) != WCPUSHBLOCK_REQUIRED_LOCK_COUNT)
                    {
                        Sfx_PlayFromObject(0, SFXsc_lockon3_off);
                    }
                }
                else
                {
                    if (gameBitIncrement(WCPUSHBLOCK_GAMEBIT_B_COUNT) != WCPUSHBLOCK_REQUIRED_LOCK_COUNT)
                    {
                        Sfx_PlayFromObject(0, SFXsc_lockon3_off);
                    }
                }
            }
            else if (r == WCPUSHBLOCK_MOVE_RESULT_CONTINUE)
            {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_IDLE;
                if (WCPUSHBLOCK_FLAGS(state).sfxActive != 0)
                {
                    WCPUSHBLOCK_FLAGS(state).sfxActive = 0;
                    Sfx_PlayFromObject(obj, SFXsc_lockon3_on);
                }
            }
            else
            {
                if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
                {
                    GameBit_Set(WCPUSHBLOCK_GAMEBIT_A_FADE, 1);
                }
                else
                {
                    GameBit_Set(WCPUSHBLOCK_GAMEBIT_B_FADE, 1);
                }
            }
        }
        if (WCPUSHBLOCK_FLAGS(state).phase != WCPUSHBLOCK_PHASE_FADE_OUT)
        {
            if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
            {
                WCPUSHBLOCK_IFACE->setTileA(0, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                                            WCPUSHBLOCK_IFACE);
                WCPUSHBLOCK_IFACE->worldPosToTileA(obj, ((GameObject*)obj)->anim.localPosX,
                                                   ((GameObject*)obj)->anim.localPosZ,
                                                   &state->tileX, &state->tileY, WCPUSHBLOCK_IFACE);
                WCPUSHBLOCK_IFACE->setTileA(WCPUSHBLOCK_INITIAL_TILE(state), WCPUSHBLOCK_TILE_X(state),
                                            WCPUSHBLOCK_TILE_Y(state), WCPUSHBLOCK_IFACE);
            }
            else
            {
                WCPUSHBLOCK_IFACE->setTileB(0, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                                            WCPUSHBLOCK_IFACE);
                WCPUSHBLOCK_IFACE->worldPosToTileB(obj, ((GameObject*)obj)->anim.localPosX,
                                                   ((GameObject*)obj)->anim.localPosZ,
                                                   &state->tileX, &state->tileY, WCPUSHBLOCK_IFACE);
                WCPUSHBLOCK_IFACE->setTileB(WCPUSHBLOCK_INITIAL_TILE(state), WCPUSHBLOCK_TILE_X(state),
                                            WCPUSHBLOCK_TILE_Y(state), WCPUSHBLOCK_IFACE);
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_FADE_OUT:
        ObjHits_DisableObject(obj);
        if (objAnim->alpha == WCPUSHBLOCK_ALPHA_OPAQUE)
        {
            Sfx_PlayFromObject(obj, SFXsc_lifeforcedoor);
        }
        {
            int a = objAnim->alpha - (framesThisStep << WCPUSHBLOCK_ALPHA_STEP_SHIFT);
            if (a < 0)
            {
                a = 0;
            }
            objAnim->alpha = a;
        }
        if (objAnim->alpha == 0)
        {
            if (wcblock_isPlayerAwayFromStoredCell(obj, (int)state, Obj_GetPlayerObject()) != 0)
            {
                if (objAnim->bankIndex == WCPUSHBLOCK_VARIANT_A)
                {
                    WCPUSHBLOCK_IFACE->getInitialTileXYA(WCPUSHBLOCK_INITIAL_TILE(state), &state->tileX,
                                                         &state->tileY, WCPUSHBLOCK_IFACE);
                    WCPUSHBLOCK_IFACE->tileAToWorldPos(
                        obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                        &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosZ, WCPUSHBLOCK_IFACE);
                }
                else
                {
                    WCPUSHBLOCK_IFACE->getInitialTileXYB(WCPUSHBLOCK_INITIAL_TILE(state), &state->tileX,
                                                         &state->tileY, WCPUSHBLOCK_IFACE);
                    WCPUSHBLOCK_IFACE->tileBToWorldPos(
                        obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                        &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosZ, WCPUSHBLOCK_IFACE);
                }
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_FADE_IN;
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_FADE_IN:
        if (objAnim->alpha == 0)
        {
            ObjHits_EnableObject(obj);
            Sfx_PlayFromObject(0, SFXsc_golfbar_swipe);
        }
        {
            int a = objAnim->alpha + (framesThisStep << WCPUSHBLOCK_ALPHA_STEP_SHIFT);
            if (a > WCPUSHBLOCK_ALPHA_OPAQUE)
            {
                a = WCPUSHBLOCK_ALPHA_OPAQUE;
            }
            objAnim->alpha = a;
        }
        if (objAnim->alpha >= WCPUSHBLOCK_ALPHA_OPAQUE)
        {
            WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_IDLE;
        }
        break;
    case WCPUSHBLOCK_PHASE_SOLVED:
        objAnim->alpha = WCPUSHBLOCK_ALPHA_OPAQUE;
    case WCPUSHBLOCK_PHASE_LOCKED:
        tex = objFindTexture((void *)obj, 0, 0);
        if (tex != 0) {
            tex->textureId = WCPUSHBLOCK_TEXTURE_LOCKED;
        }
        ((GameObject*)obj)->objectFlags |= WCPUSHBLOCK_OBJFLAG_LOCKED;
        break;
    }

    WCPUSHBLOCK_BOB_ANGLE(state) = gWcPushBlockBobAngleSpeed * timeDelta + (f32)(u32)WCPUSHBLOCK_BOB_ANGLE(state);
    WCPUSHBLOCK_BOB_Y(state) =
        gWcPushBlockBobAmplitude * mathSinf(gWcPushBlockPi * (f32)(u32)WCPUSHBLOCK_BOB_ANGLE(state) / gWcPushBlockAngleScale);
    ((GameObject*)obj)->anim.localPosY = WCPUSHBLOCK_BASE_Y(state) + WCPUSHBLOCK_BOB_Y(state);
}
#pragma opt_common_subs reset

void fn_802251B4(int obj, WcLevelControlState* state)
{
    f32 sunTime;

    (*gSkyInterface)->getSunPosition(&sunTime);
    switch (state->mode)
    {
    case WCLEVELCTL_MODE_TREX_INIT:
        gameTimerInit(0x1d, 0x50);
        timerSetToCountUp();
        state->mode = WCLEVELCTL_MODE_TREX_ACTIVE;
        break;
    case WCLEVELCTL_MODE_TREX_ACTIVE:
        if ((u32)GameBit_Get(0x2a5) != 0)
        {
            GameObject* player;
            GameBit_Set(0x274, 1);
            GameBit_Set(0xef1, 0);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->completionFlags |= WCLEVELCTL_FLAG_TREX;
            state->mode = WCLEVELCTL_MODE_IDLE;
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            gameTimerStop();
        }
        else if (isGameTimerDisabled() != 0)
        {
            GameBit_Set(0x274, 0);
            GameBit_Set(0xef1, 0);
            if ((u32)GameBit_Get(0x34d) == 0)
            {
                GameBit_Set(0x2b1, 0);
                GameBit_Set(0x226, 1);
                GameBit_Set(0x2a6, 1);
                GameBit_Set(0x206, 1);
                GameBit_Set(0x25f, 1);
                state->mode = WCLEVELCTL_MODE_IDLE;
            }
        }
        break;
    default:
        if (!(state->completionFlags & WCLEVELCTL_FLAG_TREX) && GameBit_Get(0x2b1) != 0)
        {
            GameBit_Set(0xef1, 1);
            GameBit_Set(0xe6d, 0);
            if ((u32)GameBit_Get(0x204) != 0)
            {
                GameBit_Set(0x226, 0);
                GameBit_Set(0x2a6, 0);
                GameBit_Set(0x206, 0);
                GameBit_Set(0x25f, 0);
                GameBit_Set(0x274, 1);
                state->mode = WCLEVELCTL_MODE_TREX_INIT;
            }
        }
        break;
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_TILE_A))
    {
        if ((u8)GameBit_Get(WCPUSHBLOCK_GAMEBIT_A_COUNT) == 4)
        {
            GameBit_Set(WCPUSHBLOCK_GAMEBIT_A_SOLVED, 1);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            state->completionFlags |= WCLEVELCTL_FLAG_TILE_A;
        }
        else if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_A_FADE) != 0)
        {
            if (state->tileAResetTimer <= lbl_803E6DA8)
            {
                GameBit_Set(WCPUSHBLOCK_GAMEBIT_A_COUNT, 0);
                memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
                state->tileAResetTimer = gWcPushBlockTileResetTime;
            }
        }
        if (state->tileAResetTimer > lbl_803E6DA8)
        {
            state->tileAResetTimer -= timeDelta;
            if (state->tileAResetTimer <= lbl_803E6DA8)
                GameBit_Set(WCPUSHBLOCK_GAMEBIT_A_FADE, 0);
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_TILE_B))
    {
        if ((u8)GameBit_Get(WCPUSHBLOCK_GAMEBIT_B_COUNT) == 4)
        {
            GameBit_Set(WCPUSHBLOCK_GAMEBIT_B_SOLVED, 1);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            state->completionFlags |= WCLEVELCTL_FLAG_TILE_B;
        }
        else if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_B_FADE) != 0)
        {
            if (state->tileBResetTimer <= lbl_803E6DA8)
            {
                GameBit_Set(WCPUSHBLOCK_GAMEBIT_B_COUNT, 0);
                memcpy(lbl_803AD298, lbl_8032B088, 0x40);
                state->tileBResetTimer = gWcPushBlockTileResetTime;
            }
        }
        if (state->tileBResetTimer > lbl_803E6DA8)
        {
            state->tileBResetTimer -= timeDelta;
            if (state->tileBResetTimer <= lbl_803E6DA8)
                GameBit_Set(WCPUSHBLOCK_GAMEBIT_B_FADE, 0);
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_SWITCHES))
    {
        if ((u32)GameBit_Get(0xc58) != 0 && GameBit_Get(0xc59) != 0 &&
            GameBit_Get(0xc5a) != 0)
        {
            GameBit_Set(0x205, 1);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            state->completionFlags |= WCLEVELCTL_FLAG_SWITCHES;
        }
        else if (!state->dialogueFlags.b40 &&
            GameBit_Get(0xc58) != 0)
        {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            state->dialogueFlags.b40 = 1;
        }
        else if (!state->dialogueFlags.b20 &&
            GameBit_Get(0xc59) != 0)
        {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            state->dialogueFlags.b20 = 1;
        }
        else if (!state->dialogueFlags.b18 &&
            GameBit_Get(0xc5a) != 0)
        {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            state->dialogueFlags.b18 = 1;
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_FINAL))
    {
        if ((u32)GameBit_Get(0xbcf) != 0)
        {
            GameObject* player;
            GameBit_Set(0xbc8, 0);
            GameBit_Set(0x2f0, 1);
            GameBit_Set(0xeec, 0);
            GameBit_Set(0xbd0, 0);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            state->completionFlags |= WCLEVELCTL_FLAG_FINAL;
        }
    }

    state->completionFlags &= ~WCLEVELCTL_FLAG_TRIGGERED;
    if ((u32)GameBit_Get(0xc92) != 0)
    {
        GameBit_Set(0x4e4, 0);
        GameBit_Set(0x4e5, 0);
        if ((u32)GameBit_Get(0x4e3) == 0xff)
            GameBit_Set(0x4e3, randomGetRange(6, 7));
    }
}

void wcpushblock_updateLevelControlState(int obj, WcLevelControlState* state)
{
    if (state->completionFlags & WCLEVELCTL_FLAG_EVENT_ACTIVE)
        return;
    state->previousMode = state->mode;
    switch (state->mode)
    {
    case WCLEVELCTL_MODE_PUZZLE_A:
        if (state->completionFlags & WCLEVELCTL_FLAG_TRIGGERED)
        {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedd, 1);
        }
        else if ((u32)GameBit_Get(0x7f9) != 0)
        {
            state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_A;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7fa) != 0)
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            else
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            if ((u32)GameBit_Get(0x7fa) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                state->mode = WCLEVELCTL_MODE_SEQUENCE;
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                state->mode = WCLEVELCTL_MODE_IDLE;
            }
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        else if (isGameTimerDisabled() != 0)
        {
            GameBit_Set(0x7ef, 0);
            GameBit_Set(0x7ed, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            state->mode = WCLEVELCTL_MODE_IDLE;
        }
        break;
    case WCLEVELCTL_MODE_PUZZLE_B:
        if (state->completionFlags & WCLEVELCTL_FLAG_TRIGGERED)
        {
            gameTimerInit(0x1d, 0x50);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedc, 1);
        }
        else if ((u32)GameBit_Get(0x7fa) != 0)
        {
            state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_B;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7f9) != 0)
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            else
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            if ((u32)GameBit_Get(0x7f9) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                state->mode = WCLEVELCTL_MODE_SEQUENCE;
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                state->mode = WCLEVELCTL_MODE_IDLE;
            }
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        else if (isGameTimerDisabled() != 0)
        {
            GameBit_Set(0x7f0, 0);
            GameBit_Set(0x7ee, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            state->mode = WCLEVELCTL_MODE_IDLE;
        }
        break;
    case WCLEVELCTL_MODE_SEQUENCE:
        if ((u32)GameBit_Get(0xcac) != 0)
        {
            GameObject* player;
            GameBit_Set(0xda9, 0);
            GameBit_Set(0xc37, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->mode = WCLEVELCTL_MODE_DONE;
        }
        break;
    case WCLEVELCTL_MODE_DONE:
        break;
    default:
        if (!(state->completionFlags & WCLEVELCTL_FLAG_PUZZLE_A) && GameBit_Get(0x7ed) != 0)
        {
            GameBit_Set(0x7ef, 1);
            state->eventTimer = lbl_803E6DB0;
            state->mode = WCLEVELCTL_MODE_PUZZLE_A;
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
            break;
        }
        if (!(state->completionFlags & WCLEVELCTL_FLAG_PUZZLE_B) && GameBit_Get(0x7ee) != 0)
        {
            GameBit_Set(0x7f0, 1);
            state->eventTimer = lbl_803E6DB0;
            state->mode = WCLEVELCTL_MODE_PUZZLE_B;
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        break;
    }
    state->completionFlags &= ~WCLEVELCTL_FLAG_TRIGGERED;
}

int wcpushblock_levelControlTriggerCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WcLevelControlState* state = ((GameObject*)obj)->extra;
    int i;

    state->completionFlags |= WCLEVELCTL_FLAG_TRIGGERED;
    state->completionFlags &= ~WCLEVELCTL_FLAG_EVENT_ACTIVE;
    if (state->previousMode == WCLEVELCTL_MODE_PUZZLE_A)
    {
        f32 t = state->eventTimer - timeDelta;
        state->eventTimer = t;
        if (t <= lbl_803E6DA8)
        {
            GameObject* player;
            GameBit_Set(0x7f7, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
        }
    }
    else if (state->previousMode == WCLEVELCTL_MODE_PUZZLE_B)
    {
        f32 t = state->eventTimer - timeDelta;
        state->eventTimer = t;
        if (t <= lbl_803E6DA8)
        {
            GameObject* player;
            GameBit_Set(0x802, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            state->mode = WCLEVELCTL_MODE_TREX_INIT;
            break;
        }
    }
    return 0;
}

int fn_80225D2C(int obj, s16 a, s16 b, f32* outX, f32* outZ, int dx, int dy)
{
    int i;
    int limit;
    f32 k6db4;
    f32 kc;

    if (dx != 0)
    {
        int bi = b;
        if (dx == -1)
        {
            f32 pz, px;
            mapGetBlockOriginForPos(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (kc = lbl_803E6DBC));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (kc = lbl_803E6DA8));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx)
        {
            if (lbl_803AD298[i][b] != 0)
            {
                if (lbl_803AD298[i][b] <= 4)
                {
                    f32 pz, px;
                    i += dx;
                    mapGetBlockOriginForPos(
                        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                        ((GameObject*)obj)->anim.localPosZ, &px, &pz);
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(
                        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                        ((GameObject*)obj)->anim.localPosZ, &px, &pz);
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
    }
    else
    {
        int ai = a;
        if (dy == -1)
        {
            f32 pz, px;
            mapGetBlockOriginForPos(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (kc = lbl_803E6DBC));
            b += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (kc = lbl_803E6DA8));
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy)
        {
            if (lbl_803AD298[a][i] != 0)
            {
                if (lbl_803AD298[a][i] <= 4)
                {
                    f32 pz, px;
                    i += dy;
                    mapGetBlockOriginForPos(
                        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                        ((GameObject*)obj)->anim.localPosZ, &px, &pz);
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(
                        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                        ((GameObject*)obj)->anim.localPosZ, &px, &pz);
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
    }
    return 4;
}

#undef WCPUSHBLOCK_IFACE
