#include "main/dll/dll_80220608_shared.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEventTypes.h"

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
#define WCPUSHBLOCK_REQUIRED_LOCK_COUNT 4

typedef struct WCPushBlockSetup {
    u8 pad00[0xc];
    f32 y;
    u8 pad10[WCPUSHBLOCK_MODEL_INDEX_OFFSET - 0x10];
    u8 modelIndex;
    s16 initialTile;
} WCPushBlockSetup;

typedef struct WCPushBlockRuntimeState {
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
STATIC_ASSERT(offsetof(WCPushBlockSetup, y) == 0xc);
STATIC_ASSERT(offsetof(WCPushBlockSetup, modelIndex) == WCPUSHBLOCK_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCPushBlockSetup, initialTile) == WCPUSHBLOCK_INITIAL_TILE_OFFSET);

#define WCPUSHBLOCK_CONTROLLER(state) (((WCPushBlockRuntimeState *)(state))->controller)
#define WCPUSHBLOCK_IFACE (*(int *)(*(int *)(WCPUSHBLOCK_CONTROLLER(state) + 0x68)))
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

#pragma peephole on
#pragma scheduling on
int wcpushblock_getExtraSize(void) { return WCPUSHBLOCK_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcpushblock_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + WCPUSHBLOCK_MODEL_INDEX_OFFSET);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCPUSHBLOCK_RENDER_TYPE_SHIFT) | WCPUSHBLOCK_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcpushblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D54);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcpushblock_init(int obj, int setup)
{
    WCPushBlockRuntimeState *state = *(WCPushBlockRuntimeState **)(obj + 0xb8);
    WCPushBlockSetup *setupData = (WCPushBlockSetup *)setup;

    *(u8 *)(obj + 0x36) = 0;
    *(u8 *)(obj + 0xad) = setupData->modelIndex;
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    ObjHitbox_SetStateIndex(obj, *(int *)(obj + 0x54), *(s8 *)(obj + 0xad));
    state->initialTile = (u8)setupData->initialTile;
    state->baseY = lbl_803E6DA0 + setupData->y;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpushblock_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpushblock_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();
    f32 range = lbl_803E6D58;
    f32 dist;
    int *tex;
    int moved;

    if ((void *)WCPUSHBLOCK_CONTROLLER(state) == 0) {
        WCPUSHBLOCK_CONTROLLER(state) = ObjGroup_FindNearestObject(WCPUSHBLOCK_CONTROLLER_GROUP, obj, &range);
        *(u8 *)(obj + 0x36) = 0;
        return;
    }
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) {
        *tex = WCPUSHBLOCK_TEXTURE_DEFAULT;
    }
    *(u16 *)(obj + 0xb0) &= ~WCPUSHBLOCK_OBJFLAG_LOCKED;

    if (WCPUSHBLOCK_FLAGS(state).phase != WCPUSHBLOCK_PHASE_SOLVED) {
        if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
            if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_A_SOLVED) != 0) {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_SOLVED;
                (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x34))(
                    WCPUSHBLOCK_INITIAL_TILE(state), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y, WCPUSHBLOCK_IFACE);
                (*(void (**)(int, int, int, f32 *, f32 *, int))(WCPUSHBLOCK_IFACE + 0x20))(
                    obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                    (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), WCPUSHBLOCK_IFACE);
            } else if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_A_FADE) != 0) {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_FADE_OUT;
            }
        } else {
            if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_B_SOLVED) != 0) {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_SOLVED;
                (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x50))(
                    WCPUSHBLOCK_INITIAL_TILE(state), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y, WCPUSHBLOCK_IFACE);
                (*(void (**)(int, int, int, f32 *, f32 *, int))(WCPUSHBLOCK_IFACE + 0x3c))(
                    obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                    (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), WCPUSHBLOCK_IFACE);
            } else if ((u32)GameBit_Get(WCPUSHBLOCK_GAMEBIT_B_FADE) != 0) {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_FADE_OUT;
            }
        }
    }

    {
        u32 ph = WCPUSHBLOCK_FLAGS(state).phase;
        if (ph != WCPUSHBLOCK_PHASE_FADE_OUT && ph != WCPUSHBLOCK_PHASE_FADE_IN) {
            if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
                objfx_spawnBoxBurst(obj, 1, WCPUSHBLOCK_BOX_BURST_VARIANT_A, 1, lbl_803E6D5C, lbl_803E6D60, lbl_803E6D5C,
                                    lbl_803E6D60, 50, 0, 0);
            } else {
                objfx_spawnBoxBurst(obj, 1, WCPUSHBLOCK_BOX_BURST_VARIANT_B, 1, lbl_803E6D5C, lbl_803E6D60, lbl_803E6D5C,
                                    lbl_803E6D60, 50, 0, 0);
            }
        }
    }

    switch (WCPUSHBLOCK_FLAGS(state).phase) {
    case WCPUSHBLOCK_PHASE_INIT_MOVE:
        if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
            (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x30))(
                WCPUSHBLOCK_INITIAL_TILE(state), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y, WCPUSHBLOCK_IFACE);
            (*(void (**)(int, int, int, f32 *, f32 *, int))(WCPUSHBLOCK_IFACE + 0x20))(
                obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), WCPUSHBLOCK_IFACE);
        } else {
            (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x4c))(
                WCPUSHBLOCK_INITIAL_TILE(state), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y, WCPUSHBLOCK_IFACE);
            (*(void (**)(int, int, int, f32 *, f32 *, int))(WCPUSHBLOCK_IFACE + 0x3c))(
                obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), WCPUSHBLOCK_IFACE);
        }
        WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_IDLE;
        break;
    case WCPUSHBLOCK_PHASE_IDLE:
        {
            int a = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (a > 255) {
                a = 255;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        {
            f32 zero = lbl_803E6D64;
            *(f32 *)(obj + 0x24) = zero;
            *(f32 *)(obj + 0x2c) = zero;
        }
        if (fn_80296414(player, obj, state + WCPUSHBLOCK_STATE_PUSH_DIR) != 0) {
            u32 dir = WCPUSHBLOCK_PUSH_DIR(state);
            if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
                if (dir == WCPUSHBLOCK_DIR_POS_X) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x38))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), -1, 0, WCPUSHBLOCK_IFACE);
                } else if (dir == WCPUSHBLOCK_DIR_NEG_X) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x38))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), 1, 0, WCPUSHBLOCK_IFACE);
                } else if (dir == WCPUSHBLOCK_DIR_POS_Z) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x38))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), 0, -1, WCPUSHBLOCK_IFACE);
                } else if (dir == WCPUSHBLOCK_DIR_NEG_Z) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x38))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), 0, 1, WCPUSHBLOCK_IFACE);
                }
            } else {
                if (dir == WCPUSHBLOCK_DIR_POS_X) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x54))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), -1, 0, WCPUSHBLOCK_IFACE);
                } else if (dir == WCPUSHBLOCK_DIR_NEG_X) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x54))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), 1, 0, WCPUSHBLOCK_IFACE);
                } else if (dir == WCPUSHBLOCK_DIR_POS_Z) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x54))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), 0, -1, WCPUSHBLOCK_IFACE);
                } else if (dir == WCPUSHBLOCK_DIR_NEG_Z) {
                    WCPUSHBLOCK_MOVE_RESULT(state) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(WCPUSHBLOCK_IFACE + 0x54))(
                            obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                            (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_X), (f32 *)(state + WCPUSHBLOCK_STATE_TARGET_Z), 0, 1, WCPUSHBLOCK_IFACE);
                }
            }
            if (WCPUSHBLOCK_TARGET_X(state) == *(f32 *)(obj + 0xc) &&
                WCPUSHBLOCK_TARGET_Z(state) == *(f32 *)(obj + 0x10)) {
                ;
            } else {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_SLIDING;
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_SLIDING:
        if (lbl_803E6D64 != *(f32 *)(obj + 0x24) || lbl_803E6D64 != *(f32 *)(obj + 0x2c)) {
            f32 speed = sqrtf(*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) +
                              *(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c)) -
                        lbl_803E6D68;
            if (speed < lbl_803E6D64) {
                speed = lbl_803E6D64;
            }
            dist = lbl_803E6D54 + lbl_803E6D6C * speed / lbl_803E6D70;
            if (dist > lbl_803E6D74) {
                dist = lbl_803E6D74;
            }
            Sfx_KeepAliveLoopedObjectSound(obj, SFXsc_lockon2_off);
            Sfx_SetObjectSfxVolume(obj, SFXsc_lockon2_off, (int)dist, lbl_803E6D78);
            WCPUSHBLOCK_FLAGS(state).sfxActive = 1;
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, lbl_803E6D64,
                *(f32 *)(obj + 0x2c) * timeDelta);
        moved = 0;
        {
            u32 dir = WCPUSHBLOCK_PUSH_DIR(state);
            if (dir == WCPUSHBLOCK_DIR_POS_X) {
                if (*(f32 *)(obj + 0x24) < lbl_803E6D7C) {
                    *(f32 *)(obj + 0x24) = lbl_803E6D80 * timeDelta + *(f32 *)(obj + 0x24);
                }
                if (*(f32 *)(obj + 0xc) >= WCPUSHBLOCK_TARGET_X(state)) {
                    *(f32 *)(obj + 0xc) = WCPUSHBLOCK_TARGET_X(state);
                    moved = 1;
                }
            } else if (dir == WCPUSHBLOCK_DIR_NEG_X) {
                if (*(f32 *)(obj + 0x24) > lbl_803E6D84) {
                    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) - lbl_803E6D80 * timeDelta;
                }
                if (*(f32 *)(obj + 0xc) <= WCPUSHBLOCK_TARGET_X(state)) {
                    *(f32 *)(obj + 0xc) = WCPUSHBLOCK_TARGET_X(state);
                    moved = 1;
                }
            } else if (dir == WCPUSHBLOCK_DIR_POS_Z) {
                if (*(f32 *)(obj + 0x2c) < lbl_803E6D7C) {
                    *(f32 *)(obj + 0x2c) = lbl_803E6D80 * timeDelta + *(f32 *)(obj + 0x2c);
                }
                if (*(f32 *)(obj + 0x14) >= WCPUSHBLOCK_TARGET_Z(state)) {
                    *(f32 *)(obj + 0x14) = WCPUSHBLOCK_TARGET_Z(state);
                    moved = 1;
                }
            } else if (dir == WCPUSHBLOCK_DIR_NEG_Z) {
                if (*(f32 *)(obj + 0x2c) > lbl_803E6D84) {
                    *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) - lbl_803E6D80 * timeDelta;
                }
                if (*(f32 *)(obj + 0x14) <= WCPUSHBLOCK_TARGET_Z(state)) {
                    *(f32 *)(obj + 0x14) = WCPUSHBLOCK_TARGET_Z(state);
                    moved = 1;
                }
            }
        }
        if (*(f32 *)(obj + 0x24) > lbl_803E6D7C) {
            *(f32 *)(obj + 0x24) = lbl_803E6D7C;
        }
        if (*(f32 *)(obj + 0x24) < lbl_803E6D84) {
            *(f32 *)(obj + 0x24) = lbl_803E6D84;
        }
        if (*(f32 *)(obj + 0x2c) > lbl_803E6D7C) {
            *(f32 *)(obj + 0x2c) = lbl_803E6D7C;
        }
        if (*(f32 *)(obj + 0x2c) < lbl_803E6D84) {
            *(f32 *)(obj + 0x2c) = lbl_803E6D84;
        }
        if (moved == 0) {
            break;
        }
        {
            f32 zero = lbl_803E6D64;
            *(f32 *)(obj + 0x24) = zero;
            *(f32 *)(obj + 0x2c) = zero;
        }
        {
            u32 r = WCPUSHBLOCK_MOVE_RESULT(state);
            if (r == WCPUSHBLOCK_MOVE_RESULT_LOCKED) {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_LOCKED;
                if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
                    if (gameBitIncrement(WCPUSHBLOCK_GAMEBIT_A_COUNT) != WCPUSHBLOCK_REQUIRED_LOCK_COUNT) {
                        Sfx_PlayFromObject(0, SFXsc_lockon3_off);
                    }
                } else {
                    if (gameBitIncrement(WCPUSHBLOCK_GAMEBIT_B_COUNT) != WCPUSHBLOCK_REQUIRED_LOCK_COUNT) {
                        Sfx_PlayFromObject(0, SFXsc_lockon3_off);
                    }
                }
            } else if (r == WCPUSHBLOCK_MOVE_RESULT_CONTINUE) {
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_IDLE;
                if (WCPUSHBLOCK_FLAGS(state).sfxActive != 0) {
                    WCPUSHBLOCK_FLAGS(state).sfxActive = 0;
                    Sfx_PlayFromObject(obj, SFXsc_lockon3_on);
                }
            } else {
                if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
                    GameBit_Set(WCPUSHBLOCK_GAMEBIT_A_FADE, 1);
                } else {
                    GameBit_Set(WCPUSHBLOCK_GAMEBIT_B_FADE, 1);
                }
            }
        }
        if (WCPUSHBLOCK_FLAGS(state).phase != WCPUSHBLOCK_PHASE_FADE_OUT) {
            if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
                (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x28))(
                    0, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state), WCPUSHBLOCK_IFACE);
                (*(void (**)(int, f32, f32, int, int, int))(WCPUSHBLOCK_IFACE + 0x24))(
                    obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y,
                    WCPUSHBLOCK_IFACE);
                (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x28))(
                    WCPUSHBLOCK_INITIAL_TILE(state), WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                    WCPUSHBLOCK_IFACE);
            } else {
                (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x44))(
                    0, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state), WCPUSHBLOCK_IFACE);
                (*(void (**)(int, f32, f32, int, int, int))(WCPUSHBLOCK_IFACE + 0x40))(
                    obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y,
                    WCPUSHBLOCK_IFACE);
                (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x44))(
                    WCPUSHBLOCK_INITIAL_TILE(state), WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                    WCPUSHBLOCK_IFACE);
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_FADE_OUT:
        ObjHits_DisableObject(obj);
        if (*(u8 *)(obj + 0x36) == WCPUSHBLOCK_ALPHA_OPAQUE) {
            Sfx_PlayFromObject(obj, SFXsc_lifeforcedoor);
        }
        {
            int a = *(u8 *)(obj + 0x36) - (framesThisStep << WCPUSHBLOCK_ALPHA_STEP_SHIFT);
            if (a < 0) {
                a = 0;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            if (wcblock_isPlayerAwayFromStoredCell(obj, state, Obj_GetPlayerObject()) != 0) {
                if ((s8)*(u8 *)(obj + 0xad) == WCPUSHBLOCK_VARIANT_A) {
                    (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x30))(
                        WCPUSHBLOCK_INITIAL_TILE(state), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y, WCPUSHBLOCK_IFACE);
                    (*(void (**)(int, int, int, f32 *, f32 *, int))(WCPUSHBLOCK_IFACE + 0x20))(
                        obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                        (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), WCPUSHBLOCK_IFACE);
                } else {
                    (*(void (**)(int, int, int, int))(WCPUSHBLOCK_IFACE + 0x4c))(
                        WCPUSHBLOCK_INITIAL_TILE(state), state + WCPUSHBLOCK_STATE_TILE_X, state + WCPUSHBLOCK_STATE_TILE_Y, WCPUSHBLOCK_IFACE);
                    (*(void (**)(int, int, int, f32 *, f32 *, int))(WCPUSHBLOCK_IFACE + 0x3c))(
                        obj, WCPUSHBLOCK_TILE_X(state), WCPUSHBLOCK_TILE_Y(state),
                        (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), WCPUSHBLOCK_IFACE);
                }
                WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_FADE_IN;
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_FADE_IN:
        if (*(u8 *)(obj + 0x36) == 0) {
            ObjHits_EnableObject(obj);
            Sfx_PlayFromObject(0, SFXsc_golfbar_swipe);
        }
        {
            int a = *(u8 *)(obj + 0x36) + (framesThisStep << WCPUSHBLOCK_ALPHA_STEP_SHIFT);
            if (a > WCPUSHBLOCK_ALPHA_OPAQUE) {
                a = WCPUSHBLOCK_ALPHA_OPAQUE;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        if (*(u8 *)(obj + 0x36) >= WCPUSHBLOCK_ALPHA_OPAQUE) {
            WCPUSHBLOCK_FLAGS(state).phase = WCPUSHBLOCK_PHASE_IDLE;
        }
        break;
    case WCPUSHBLOCK_PHASE_SOLVED:
        *(u8 *)(obj + 0x36) = WCPUSHBLOCK_ALPHA_OPAQUE;
    case WCPUSHBLOCK_PHASE_LOCKED:
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) {
            *tex = WCPUSHBLOCK_TEXTURE_LOCKED;
        }
        *(u16 *)(obj + 0xb0) |= WCPUSHBLOCK_OBJFLAG_LOCKED;
        break;
    }

    WCPUSHBLOCK_BOB_ANGLE(state) = lbl_803E6D88 * timeDelta + (f32)(u32)WCPUSHBLOCK_BOB_ANGLE(state);
    WCPUSHBLOCK_BOB_Y(state) =
        lbl_803E6D8C * fn_80293E80(lbl_803E6D90 * (f32)(u32)WCPUSHBLOCK_BOB_ANGLE(state) / lbl_803E6D94);
    *(f32 *)(obj + 0x10) = WCPUSHBLOCK_BASE_Y(state) + WCPUSHBLOCK_BOB_Y(state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_802251B4(int obj, int state)
{
    int scratch;

    (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&scratch);
    switch (*(u8 *)(state + 0xc)) {
    case 6:
        gameTimerInit(0x1d, 0x50);
        timerSetToCountUp();
        *(u8 *)(state + 0xc) = 4;
        break;
    case 4:
        if ((u32)GameBit_Get(0x2a5) != 0) {
            int player;
            GameBit_Set(0x274, 1);
            GameBit_Set(0xef1, 0);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
            *(u16 *)(state + 0x1a) |= 0x40;
            *(u8 *)(state + 0xc) = 0;
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            gameTimerStop();
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x274, 0);
            GameBit_Set(0xef1, 0);
            if ((u32)GameBit_Get(0x34d) == 0) {
                GameBit_Set(0x2b1, 0);
                GameBit_Set(0x226, 1);
                GameBit_Set(0x2a6, 1);
                GameBit_Set(0x206, 1);
                GameBit_Set(0x25f, 1);
                *(u8 *)(state + 0xc) = 0;
            }
        }
        break;
    default:
        if (!(*(u16 *)(state + 0x1a) & 0x40) && (u32)GameBit_Get(0x2b1) != 0) {
            GameBit_Set(0xef1, 1);
            GameBit_Set(0xe6d, 0);
            if ((u32)GameBit_Get(0x204) != 0) {
                GameBit_Set(0x226, 0);
                GameBit_Set(0x2a6, 0);
                GameBit_Set(0x206, 0);
                GameBit_Set(0x25f, 0);
                GameBit_Set(0x274, 1);
                *(u8 *)(state + 0xc) = 6;
            }
        }
        break;
    }

    if (!(*(u16 *)(state + 0x1a) & 0x10)) {
        if ((u8)GameBit_Get(0x810) == 4) {
            GameBit_Set(0x812, 1);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            *(u16 *)(state + 0x1a) |= 0x10;
        } else if ((u32)GameBit_Get(0x808) != 0) {
            if (*(f32 *)(state + 8) <= lbl_803E6DA8) {
                GameBit_Set(0x810, 0);
                memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
                *(f32 *)(state + 8) = lbl_803E6DAC;
            }
        }
        if (*(f32 *)(state + 8) > lbl_803E6DA8) {
            *(f32 *)(state + 8) -= timeDelta;
            if (*(f32 *)(state + 8) <= lbl_803E6DA8)
                GameBit_Set(0x808, 0);
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x20)) {
        if ((u8)GameBit_Get(0x811) == 4) {
            GameBit_Set(0x813, 1);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            *(u16 *)(state + 0x1a) |= 0x20;
        } else if ((u32)GameBit_Get(0x809) != 0) {
            if (*(f32 *)(state + 4) <= lbl_803E6DA8) {
                GameBit_Set(0x811, 0);
                memcpy(lbl_803AD298, lbl_8032B088, 0x40);
                *(f32 *)(state + 4) = lbl_803E6DAC;
            }
        }
        if (*(f32 *)(state + 4) > lbl_803E6DA8) {
            *(f32 *)(state + 4) -= timeDelta;
            if (*(f32 *)(state + 4) <= lbl_803E6DA8)
                GameBit_Set(0x809, 0);
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x80)) {
        if ((u32)GameBit_Get(0xc58) != 0 && (u32)GameBit_Get(0xc59) != 0 &&
            (u32)GameBit_Get(0xc5a) != 0) {
            GameBit_Set(0x205, 1);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            *(u16 *)(state + 0x1a) |= 0x80;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b40 &&
                   (u32)GameBit_Get(0xc58) != 0) {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            ((WclevelcontFlags *)(state + 0x14))->b40 = 1;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b20 &&
                   (u32)GameBit_Get(0xc59) != 0) {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            ((WclevelcontFlags *)(state + 0x14))->b20 = 1;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b18 &&
                   (u32)GameBit_Get(0xc5a) != 0) {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            ((WclevelcontFlags *)(state + 0x14))->b18 = 1;
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x100)) {
        if ((u32)GameBit_Get(0xbcf) != 0) {
            int player;
            GameBit_Set(0xbc8, 0);
            GameBit_Set(0x2f0, 1);
            GameBit_Set(0xeec, 0);
            GameBit_Set(0xbd0, 0);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            *(u16 *)(state + 0x1a) |= 0x100;
        }
    }

    *(u16 *)(state + 0x1a) &= ~1;
    if ((u32)GameBit_Get(0xc92) != 0) {
        GameBit_Set(0x4e4, 0);
        GameBit_Set(0x4e5, 0);
        if ((u32)GameBit_Get(0x4e3) == 0xff)
            GameBit_Set(0x4e3, randomGetRange(6, 7));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpushblock_updateLevelControlState(int obj, int state)
{
    if (*(u16 *)(state + 0x1a) & 0x2)
        return;
    *(u8 *)(state + 0xd) = *(u8 *)(state + 0xc);
    switch (*(u8 *)(state + 0xc)) {
    case 1:
        if (*(u16 *)(state + 0x1a) & 0x1) {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedd, 1);
        } else if ((u32)GameBit_Get(0x7f9) != 0) {
            *(u16 *)(state + 0x1a) |= 0x4;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7fa) != 0)
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            else
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            if ((u32)GameBit_Get(0x7fa) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                *(u8 *)(state + 0xc) = 3;
            } else {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 0xc) = 0;
            }
            *(u16 *)(state + 0x1a) |= 0x2;
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x7ef, 0);
            GameBit_Set(0x7ed, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            *(u8 *)(state + 0xc) = 0;
        }
        break;
    case 2:
        if (*(u16 *)(state + 0x1a) & 0x1) {
            gameTimerInit(0x1d, 0x50);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedc, 1);
        } else if ((u32)GameBit_Get(0x7fa) != 0) {
            *(u16 *)(state + 0x1a) |= 0x8;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7f9) != 0)
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
            else
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            if ((u32)GameBit_Get(0x7f9) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                *(u8 *)(state + 0xc) = 3;
            } else {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 0xc) = 0;
            }
            *(u16 *)(state + 0x1a) |= 0x2;
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x7f0, 0);
            GameBit_Set(0x7ee, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            *(u8 *)(state + 0xc) = 0;
        }
        break;
    case 3:
        if ((u32)GameBit_Get(0xcac) != 0) {
            int player;
            GameBit_Set(0xda9, 0);
            GameBit_Set(0xc37, 1);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
            *(u8 *)(state + 0xc) = 7;
        }
        break;
    case 7:
        break;
    default:
        if (!(*(u16 *)(state + 0x1a) & 0x4) && (u32)GameBit_Get(0x7ed) != 0) {
            GameBit_Set(0x7ef, 1);
            *(f32 *)(state + 0) = lbl_803E6DB0;
            *(u8 *)(state + 0xc) = 1;
            *(u16 *)(state + 0x1a) |= 0x2;
            break;
        }
        if (!(*(u16 *)(state + 0x1a) & 0x8) && (u32)GameBit_Get(0x7ee) != 0) {
            GameBit_Set(0x7f0, 1);
            *(f32 *)(state + 0) = lbl_803E6DB0;
            *(u8 *)(state + 0xc) = 2;
            *(u16 *)(state + 0x1a) |= 0x2;
        }
        break;
    }
    *(u16 *)(state + 0x1a) &= ~1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcpushblock_levelControlTriggerCallback(int obj, int p2, int p3)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(u16 *)(state + 0x1a) |= 0x1;
    *(u16 *)(state + 0x1a) &= ~0x2;
    if (*(u8 *)(state + 0xd) == 1) {
        f32 t = *(f32 *)(state + 0) - timeDelta;
        *(f32 *)(state + 0) = t;
        if (t <= lbl_803E6DA8) {
            int player;
            GameBit_Set(0x7f7, 1);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
        }
    } else if (*(u8 *)(state + 0xd) == 2) {
        f32 t = *(f32 *)(state + 0) - timeDelta;
        *(f32 *)(state + 0) = t;
        if (t <= lbl_803E6DA8) {
            int player;
            GameBit_Set(0x802, 1);
            player = Obj_GetPlayerObject();
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
        }
    }
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        switch (*(u8 *)(p3 + i + 0x81)) {
        case 1:
            *(u8 *)(state + 0xc) = 6;
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80225D2C(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0) {
        int bi = b;
        if (dx == -1) {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + lbl_803E6DBC);
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        } else {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + lbl_803E6DA8);
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx) {
            if (lbl_803AD298[i][b] != 0) {
                if (lbl_803AD298[i][b] <= 4) {
                    f32 pz, px;
                    i += dx;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    } else {
        int ai = a;
        if (dy == -1) {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + lbl_803E6DBC);
            b += 1;
            limit = 8;
        } else {
            f32 pz, px;
            mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + lbl_803E6DA8);
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy) {
            if (lbl_803AD298[a][i] != 0) {
                if (lbl_803AD298[a][i] <= 4) {
                    f32 pz, px;
                    i += dy;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
}
#pragma scheduling reset
#pragma peephole reset

#undef WCPUSHBLOCK_IFACE
#undef SFXmn_sml_trex_fstep
#undef SFXsc_lockon3_on
#undef SFXsc_lockon3_off
#undef SFXsc_lifeforcedoor
#undef SFXsc_golfbar_swipe
#undef SFXsp_lf_mutter4
