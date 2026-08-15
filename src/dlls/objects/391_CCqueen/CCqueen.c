/*
 * CCqueen (DLL 0x187) - Crystal Caves Queen.
 *
 * Completing the gas puzzle and approaching the Queen sets her proximity
 * latch. Another progression bit hides and disables her; otherwise she
 * advances her movement and eye animation.
 */
#include "dlls/objects/391_CCqueen.h"

#include "dlls/objects/390_CCgasventCo.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/objhits.h"
#include "main/objprint_character_api.h"
#include "main/dll/dll_002E_moveLib.h"

#define CC_QUEEN_PROXIMITY_LATCH_GAMEBIT     0x1C2
#define CC_QUEEN_PROXIMITY_DISTANCE_SQUARED  18225.0f
#define CC_QUEEN_RENDER_SCALE                1.0f
#define CC_QUEEN_MOVE_STEP_SCALE             0.005f
#define CC_QUEEN_MOVE_YAW_LIMIT_A            0x71C7
#define CC_QUEEN_MOVE_YAW_LIMIT_B            0x3555
#define CC_QUEEN_MOVE_POINT_COUNT            3
#define CC_QUEEN_MOVE_REATTACK_DELAY_BASE    0x258
#define CC_QUEEN_MOVE_REATTACK_DELAY_MINIMUM 0xF0
#define CC_QUEEN_MOVE_LIB_MODE_BITS          0x0A
#define CC_QUEEN_ROT_X_SHIFT                 8

typedef struct CCQueenMoveTable {
    s16 entries[CC_QUEEN_MOVE_POINT_COUNT];
} CCQueenMoveTable;

STATIC_ASSERT(sizeof(CCQueenMoveTable) == 0x06);

static const CCQueenMoveTable sCCQueenMoveEventTable = {{0x1E, 0, 0}};
static const CCQueenMoveTable sCCQueenMoveTurnTable = {{0x19, 0x19, 0x19}};

int ccQueen_getExtraSize(void) {
    return sizeof(CCQueenState);
}

void ccQueen_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 unusedVisible) {
    CCQueenState* state = obj->extra;

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, CC_QUEEN_RENDER_SCALE);
    dll_2E_setTargetFromPathPoint(obj, &state->moveLib, 0);
}

void ccQueen_update(GameObject* obj) {
    CCQueenState* state;
    GameObject* player;

    state = obj->extra;
    if (mainGetBit(CC_QUEEN_PROXIMITY_LATCH_GAMEBIT) == 0 &&
        mainGetBit(CC_GAS_VENT_CONTROL_PUZZLE_COMPLETE_GAMEBIT) != 0) {
        player = Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) <
            CC_QUEEN_PROXIMITY_DISTANCE_SQUARED) {
            mainSetBits(CC_QUEEN_PROXIMITY_LATCH_GAMEBIT, 1);
        }
    }
    if (mainGetBit(GAMEBIT_ITEM_NWKey_Got2) != 0) {
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED);
        ObjHits_DisableObject(obj);
    } else {
        ObjAnim_AdvanceCurrentMove(obj, CC_QUEEN_MOVE_STEP_SCALE, timeDelta, NULL);
        dll_2E_updateLookAt(obj, &state->moveLib);
        characterDoEyeAnims(obj, &state->eyeAnimState);
    }
}

void ccQueen_init(GameObject* obj, const CCQueenPlacement* placement) {
    CCQueenState* state;
    CCQueenMoveTable eventTable;
    CCQueenMoveTable turnTable;

    state = obj->extra;
    eventTable = sCCQueenMoveEventTable;
    turnTable = sCCQueenMoveTurnTable;
    obj->anim.rotX = (s16)(placement->rotXByte << CC_QUEEN_ROT_X_SHIFT);
    dll_2E_initState(obj, &state->moveLib, CC_QUEEN_MOVE_YAW_LIMIT_A, CC_QUEEN_MOVE_YAW_LIMIT_B,
                  CC_QUEEN_MOVE_POINT_COUNT);
    dll_2E_setReattackDelay(&state->moveLib, CC_QUEEN_MOVE_REATTACK_DELAY_BASE, CC_QUEEN_MOVE_REATTACK_DELAY_MINIMUM);
    dll_2E_setMoveTables(&state->moveLib, &turnTable, &eventTable, CC_QUEEN_MOVE_POINT_COUNT);
    state->moveLib.modeBits = (u8)(state->moveLib.modeBits | CC_QUEEN_MOVE_LIB_MODE_BITS);
}

ObjectDescriptor gCCQueenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ccQueen_init,
    (ObjectDescriptorCallback)ccQueen_update,
    0,
    (ObjectDescriptorCallback)ccQueen_render,
    0,
    0,
    ccQueen_getExtraSize,
};
