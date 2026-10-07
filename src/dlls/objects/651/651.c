/*
 * DLL 651 - a player-control-interface driven NPC character.
 *
 * The object joins object group 3 and runs entirely off the shared
 * gPlayerInterface vtable: init() wires its move/state tables, and each
 * frame update() drives it through update() (using the gDll28BStateHandlers
 * main and gDll28BSubstateHandlers sub state-handler tables installed by
 * initialise(); the handler functions are defined below in this TU).
 * Its obj+0xB8 state is described by Dll28BState.
 * Per-frame it caches its planar distance to the player, runs the shared
 * dll_2E (moveLib) look-at/turn block at state+0x35C, the eye-animation
 * block at state+0x980, and a ROM-curve walker at state+0x9B0. render()
 * draws the model and the moveLib attachment when visible.
 */
#include "main/dll/dll_028B.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/curve.h"
#include "main/objanim.h"
#include "main/frame_timing.h"
#include "sys/objects.h"
#include "main/vecmath.h"
#include "main/dll/rom_curve_interface.h"
#include "main/player_control_interface.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/track_dolphin_api.h"
#include "main/objtype.h"
#include "main/objprint_character_api.h"
#include "main/dll/dll_002E_moveLib.h"

#define DLL28B_OBJ_GROUP    3
#define OBJFLAG_BIT_2000000 0x2000000

const Dll28BMoveBlendData gDll28BMoveBlendDataA = {{0x00050005, 0x000A000A, 0x000A000A, 0x000A000A}};
const Dll28BMoveBlendData gDll28BMoveBlendDataB = {{0x0005000A, 0x00140014, 0x00140014, 0x00140014}};

void* gDll28BSubstateHandlers[4];

/* Address reads retain the named read-only pool without duplicate literals. */
const f32 gWcEarthWalkerFarPlayerDistance = 220.0f;
const f32 gWcEarthWalkerNearPlayerDistance = 100.0f;
const f32 gWcEarthWalkerIdleTimerThreshold = 0.0f;
int dll_28B_substateHandler3(GameObject* obj, BaddieState* ai) {
    Dll28BState* state = *(Dll28BState**)&obj->extra;

    if (ai->moveJustStartedB != 0) {
        state->flagsAC0 &= ~1;
        (*gPlayerInterface)->setState(obj, ai, 3);
    } else if (ai->moveDone != 0) {
        return 3;
    }
    return 0;
}

int dll_28B_substateHandler2(GameObject* obj, BaddieState* ai) {
    Dll28BState* state = *(Dll28BState**)&obj->extra;
    f32 dist;

    if (ai->moveJustStartedB != 0) {
        state->flagsAC0 |= 1;
        (*gPlayerInterface)->setState(obj, ai, 1);
    }
    state->randomTimer -= timeDelta;
    dist = state->playerDistance;
    if (dist > (*(const f32*)&gWcEarthWalkerFarPlayerDistance)) {
        return 2;
    }
    if (dist < (*(const f32*)&gWcEarthWalkerNearPlayerDistance)) {
        if (state->randomTimer <= (*(const f32*)&gWcEarthWalkerIdleTimerThreshold)) {
            state->randomTimer = randomGetRange(0x78, 0xfa);
            return 4;
        }
    }
    return 0;
}

#define WC_EARTHWALKER_CURVE_ADVANCE_STEP   0.5f
#define WC_EARTHWALKER_APPROACH_PLAYER_DIST 200.0f
#define WC_EARTHWALKER_CHASE_MOVE_SPEED     0.012f
#define WC_EARTHWALKER_WALK_MOVE_SPEED      0.005f

int dll_28B_substateHandler1(GameObject* obj, BaddieState* ai) {
    Dll28BState* state = *(Dll28BState**)&obj->extra;
    RomCurveWalker* route = &state->route;

    if (ai->moveJustStartedB != 0) {
        state->flagsAC0 &= ~1;
        (*gPlayerInterface)->setState(obj, ai, 2);
    }
    if (Curve_AdvanceAlongPath(&route->curve, WC_EARTHWALKER_CURVE_ADVANCE_STEP) != 0 || route->atSegmentEnd != 0) {
        (*gRomCurveInterface)->goNextPoint(route);
    }
    if (state->playerDistance < WC_EARTHWALKER_APPROACH_PLAYER_DIST) {
        return 3;
    }
    return 0;
}

/*
 * DLL 0x28B state-machine handlers (installed by dll_028B_initialise into
 * gDll28BStateHandlers / gDll28BSubstateHandlers; driven each frame by
 * gPlayerInterface->update). Each returns the next state index (0 = stay).
 * `ai` is the BaddieState at obj->extra (== the local `state` pointer); the
 * The slot at 0x14 is setState().
 *
 *   stateHandler:    0 -> next state 2; 1/3 set moveSpeed on (re)entry,
 *                    3 also faces the player; 2 = locomotion: drives the
 *                    object along the ROM-curve route and samples root motion.
 *   substateHandler: 0 -> next state 2; 1 = follow curve, advancing points,
 *                    -> 3 when the player is within range; 2 = idle/watch,
 *                    -> 2 when player far, -> 4 (after a random 120..250
 *                    frame timer) when near; 3 requests setState 3 and
 *                    -> 3 when the move finishes.
 */
int dll_28B_substateHandler0(void) {
    return 0x2;
}

int dll_28B_stateHandler3(GameObject* obj, BaddieState* ai) {
    GameObject* player = (GameObject*)Obj_GetPlayerObject();

    if (ai->moveJustStartedA != 0) {
        ai->moveSpeed = WC_EARTHWALKER_CHASE_MOVE_SPEED;
        getAngle(obj->anim.localPosX - player->anim.localPosX, obj->anim.localPosZ - player->anim.localPosZ);
    }
    return 0;
}

int dll_28B_stateHandler2(GameObject* obj, BaddieState* ai) {
    Dll28BState* state = *(Dll28BState**)&obj->extra;

    obj->anim.velocityX = oneOverTimeDelta * (state->route.posX - obj->anim.localPosX);
    obj->anim.velocityZ = oneOverTimeDelta * (state->route.posZ - obj->anim.localPosZ);
    obj->anim.localPosX = state->route.posX;
    obj->anim.localPosZ = state->route.posZ;
    obj->anim.rotX = getAngle(-state->route.tangentX, -state->route.tangentZ);
    /* Retail rounds both squared components before adding; do not fuse them. */
    ObjAnim_SampleRootCurvePhase(
        obj,
        sqrtf((f32)(obj->anim.velocityX * obj->anim.velocityX) + (f32)(obj->anim.velocityZ * obj->anim.velocityZ)),
        &ai->moveSpeed);
    return 0;
}

int dll_28B_stateHandler1(GameObject* obj, BaddieState* ai) {
    if (ai->moveJustStartedA != 0) {
        ai->moveSpeed = WC_EARTHWALKER_WALK_MOVE_SPEED;
    }
    return 0;
}

int dll_28B_stateHandler0(void) {
    return 0x2;
}
int dll_28B_getExtraSize(void) {
    return sizeof(Dll28BState);
}

int dll_28B_getObjectTypeId(void) {
    return 0x0;
}

void dll_28B_free(GameObject* obj) {
    objFreeObjectType(obj, DLL28B_OBJ_GROUP);
}

void dll_28B_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    Dll28BState* state = obj->extra;
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        dll_2E_setTargetFromPathPoint(obj, &state->moveLib, 0);
    }
}

void dll_28B_hitDetect_nop(void) {
}

void dll_28B_update(GameObject* obj) {
    f32 oz, oy, ox;
    f32 dt;
    MatrixTransform xform;
    f32 mtx[16];
    Dll28BState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();

    state->playerDistance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
    state->baddie.flags0 |= OBJFLAG_BIT_2000000;
    dt = timeDelta;
    (*gPlayerInterface)->update(obj, &state->baddie, dt, dt, gDll28BStateHandlers, gDll28BSubstateHandlers);
    if ((state->flagsAC0 & 1) != 0) {
        state->moveLib.modeBits &= ~1;
    } else {
        state->moveLib.modeBits |= 1;
    }
    dll_2E_updateLookAt(obj, &state->moveLib);
    characterDoEyeAnims(obj, &state->eyeAnimState);
    xform.x = obj->anim.localPosX;
    xform.y = obj->anim.localPosY;
    xform.z = obj->anim.localPosZ;
    xform.rotX = obj->anim.rotX;
    xform.rotY = obj->anim.rotY;
    xform.rotZ = obj->anim.rotZ;
    xform.scale = 1.0f;
    setMatrixFromObjectPos(mtx, &xform);
    Matrix_TransformPoint(mtx, (*(const f32*)&gWcEarthWalkerIdleTimerThreshold),
                          (*(const f32*)&gWcEarthWalkerIdleTimerThreshold),
                          (*(const f32*)&gWcEarthWalkerIdleTimerThreshold), &ox, &oy, &oz);
    playerShadowSetPositionOverride(obj, ox, oy, oz);
}

static const f32 gDll28BCurveInitParam = 1000.0f;

void* gDll28BStateHandlers[4];

void dll_28B_init(GameObject* obj) {
    int curveParam;
    Dll28BMoveBlendData blockA;
    Dll28BMoveBlendData blockB;
    Dll28BState* state = obj->extra;

    blockA = gDll28BMoveBlendDataA;
    blockB = gDll28BMoveBlendDataB;
    curveParam = 2;
    dll_2E_initState(obj, &state->moveLib, -0x2AAA, 0x638E, 8);
    dll_2E_setMoveTables(&state->moveLib, &blockB, &blockA, 8);
    state->moveLib.modeBits |= 0x22;
    (*gRomCurveInterface)->initCurve(&state->route, obj, gDll28BCurveInitParam, &curveParam, -1);
    (*gPlayerInterface)->init(obj, &state->baddie, 4, 4);
    objAddObjectType(obj, DLL28B_OBJ_GROUP);
}

void dll_28B_release_nop(void) {
}

void dll_28B_initialise(void) {
    gDll28BStateHandlers[0] = dll_28B_stateHandler0;
    gDll28BStateHandlers[1] = dll_28B_stateHandler1;
    gDll28BStateHandlers[2] = dll_28B_stateHandler2;
    gDll28BStateHandlers[3] = dll_28B_stateHandler3;
    gDll28BSubstateHandlers[0] = dll_28B_substateHandler0;
    gDll28BSubstateHandlers[1] = dll_28B_substateHandler1;
    gDll28BSubstateHandlers[2] = dll_28B_substateHandler2;
    gDll28BSubstateHandlers[3] = dll_28B_substateHandler3;
}

ObjectDescriptor gDll28BObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_28B_initialise,
    (ObjectDescriptorCallback)dll_28B_release_nop,
    0,
    (ObjectDescriptorCallback)dll_28B_init,
    (ObjectDescriptorCallback)dll_28B_update,
    (ObjectDescriptorCallback)dll_28B_hitDetect_nop,
    (ObjectDescriptorCallback)dll_28B_render,
    (ObjectDescriptorCallback)dll_28B_free,
    (ObjectDescriptorCallback)dll_28B_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_28B_getExtraSize,
};
