/*
 * DLL 0x28B - a player-control-interface driven NPC character.
 *
 * The object joins object group 3 and runs entirely off the shared
 * gPlayerInterface vtable: init() wires its move/state tables, and each
 * frame update() drives it through update() (using the gDll28BStateHandlers
 * main and gDll28BSubstateHandlers sub state-handler tables installed by
 * initialise(); the handler functions themselves are compiled into the
 * dll_028A_wcearthwalker TU). Its obj+0xB8 block is also described by
 * Dll28BAiState in earthwalker_state.h (where the handlers view it).
 * Per-frame it caches its planar distance to the player, runs the shared
 * dll_2E (moveLib) look-at/turn block at state+0x35C, the eye-animation
 * block at state+0x980, and a ROM-curve walker at state+0x9B0. render()
 * draws the model and the moveLib attachment when visible.
 */
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/dll/moveLib.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objprint_character_api.h"
#include "main/dll/WC/dll_028A_wcearthwalker.h"
#include "main/dll/dll_028B.h"
#include "main/player_control_interface.h"
#include "main/object_render_legacy.h"

#define DLL28B_OBJ_GROUP    3
#define OBJFLAG_BIT_2000000 0x2000000

__declspec(section ".rodata") Dll28BMoveBlendData gDll28BMoveBlendDataA = {{0x00050005, 0x000A000A, 0x000A000A, 0x000A000A}};
__declspec(section ".rodata") Dll28BMoveBlendData gDll28BMoveBlendDataB = {{0x0005000A, 0x00140014, 0x00140014, 0x00140014}};

int dll_28B_getExtraSize(void)
{
    return sizeof(Dll28BState);
}

int dll_28B_getObjectTypeId(void)
{
    return 0x0;
}

void dll_28B_free(int obj)
{
    ObjGroup_RemoveObject(obj, DLL28B_OBJ_GROUP);
}

void dll_28B_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    Dll28BState* state = obj->extra;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6D18);
        dll_2E_func06(obj, &state->moveLib, 0);
    }
}

void dll_28B_hitDetect_nop(void)
{
}

#pragma opt_common_subs off
#pragma opt_propagation off
void dll_28B_update(GameObject* obj)
{
    f32 oz, oy, ox;
    f32 dt;
    MatrixTransform xform;
    f32 mtx[16];
    Dll28BState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();

    state->playerDistance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
    state->objectFlagsMirror |= OBJFLAG_BIT_2000000;
    dt = timeDelta;
    (*(void (**)(int, int, f32, f32, void*, void*))((char*)*gPlayerInterface + 0x8))(
        (int)obj, (int)state, dt, dt, gDll28BStateHandlers, gDll28BSubstateHandlers);
    if ((state->flagsAC0 & 1) != 0)
    {
        state->moveLib.modeBits &= ~1;
    }
    else
    {
        state->moveLib.modeBits |= 1;
    }
    dll_2E_func03(obj, &state->moveLib);
    characterDoEyeAnimsState(obj, state->eyeAnim);
    xform.x = obj->anim.localPosX;
    xform.y = obj->anim.localPosY;
    xform.z = obj->anim.localPosZ;
    xform.rotX = obj->anim.rotX;
    xform.rotY = obj->anim.rotY;
    xform.rotZ = obj->anim.rotZ;
    xform.scale = lbl_803E6D18;
    setMatrixFromObjectPos(mtx, &xform);
    Matrix_TransformPoint(mtx, gWcEarthWalkerIdleTimerThreshold, gWcEarthWalkerIdleTimerThreshold,
                          gWcEarthWalkerIdleTimerThreshold, &ox, &oy, &oz);
    doNothing_80062A50((int)obj, ox, oy, oz);
}
#pragma opt_common_subs reset
#pragma opt_propagation reset

void dll_28B_init(GameObject* obj)
{
    int curveParam;
    Dll28BMoveBlendData blockA;
    Dll28BMoveBlendData blockB;
    Dll28BState* state = obj->extra;

    blockA = gDll28BMoveBlendDataA;
    blockB = gDll28BMoveBlendDataB;
    curveParam = 2;
    dll_2E_func05(obj, &state->moveLib, -0x2AAA, 0x638E, 8);
    dll_2E_func09(&state->moveLib, &blockB, &blockA, 8);
    state->moveLib.modeBits |= 0x22;
    (*gRomCurveInterface)->initCurve(&state->route, obj, gDll28BCurveInitParam, &curveParam, -1);
    (*(void (**)(int, int, int, int))((char*)*gPlayerInterface + 0x4))((int)obj, (int)state, 4, 4);
    ObjGroup_AddObject((int)obj, DLL28B_OBJ_GROUP);
}

void dll_28B_release_nop(void)
{
}

void dll_28B_initialise(void)
{
    gDll28BStateHandlers[0] = dll_28B_stateHandler0;
    gDll28BStateHandlers[1] = dll_28B_stateHandler1;
    gDll28BStateHandlers[2] = dll_28B_stateHandler2;
    gDll28BStateHandlers[3] = dll_28B_stateHandler3;
    gDll28BSubstateHandlers[0] = dll_28B_substateHandler0;
    gDll28BSubstateHandlers[1] = dll_28B_substateHandler1;
    gDll28BSubstateHandlers[2] = dll_28B_substateHandler2;
    gDll28BSubstateHandlers[3] = dll_28B_substateHandler3;
}
