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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define DLL28B_OBJ_GROUP 3
#define OBJFLAG_BIT_2000000 0x2000000

typedef struct Dll28BState
{
    int objectFlagsMirror;  /* 0x00: receives OBJFLAG_BIT_2000000 each update */
    u8 pad4[0x35C - 0x4];
    u8 moveLib[0x96D - 0x35C]; /* 0x35C: dll_2E (moveLib) look-at/turn block */
    u8 flags96D;            /* 0x96D: bit0 mirrors !(flagsAC0 & 1); 0x22 set at init */
    u8 pad96E[0x980 - 0x96E];
    u8 eyeAnim[0x9B0 - 0x980]; /* 0x980: eye-animation block */
    RomCurveWalker route;      /* 0x9B0: ROM-curve walker */
    f32 playerDistance;     /* 0xAB8: planar distance to the player object */
    u8 padABC[0xAC0 - 0xABC];
    u8 flagsAC0;            /* 0xAC0: bit0 drives flags96D bit0 */
    u8 padAC1[0xAC4 - 0xAC1];
} Dll28BState;

STATIC_ASSERT(sizeof(Dll28BState) == 0xAC4);
STATIC_ASSERT(offsetof(Dll28BState, moveLib) == 0x35C);
STATIC_ASSERT(offsetof(Dll28BState, eyeAnim) == 0x980);
STATIC_ASSERT(offsetof(Dll28BState, route) == 0x9B0);
STATIC_ASSERT(offsetof(Dll28BState, playerDistance) == 0xAB8);
STATIC_ASSERT(offsetof(Dll28BState, flagsAC0) == 0xAC0);

int dll_28B_getExtraSize(void) { return sizeof(Dll28BState); }

int dll_28B_getObjectTypeId(void) { return 0x0; }

void dll_28B_hitDetect_nop(void)
{
}

void dll_28B_release_nop(void)
{
}

void dll_28B_free(int obj) { ObjGroup_RemoveObject(obj, DLL28B_OBJ_GROUP); }

void dll_28B_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6D18);
        dll_2E_func06(obj, (int)((Dll28BState*)state)->moveLib, 0);
    }
}

void dll_28B_update(int obj)
{
    f32 oz, oy, ox;
    ObjXform xform;
    f32 mtx[16];
    int state = *(int*)&((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();

    ((Dll28BState*)state)->playerDistance = Vec_xzDistance(obj + 0x18, player + 0x18);
    ((Dll28BState*)state)->objectFlagsMirror |= OBJFLAG_BIT_2000000;
    (*(void (**)(int, int, f32, f32, void*, void*))(*gPlayerInterface + 0x8))(
        obj, state, timeDelta, timeDelta, gDll28BStateHandlers, gDll28BSubstateHandlers);
    if ((((Dll28BState*)state)->flagsAC0 & 1) != 0)
    {
        ((Dll28BState*)state)->flags96D &= ~1;
    }
    else
    {
        ((Dll28BState*)state)->flags96D |= 1;
    }
    dll_2E_func03(obj, (int)((Dll28BState*)state)->moveLib);
    characterDoEyeAnims(obj, (int)((Dll28BState*)state)->eyeAnim);
    xform.x = ((GameObject*)obj)->anim.localPosX;
    xform.y = ((GameObject*)obj)->anim.localPosY;
    xform.z = ((GameObject*)obj)->anim.localPosZ;
    xform.rx = ((GameObject*)obj)->anim.rotX;
    xform.ry = ((GameObject*)obj)->anim.rotY;
    xform.rz = ((GameObject*)obj)->anim.rotZ;
    xform.scale = lbl_803E6D18;
    setMatrixFromObjectPos(mtx, &xform);
    Matrix_TransformPoint(mtx, 0.0f, 0.0f, 0.0f, &ox, &oy, &oz);
    doNothing_80062A50(obj, ox, oy, oz);
}

void dll_28B_init(int obj)
{
    int curveParam;
    Blob16 blockA;
    Blob16 blockB;
    int state = *(int*)&((GameObject*)obj)->extra;

    blockA = *(Blob16*)gDll28BMoveBlendDataA;
    blockB = *(Blob16*)gDll28BMoveBlendDataB;
    curveParam = 2;
    dll_2E_func05(obj, state + 0x35C, -0x2AAA, 0x638E, 8);
    dll_2E_func09(state + 0x35C, &blockB, &blockA, 8);
    ((Dll28BState*)state)->flags96D |= 0x22;
    (*gRomCurveInterface)->initCurve((void*)(state + 0x9B0), (void*)obj, gDll28BCurveInitParam, &curveParam, -1);
    (*(void (**)(int, int, int, int))(*gPlayerInterface + 0x4))(obj, state, 4, 4);
    ObjGroup_AddObject(obj, DLL28B_OBJ_GROUP);
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
