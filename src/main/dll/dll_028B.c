#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct Dll28BState {
    u8 pad0[0x96D - 0x0];
    u8 flags96D;
    u8 pad96E[0xAB8 - 0x96E];
    f32 unkAB8;
    u8 padABC[0xAC0 - 0xABC];
    u8 unkAC0;
    u8 padAC1[0xAC8 - 0xAC1];
} Dll28BState;


int dll_28B_getExtraSize_ret_2756(void) { return 0xac4; }

int dll_28B_getObjectTypeId(void) { return 0x0; }

void dll_28B_hitDetect_nop(void) {}

void dll_28B_release_nop(void) {}

void dll_28B_free(int obj) { ObjGroup_RemoveObject(obj, 3); }

void dll_28B_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D18);
        dll_2E_func06(obj, state + 0x35c, 0);
    }
}

void dll_28B_update(int obj)
{
    f32 oz, oy, ox;
    ObjXform xform;
    f32 mtx[16];
    int state = *(int *)&((GameObject *)obj)->extra;
    int player = Obj_GetPlayerObject();

    ((Dll28BState *)state)->unkAB8 = Vec_xzDistance(obj + 0x18, player + 0x18);
    *(int *)state |= 0x2000000;
    (*(void (**)(int, int, f32, f32, void *, void *))(*gPlayerInterface + 0x8))(
        obj, state, timeDelta, timeDelta, lbl_803AD288, lbl_803AD278);
    if ((((Dll28BState *)state)->unkAC0 & 1) != 0) {
        ((Dll28BState *)state)->flags96D &= ~1;
    } else {
        ((Dll28BState *)state)->flags96D |= 1;
    }
    dll_2E_func03(obj, state + 0x35c);
    characterDoEyeAnims(obj, state + 0x980);
    xform.x = ((GameObject *)obj)->anim.localPosX;
    xform.y = ((GameObject *)obj)->anim.localPosY;
    xform.z = ((GameObject *)obj)->anim.localPosZ;
    xform.rx = ((GameObject *)obj)->anim.rotX;
    xform.ry = ((GameObject *)obj)->anim.rotY;
    xform.rz = ((GameObject *)obj)->anim.rotZ;
    xform.scale = lbl_803E6D18;
    setMatrixFromObjectPos(mtx, &xform);
    Matrix_TransformPoint(mtx, lbl_803E6CF8, lbl_803E6CF8, lbl_803E6CF8, &ox, &oy, &oz);
    doNothing_80062A50(obj, ox, oy, oz);
}

void dll_28B_init(int obj)
{
    int two;
    Blob16 blockA;
    Blob16 blockB;
    int state = *(int *)&((GameObject *)obj)->extra;

    blockA = *(Blob16 *)lbl_802C25B8;
    blockB = *(Blob16 *)lbl_802C25C8;
    two = 2;
    dll_2E_func05(obj, state + 0x35c, -0x2aaa, 0x638e, 8);
    dll_2E_func09(state + 0x35c, &blockB, &blockA, 8);
    ((Dll28BState *)state)->flags96D |= 0x22;
    (*gRomCurveInterface)->initCurve((void *)(state + 0x9b0), (void *)obj, lbl_803E6D1C, &two, -1);
    (*(void (**)(int, int, int, int))(*gPlayerInterface + 0x4))(obj, state, 4, 4);
    ObjGroup_AddObject(obj, 3);
}

void dll_28B_initialise(void)
{
    lbl_803AD288[0] = (void *)fn_80223D10;
    lbl_803AD288[1] = (void *)fn_80223CF0;
    lbl_803AD288[2] = (void *)fn_80223C34;
    lbl_803AD288[3] = (void *)fn_80223BC4;
    lbl_803AD278[0] = (void *)fn_80223BBC;
    lbl_803AD278[1] = (void *)fn_80223AFC;
    lbl_803AD278[2] = (void *)fn_80223A1C;
    lbl_803AD278[3] = (void *)fn_802239A4;
}
