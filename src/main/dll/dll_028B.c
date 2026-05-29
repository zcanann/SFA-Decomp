#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int dll_28B_getExtraSize_ret_2756(void) { return 0xac4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int dll_28B_getObjectTypeId(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_28B_hitDetect_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_28B_release_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_28B_free(int obj) { ObjGroup_RemoveObject(obj, 3); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_28B_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D18);
        dll_2E_func06(obj, state + 0x35c, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_28B_update(int obj)
{
    f32 ox, oy, oz;
    ObjXform xform;
    f32 mtx[12];
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();

    *(f32 *)(state + 0xab8) = Vec_xzDistance(obj + 0x18, player + 0x18);
    *(int *)state |= 0x2000000;
    (*(void (**)(int, int, f32, f32, void *, void *))(*gPlayerInterface + 0x8))(
        obj, state, timeDelta, timeDelta, lbl_803AD288, lbl_803AD278);
    if ((*(u8 *)(state + 0xac0) & 1) != 0) {
        *(u8 *)(state + 0x96d) &= ~1;
    } else {
        *(u8 *)(state + 0x96d) |= 1;
    }
    dll_2E_func03(obj, state + 0x35c);
    characterDoEyeAnims(obj, state + 0x980);
    xform.x = *(f32 *)(obj + 0xc);
    xform.y = *(f32 *)(obj + 0x10);
    xform.z = *(f32 *)(obj + 0x14);
    xform.rx = *(s16 *)(obj + 0);
    xform.ry = *(s16 *)(obj + 2);
    xform.rz = *(s16 *)(obj + 4);
    xform.scale = lbl_803E6D18;
    setMatrixFromObjectPos(mtx, &xform);
    Matrix_TransformPoint(mtx, lbl_803E6CF8, lbl_803E6CF8, lbl_803E6CF8, &ox, &oy, &oz);
    doNothing_80062A50(obj, ox, oy, oz);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_28B_init(int obj)
{
    int two;
    Blob16 blockA;
    Blob16 blockB;
    int state = *(int *)(obj + 0xb8);

    blockA = *(Blob16 *)lbl_802C25B8;
    blockB = *(Blob16 *)lbl_802C25C8;
    two = 2;
    dll_2E_func05(obj, state + 0x35c, -0x2aaa, 0x638e, 8);
    dll_2E_func09(state + 0x35c, &blockB, &blockA, 8);
    *(u8 *)(state + 0x96d) |= 0x22;
    (*(void (**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
        state + 0x9b0, obj, lbl_803E6D1C, &two, -1);
    (*(void (**)(int, int, int, int))(*gPlayerInterface + 0x4))(obj, state, 4, 4);
    ObjGroup_AddObject(obj, 3);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
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
#pragma scheduling reset
#pragma peephole reset
