#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int arwspeedstr_getExtraSize(void) { return 0x1c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwspeedstr_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwspeedstr_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwspeedstr_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwspeedstr_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7100);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwspeedstr_init(int obj, int setup)
{
    *(u8 *)(obj + 0x36) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwspeedstr_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwspeedstr_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwspeedstr_update(int obj) {
    int state = *(int *)(obj + 0xb8);
    if (*(u8 *)(state + 0x18) == 0) {
        f32 local[3];
        local[0] = (f32)(int)randomGetRange((int)-*(f32 *)(state + 0xc), (int)*(f32 *)(state + 0xc));
        local[1] =
            (f32)(int)randomGetRange((int)-*(f32 *)(state + 0x10), (int)*(f32 *)(state + 0x10));
        local[2] = *(f32 *)(state + 0x14);
        PSMTXMultVec(Camera_GetInverseViewMatrix(), &local[0], (f32 *)(obj + 0xc));
        *(f32 *)(obj + 0xc) += playerMapOffsetX;
        *(f32 *)(obj + 0x14) += playerMapOffsetZ;
        *(u8 *)(state + 0x18) = (*(u8 *)(state + 0x18) | 1) & 0xff;
        *(f32 *)(state + 8) = lbl_803E7104;
    }
    {
        f32 t = *(f32 *)(state + 4);
        if (t > lbl_803E7104) {
            *(f32 *)(state + 4) = t - timeDelta;
            if (*(f32 *)(state + 4) <= lbl_803E7104) {
                *(f32 *)(state + 4) = lbl_803E7104;
                Obj_FreeObject(obj);
            } else {
                objMove(obj, lbl_803E7104, lbl_803E7104, *(f32 *)(state + 0) * timeDelta);
                *(f32 *)(state + 8) = lbl_803E7108 * timeDelta + *(f32 *)(state + 8);
                if (*(f32 *)(state + 8) > lbl_803E710C)
                    *(f32 *)(state + 8) = lbl_803E710C;
                *(u8 *)(obj + 0x36) = (int)*(f32 *)(state + 8);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_80231058(int obj, int src)
{
    *(f32 *)(obj + 0x24) = *(f32 *)(src + 0x0);
    *(f32 *)(obj + 0x28) = *(f32 *)(src + 0x4);
    *(f32 *)(obj + 0x2c) = *(f32 *)(src + 0x8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_80231028(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }
#pragma scheduling reset
#pragma peephole reset
