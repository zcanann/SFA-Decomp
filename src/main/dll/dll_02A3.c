#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#pragma peephole on
#pragma scheduling on
int dll_2A3_getExtraSize_ret_12(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int dll_2A3_getObjectTypeId(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_release_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_initialise_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_free(void) { lbl_803DDD90 = lbl_803DDD90 - 1; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7118);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_hitDetect(void) { lbl_803DDD94 = 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_2A3_update(int obj)
{
    f32 thr;
    f32 v;
    int state = *(int *)&((GameObject *)obj)->extra;

    if (*(f32 *)state > (thr = lbl_803E711C)) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= thr) {
            *(f32 *)state = thr;
            Obj_FreeObject(obj);
            return;
        }
    }

    v = (f32)(u32)((GameObject *)obj)->anim.alpha;
    v = lbl_803E7120 * timeDelta + v;
    if (v > lbl_803E7124) {
        v = lbl_803E7124;
    }
    ((GameObject *)obj)->anim.alpha = (u8)v;

    ((GameObject *)obj)->anim.rotX = (s16)((f32) * (s16 *)(state + 4) * timeDelta + (f32) * (s16 *)(obj + 0));
    ((GameObject *)obj)->anim.rotY = (s16)((f32) * (s16 *)(state + 6) * timeDelta + (f32) * (s16 *)(obj + 2));
    ((GameObject *)obj)->anim.rotZ = (s16)((f32) * (s16 *)(state + 8) * timeDelta + (f32) * (s16 *)(obj + 4));

    objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta,
            ((GameObject *)obj)->anim.velocityZ * timeDelta);

    if (lbl_803DDD94 == 0) {
        lbl_803DDD94 = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_2A3_init(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;

    ((GameObject *)obj)->anim.alpha = 0;
    ((GameObject *)obj)->anim.rotX = randomGetRange(0, 0xffff);
    ((GameObject *)obj)->anim.rotY = randomGetRange(0, 0xffff);
    ((GameObject *)obj)->anim.rotZ = randomGetRange(0, 0xffff);
    *(s16 *)(state + 4) = randomGetRange(-0x32, 0x32);
    *(s16 *)(state + 6) = randomGetRange(-0x32, 0x32);
    *(s16 *)(state + 8) = randomGetRange(-0x32, 0x32);
    lbl_803DDD90 = lbl_803DDD90 + 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8023137C(int obj, int src)
{
    ((GameObject *)obj)->anim.velocityX = *(f32 *)(src + 0x0);
    ((GameObject *)obj)->anim.velocityY = *(f32 *)(src + 0x4);
    ((GameObject *)obj)->anim.velocityZ = *(f32 *)(src + 0x8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8023134C(int obj, int v) { *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x0) = (f32)v; }
#pragma scheduling reset
#pragma peephole reset
