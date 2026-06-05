#include "main/dll/dll_80220608_shared.h"

#include "main/audio/sfx_ids.h"
#pragma peephole on
#pragma scheduling on
int drlightbea_getExtraSize(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drlightbea_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drlightbea_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *buffer = *(void **)state;

    if (buffer != NULL) {
        mm_free(buffer);
        *(void **)state = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drlightbea_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void drlightbea_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (((DrLightBeaFlags *)(state + 4))->bit40) {
        Obj_FreeObject(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drlightbea_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((DrLightBeaFlags *)(state + 4))->bit80 = 0;
    *(void **)state = NULL;
    ((DrLightBeaFlags *)(state + 4))->bit40 = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drlightbea_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drlightbea_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void drlightbea_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    int player;
    f32 buf[6];
    f32 vecA[3];
    f32 vecB[3];

    if (((DrLightBeaFlags *)(state + 4))->bit80) {
        *(f32 *)(*(int *)state + 0) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(int *)state + 4) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(int *)state + 8) = *(f32 *)(obj + 0x14);
        if (*(s8 *)(setup + 0x19) == 0) {
            player = Obj_GetPlayerObject();
            *(f32 *)(*(int *)state + 0xc) = *(f32 *)(player + 0xc);
            *(f32 *)(*(int *)state + 0x10) = lbl_803E6BB8 + *(f32 *)(player + 0x10);
            *(f32 *)(*(int *)state + 0x14) = *(f32 *)(player + 0x14);
        }
        renderFn_8008f904(*(void **)state);
        *(u16 *)(*(int *)state + 0x20) += 1;
        if (*(u16 *)(*(int *)state + 0x20) >= *(u16 *)(*(int *)state + 0x22)) {
            mm_free(*(void **)state);
            *(int *)state = 0;
            ((DrLightBeaFlags *)(state + 4))->bit80 = 0;
            if (*(u32 *)(setup + 0x14) == 0xffffffff) {
                ((DrLightBeaFlags *)(state + 4))->bit40 = 1;
            }
        }
    } else {
        if (*(void **)state != NULL) {
            mm_free(*(void **)state);
            *(int *)state = 0;
        }
        ((DrLightBeaFlags *)(state + 4))->bit80 = (u8)GameBit_Get(*(s16 *)(setup + 0x20));
        if (((DrLightBeaFlags *)(state + 4))->bit80) {
            Sfx_PlayFromObject(obj, SFXfend_pep_snoreout);
            vecA[0] = *(f32 *)(obj + 0xc);
            vecA[1] = *(f32 *)(obj + 0x10);
            vecA[2] = *(f32 *)(obj + 0x14);
            if (*(s8 *)(setup + 0x19) != 0 && dll_2E_func0A(*(s8 *)(setup + 0x19), buf) != 0) {
                vecB[0] = buf[3];
                vecB[1] = buf[4];
                vecB[2] = buf[5];
            } else {
                player = Obj_GetPlayerObject();
                vecB[0] = *(f32 *)(player + 0xc);
                vecB[1] = lbl_803E6BB8 + *(f32 *)(player + 0x10);
                vecB[2] = *(f32 *)(player + 0x14);
            }
            *(void **)state = fn_8008FB20(vecA, vecB, lbl_803E6BBC, lbl_803E6BC0,
                                         (u16)randomGetRange(5, 0xf), 0x60, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
