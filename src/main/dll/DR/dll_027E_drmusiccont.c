#include "main/dll/dll_80220608_shared.h"

#define SFXmn_sml_trex_fstep 126
#define SFXsp_lf_mutter4 265

#pragma peephole on
#pragma scheduling on
int drmusiccont_getExtraSize(void) { return 4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drmusiccont_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drmusiccont_free(int obj) { fn_8009436C(obj); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6BC8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drmusiccont_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drmusiccont_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drmusiccont_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drmusiccont_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    DrMusicContFlags *f = (DrMusicContFlags *)(state + 0x8);

    f->b_e30 = (u8)GameBit_Get(0xe30);
    f->b_e31 = (u8)GameBit_Get(0xe31);
    f->b_e32 = (u8)GameBit_Get(0xe32);
    f->b_e33 = (u8)GameBit_Get(0xe33);
    f->b_e9c = (u8)GameBit_Get(0xe9c);
    f->b_e38 = (u8)GameBit_Get(0xe38);
    f->b_e3c = (u8)GameBit_Get(0xe3c);
    f->b_e3d = (u8)GameBit_Get(0xe3d);
    f->b_e3e = (u8)GameBit_Get(0xe3e);
    f->b_e39 = (u8)GameBit_Get(0xe39);
    f->b_9e0 = (u8)GameBit_Get(0x9e0);
    f->b_9e1 = (u8)GameBit_Get(0x9e1);
    f->b_9e2 = (u8)GameBit_Get(0x9e2);
    f->b_9e7 = (u8)GameBit_Get(0x9e7);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void drmusiccont_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    DrMusicContFlags *f = (DrMusicContFlags *)(state + 0x8);
    u32 a;
    u32 b;
    u32 c;
    u32 d;

    fn_80094378(obj, lbl_803E6BCC, lbl_803E6BD0, lbl_803E6BD4);
    if (*(int *)(obj + 0xf4) == 0) {
        if ((u32)GameBit_Get(0xe7b) == 0) {
            getEnvfxActImmediately(obj, obj, 0x210, 0);
            getEnvfxActImmediately(obj, obj, 0x20f, 0);
            getEnvfxActImmediately(obj, obj, 0x212, 0);
            getEnvfxActImmediately(obj, obj, 0x1ea, 0);
            skyFn_80088e54(0, lbl_803E6BD8);
            GameBit_Set(0xe7b, 1);
        }
        *(int *)(obj + 0xf4) = 1;
    }

    SCGameBitLatch_Update(state, 2, 0x1a7, 0x64b, 0xf0e, 0xe5);
    SCGameBitLatch_UpdateInverted(state, 1, -1, -1, 0xe26, 0xb8);
    SCGameBitLatch_Update(state, 4, -1, -1, 0xcbb, 0xc4);

    a = (u8)GameBit_Get(0xe30);
    b = (u8)GameBit_Get(0xe31);
    c = (u8)GameBit_Get(0xe32);
    d = (u8)GameBit_Get(0xe33);
    if (f->b_e9c == 0 && a && b && c && d) {
        f->b_e9c = 1;
        GameBit_Set(0xe9c, 1);
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
    } else if (a != f->b_e30 || b != f->b_e31 || c != f->b_e32 || d != f->b_e33) {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    f->b_e30 = a;
    f->b_e31 = b;
    f->b_e32 = c;
    f->b_e33 = d;

    a = (u8)GameBit_Get(0xe38);
    b = (u8)GameBit_Get(0xe3c);
    c = (u8)GameBit_Get(0xe3d);
    d = (u8)GameBit_Get(0xe3e);
    if (f->b_e39 == 0 && a && b && c && d) {
        f->b_e39 = 1;
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
    } else if (a != f->b_e38 || b != f->b_e3c || c != f->b_e3d || d != f->b_e3e) {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    f->b_e38 = a;
    f->b_e3c = b;
    f->b_e3d = c;
    f->b_e3e = d;

    a = (u8)GameBit_Get(0x9e0);
    b = (u8)GameBit_Get(0x9e1);
    c = (u8)GameBit_Get(0x9e2);
    d = (u8)GameBit_Get(0x9e7);
    if (!(a && b && c && d)) {
        if (a != f->b_9e0 || b != f->b_9e1 || c != f->b_9e2 || d != f->b_9e7) {
            *(f32 *)(state + 4) = lbl_803E6BDC;
        }
    }
    {
        f32 zero = lbl_803E6BD8;
        if (*(f32 *)(state + 4) > zero) {
            *(f32 *)(state + 4) = *(f32 *)(state + 4) - timeDelta;
            if (*(f32 *)(state + 4) <= zero) {
                Sfx_PlayFromObject(0, 0x4bd);
            }
        }
    }
    f->b_9e0 = a;
    f->b_9e1 = b;
    f->b_9e2 = c;
    f->b_9e7 = d;

    if (f->b_state != 0) {
        if ((u32)GameBit_Get(0x9f0) == 0 || (u32)GameBit_Get(0x632) != 0) {
            (*(void (**)(void))(*gMapEventInterface + 0x2c))();
            f->b_state = 0;
        }
    } else {
        if ((u32)GameBit_Get(0x9f0) != 0 && (u32)GameBit_Get(0x632) == 0) {
            f32 vec[3];
            vec[0] = lbl_803E6BE0;
            vec[1] = lbl_803E6BE4;
            vec[2] = lbl_803E6BE8;
            (*(void (**)(f32 *, int, int, int))(*gMapEventInterface + 0x24))(vec, 0x7fff, 0, 0);
            f->b_state = 1;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
