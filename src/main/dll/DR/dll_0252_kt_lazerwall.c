#include "main/dll/DR/dr_shared.h"

#define SFXmn_sml_trex_snap3 130
#define SFXmv_bflconc1 131
#define SFXmv_blkhit_c 132

int ktlazerwall_getExtraSize(void) { return 0x14; }

int ktlazerwall_getObjectTypeId(void) { return 0x0; }

void ktlazerwall_hitDetect(void) {}

void ktlazerwall_initialise(void) {}

void ktlazerwall_release(void) {}

#pragma scheduling off
#pragma peephole off
void ktlazerwall_free(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    void *m = *(void **)(p + 0x10);
    if (m != 0) {
        mm_free(m);
        *(void **)(p + 0x10) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktlazerwall_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(f32 *)(p + 0x4) = lbl_803E6898;
    *(f32 *)(p + 0xc) = lbl_803E68BC * (f32)(int)randomGetRange(0x50, 0x78);
    if ((s32)randomGetRange(0, 1) != 0) {
        *(f32 *)(p + 0xc) = -*(f32 *)(p + 0xc);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktlazerwall_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    u8 *runtime = *(u8 **)((char *)obj + 0xb8);
    int cur;
    int mode;
    int i;
    runtime[1] = runtime[0];
    runtime[0] &= ~3;
    cur = (s16)GameBit_Get(*(s16 *)(q + 0x1a));
    if (cur >= *(s16 *)(q + 0x1c)) {
        runtime[0] |= 4;
    } else {
        runtime[0] &= ~4;
        if (GameBit_Get(*(s16 *)(q + 0x1e)) == 0) {
            return;
        }
    }
    *(s16 *)((char *)obj + 4) += 910;
    if (cur >= 15 && (runtime[0] & 9) == 0) {
        GameBit_Set(*(s16 *)(q + 0x1e), 1);
        runtime[0] |= 9;
        ktrexfloorswitch_spawnEnergyArc(obj, lbl_803E68B8, 120);
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1150, 0, 2, -1, 0);
        for (i = 10; i != 0; i--) {
            mode = 2;
            (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        }
        *(f32 *)(runtime + 4) = (f32)(int)randomGetRange(1, 60);
    }
    if (runtime[0] & 4) {
        mode = 0;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        mode = 1;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        if ((runtime[1] & 4) == 0) {
            Sfx_PlayFromObject(obj, SFXmn_sml_trex_snap3);
        }
    }
    if (runtime[0] & 8) {
        mode = 0;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        mode = 2;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
    }
    if ((runtime[0] & 8) == 0 && (runtime[1] & 8) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_blkhit_c);
    }
    if (*(f32 *)(runtime + 4) > lbl_803E6898) {
        *(f32 *)(runtime + 4) -= timeDelta;
        if (*(f32 *)(runtime + 4) <= lbl_803E6898) {
            Sfx_PlayFromObject(obj, SFXmv_bflconc1);
            *(f32 *)(runtime + 4) = lbl_803E6898;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktlazerwall_render(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    int m;
    if (*(void **)(p + 0x10) != 0) {
        *(f32 *)(p + 0x8) -= timeDelta;
        if (*(f32 *)(p + 0x8) <= lbl_803E6898) {
            f32 t = lbl_803E68B0 * *(f32 *)(p + 0xc);
            m = *(int *)(p + 0x10);
            *(f32 *)(m + 0x10) = *(f32 *)(m + 0x10) - t * lbl_803E68B4;
            *(f32 *)(p + 0x8) = (f32)(int)randomGetRange(0xa, 0x78);
        } else {
            m = *(int *)(p + 0x10);
            *(f32 *)(m + 0x10) = *(f32 *)(p + 0xc) * timeDelta + *(f32 *)(m + 0x10);
        }
        renderFn_8008f904(*(void **)(p + 0x10));
        *(u16 *)(*(int *)(p + 0x10) + 0x20) += framesThisStep;
        m = *(int *)(p + 0x10);
        if (*(u16 *)(m + 0x20) >= *(u16 *)(m + 0x22)) {
            mm_free((void *)m);
            *(int *)(p + 0x10) = 0;
            *(u8 *)p &= ~8;
            GameBit_Set(*(s16 *)(q + 0x1e), 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
