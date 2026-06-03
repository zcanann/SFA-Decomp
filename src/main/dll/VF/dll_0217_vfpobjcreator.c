#include "main/dll/VF/vf_shared.h"

int vfpobjcreator_getExtraSize(void) { return 0xa; }

int vfpobjcreator_getObjectTypeId(void) { return 0x0; }

void vfpobjcreator_free(void) {}

#pragma peephole off
#pragma scheduling off
void vfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible == 0) return;
}
#pragma scheduling reset
#pragma peephole reset

void vfpobjcreator_hitDetect(void) {}

void vfpobjcreator_release(void) {}

void vfpobjcreator_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpobjcreator_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x1e] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x18);
    *(s16 *)((char *)inner + 2) = *(s16 *)((char *)init + 0x1c);
    *(s16 *)((char *)inner + 4) = *(s16 *)((char *)inner + 2);
    *(s16 *)((char *)inner + 6) = (s8)init[0x1f];
    *(s16 *)((char *)inner + 8) = init[0x20];
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma scheduling reset
#pragma peephole reset

extern u8 Obj_IsLoadingLocked(void);
extern char *Obj_AllocObjectSetup(int size, int typeId);
extern char *Obj_SetupObject(char *setup, int a, int b, int c, int d);
extern void mathFn_80021ac8(s16 *angles, f32 *vec);
extern f32 lbl_803E6068;
extern f32 lbl_803E606C;
extern f32 lbl_803E6070;
extern f32 lbl_803E6074;
extern f32 lbl_803E6078;

/* EN v1.0 0x801F9D78  size: 1068b  Periodically spawns falling-object setups
 * (mode 1) or projectile bursts (mode 6) while loading is locked. */
#pragma peephole off
#pragma scheduling off
void vfpobjcreator_update(int *obj)
{
    char *setup = *(char **)((char *)obj + 0x4c);
    char *st = *(char **)((char *)obj + 0xb8);

    if (Obj_IsLoadingLocked() == 0) {
        return;
    }
    switch (*(s16 *)(setup + 0x1a)) {
    case 0:
        break;
    case 1:
        if ((u32)GameBit_Get(*(s16 *)(st + 0x0)) == 0 && *(s16 *)(st + 0x0) != -1) {
            break;
        }
        *(s16 *)(st + 0x4) -= (s16)timeDelta;
        if (*(s16 *)(st + 0x4) <= 0) {
            char *o;
            char *n;
            *(s16 *)(st + 0x4) = *(s16 *)(st + 0x2);
            o = Obj_AllocObjectSetup(0x28, 0x263);
            *(u8 *)(o + 6) = 0xff;
            *(u8 *)(o + 7) = 0xff;
            o[4] = 2;
            o[5] = 1;
            *(f32 *)(o + 0x8) =
                *(f32 *)((char *)obj + 0xc) +
                (f32)(int)randomGetRange(-*(s16 *)(st + 0x8), *(s16 *)(st + 0x8));
            *(f32 *)(o + 0xc) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(o + 0x10) =
                *(f32 *)((char *)obj + 0x14) +
                (f32)(int)randomGetRange(-*(s16 *)(st + 0x8), *(s16 *)(st + 0x8));
            *(s16 *)(o + 0x20) = 0x50;
            *(s16 *)(o + 0x1e) = (s16)(randomGetRange(0, 2) + 0x16a);
            *(s16 *)(o + 0x22) = -1;
            *(s16 *)(o + 0x18) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            *(s16 *)(o + 0x1a) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            *(s16 *)(o + 0x1c) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            o[0x24] = 0;
            n = Obj_SetupObject(o, 5, *(s8 *)((char *)obj + 0xac), -1,
                                *(int *)((char *)obj + 0x30));
            if (n == NULL) {
                break;
            }
            *(f32 *)(n + 0x28) =
                lbl_803E606C * (f32)(int)randomGetRange(0, 10) + lbl_803E6068;
            *(f32 *)(n + 0x24) = lbl_803E6070 * (f32)(int)randomGetRange(-10, 10);
            *(f32 *)(n + 0x2c) = lbl_803E6070 * (f32)(int)randomGetRange(-10, 10);
        }
        break;
    case 6:
        *(s16 *)(st + 0x4) -= (s16)timeDelta;
        if (*(s16 *)(st + 0x4) <= 0) {
            char *o;
            char *n;
            struct {
                s16 ang[3];
                f32 v[4];
            } m;
            *(s16 *)(st + 0x4) = *(s16 *)(st + 0x2);
            o = Obj_AllocObjectSetup(0x24, 0x549);
            *(f32 *)(o + 0x8) = *(f32 *)(setup + 0x8);
            *(f32 *)(o + 0xc) = *(f32 *)(setup + 0xc);
            *(f32 *)(o + 0x10) = *(f32 *)(setup + 0x10);
            o[4] = setup[4];
            o[5] = setup[5];
            o[6] = setup[6];
            o[7] = setup[7];
            *(s16 *)(o + 0x1e) = -1;
            *(s16 *)(o + 0x20) = -1;
            n = Obj_SetupObject(o, 5, *(s8 *)((char *)obj + 0xac), -1,
                                *(int *)((char *)obj + 0x30));
            if (n == NULL) {
                break;
            }
            *(int *)(n + 0xf8) = 0x1f4;
            {
                f32 a = lbl_803E6074;
                f32 b;
                *(f32 *)(n + 0x28) = a;
                *(f32 *)(n + 0x24) = a;
                b = lbl_803E6078;
                *(f32 *)(n + 0x2c) = b;
                m.v[1] = a;
                m.v[2] = a;
                m.v[3] = a;
                m.v[0] = b;
            }
            m.ang[2] = 0;
            m.ang[1] = 0;
            m.ang[0] = *(s16 *)obj;
            mathFn_80021ac8(m.ang, (f32 *)(n + 0x24));
            Sfx_PlayFromObject((int)n, 0x10c);
            (*(int (*)(char *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                n, 0x39a, 0, 0x10002, -1, 0);
            (*(int (*)(char *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                n, 0x39b, 0, 0x10002, -1, 0);
            (*(int (*)(char *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                n, 0x39c, 0, 0x10002, -1, 0);
        }
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
