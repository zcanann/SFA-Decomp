#include "ghidra_import.h"
#include "main/dll/CF/CFTreasSharpy.h"
#include "main/objanim.h"

extern undefined4 FUN_80017a78();
extern undefined4 FUN_800305f8();

extern u32 GameBit_Get(int bit);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern u32 randomGetRange(int min, int max);
extern void CFCrate_SeqFn(void);

extern undefined4 gCameraInterface;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e4ac0;
extern f32 FLOAT_803e4a70;
extern f32 FLOAT_803e4a84;
extern f32 FLOAT_803e4a8c;
extern f32 FLOAT_803e4a94;
extern f32 FLOAT_803e4ac8;
extern f32 FLOAT_803e4acc;
extern f32 FLOAT_803e4ad0;
extern f32 FLOAT_803e4ad4;
extern f32 FLOAT_803e4ad8;
extern f32 FLOAT_803e4ae0;

extern void *lbl_803DBDE8;
extern void *gExpgfxInterface;
extern void *gModgfxInterface;
extern void *gPartfxInterface;
extern u8 framesThisStep;
extern f32 lbl_803E3E48;
extern char sCFTreasSharpyDebugFormat[];
extern void fn_80137948(char *fmt, int obj, f32 x, f32 z);
extern void *Resource_Acquire(int id, int flags);
extern void Resource_Release(void *resource);

extern f32 lbl_803E3DD8;
extern f32 lbl_803E3DEC;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DFC;
extern f64 lbl_803E3E28;
extern f32 lbl_803E3E30;
extern f32 lbl_803E3E34;
extern f32 lbl_803E3E38;
extern f32 lbl_803E3E3C;
extern f32 lbl_803E3E40;

/*
 * --INFO--
 *
 * Function: cfccrate_init
 * EN v1.0 Address: 0x8018E0A4
 * EN v1.0 Size: 1560b
 */
#pragma scheduling off
#pragma peephole off
void cfccrate_init(int obj, int aux)
{
    int state;
    short id;
    f32 zeroF;

    id = *(short *)(aux + 0x0);
    state = *(int *)(obj + 0xb8);
    zeroF = lbl_803E3DD8;
    *(f32 *)(state + 0x2c) = zeroF;

    switch (id) {
    case 0x2bb:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        *(short *)(obj + 4) = *(short *)(aux + 0x1c);
        *(f32 *)(obj + 8) = zeroF;
        break;
    case 0x1d0:
    case 0x1d1:
    case 0x1d7:
    case 0x1e6:
    case 0x201:
    case 0x23b:
    case 0x492:
    case 0x78b:
    case 0x78c:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        break;
    case 0x726:
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        break;
    case 0x71b:
        *(short *)(state + 0x36) = *(short *)(aux + 0x1a);
        break;
    case 0x6be:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(u8 *)(state + 0x3e) = 0;
        *(short *)(state + 0x3a) = *(short *)(aux + 0x20);
        break;
    case 0x828:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(u8 *)(state + 0x3e) = 0;
        *(short *)(state + 0x3a) = *(short *)(aux + 0x20);
        if ((GameBit_Get(*(short *)(state + 0x3a)) != 0) && (*(u8 *)(state + 0x3e) == 0)) {
            *(short *)(obj + 4) = 0x7fff;
            *(u8 *)(state + 0x3e) = 1;
        }
        break;
    case 0x6bf:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        *(short *)(state + 0x3a) = *(short *)(aux + 0x20);
        break;
    case 0x708:
        *(s8 *)(obj + 0xad) = (s8)*(short *)(aux + 0x1a);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        if ((s8)*(u8 *)(obj + 0xad) >= 3) {
            *(s8 *)(obj + 0xad) = 0;
        }
        Obj_SetActiveModelIndex(obj, *(s8 *)(obj + 0xad));
        break;
    case 0x6fc:
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        break;
    case 0x622:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        break;
    case 0x6b4:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E3E30, 0);
        break;
    case 0x66c:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        break;
    case 0x216:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        break;
    case 0x4bf:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(u8 *)(obj + 0xad) = *(u8 *)(aux + 0x19);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        if (GameBit_Get(*(short *)(state + 0x38)) != 0) {
            *(f32 *)(obj + 0x10) = lbl_803E3DFC + *(f32 *)(aux + 0xc);
        }
        break;
    case 0x8e:
        *(short *)(obj + 0) = 0;
        *(short *)(obj + 2) = 0;
        if (*(short *)(aux + 0x1c) >= 0x3e8) {
            *(f32 *)(obj + 8) = zeroF / ((f32)(s32)*(short *)(aux + 0x1c) / lbl_803E3DF4);
        } else {
            *(f32 *)(obj + 8) = lbl_803E3E34;
        }
        *(u8 *)(state + 0x3e) = 0;
        *(f32 *)(state + 0x4) = *(f32 *)(aux + 0x8);
        *(f32 *)(state + 0x8) = *(f32 *)(aux + 0xc);
        *(f32 *)(state + 0xc) = *(f32 *)(aux + 0x10);
        *(f32 *)(state + 0x14) = *(f32 *)(state + 0x18) = lbl_803E3E30;
        *(f32 *)(state + 0x28) = lbl_803E3DF4;
        *(f32 *)(state + 0x20) = lbl_803E3E38;
        *(f32 *)(state + 0x1c) = *(f32 *)(state + 0x24) = lbl_803E3DEC;
        *(short *)(obj + 4) = 0;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x7de:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = 0;
        if (*(short *)(aux + 0x1c) >= 0x3e8) {
            *(f32 *)(obj + 8) = zeroF / ((f32)(s32)*(short *)(aux + 0x1c) / lbl_803E3DF4);
        } else {
            *(f32 *)(obj + 8) = zeroF;
        }
        *(f32 *)(state + 0x24) = (f32)(s32)*(short *)(aux + 0x1a);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        if (GameBit_Get(*(short *)(state + 0x38)) != 0) {
            *(f32 *)(state + 0x24) = *(f32 *)(state + 0x24) * lbl_803E3E3C;
        }
        break;
    case 0xd7:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(f32 *)(obj + 8) = zeroF;
        *(u8 *)(state + 0x3e) = 0;
        *(f32 *)(state + 0x4) = *(f32 *)(aux + 0x8);
        *(f32 *)(state + 0x8) = *(f32 *)(aux + 0xc);
        *(f32 *)(state + 0xc) = *(f32 *)(aux + 0x10);
        *(f32 *)(state + 0x1c) = *(f32 *)(state + 0x24) = *(f32 *)(state + 0x20) = *(f32 *)(state + 0x28) = *(f32 *)(state + 0x14) = *(f32 *)(state + 0x18) = lbl_803E3E30;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x125:
        *(short *)(obj + 0) = 0;
        *(short *)(obj + 2) = 0;
        *(short *)(obj + 4) = 0;
        *(f32 *)(obj + 8) = zeroF;
        *(int *)(obj + 0xf4) = 0;
        *(int *)(obj + 0xf8) = 0;
        *(f32 *)(state + 0x24) = lbl_803E3E40;
        *(f32 *)(state + 0x1c) = lbl_803E3DEC;
        *(short *)(state + 0x32) = 0;
        *(short *)(state + 0x34) = (short)randomGetRange(0x3e8, 0x1388);
        *(u8 *)(state + 0x3f) = 1;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x10d:
        *(int *)(obj + 0x54) = 0;
        if (*(short *)(aux + 0x1a) == 0) {
            *(int *)(state + 0x44) = (int)&lbl_803DBDE8;
            *(u8 *)(state + 0x40) = 1;
        }
        *(u16 *)(state + 0x48) = (u16)*(short *)(aux + 0x1c);
        *(short *)(state + 0x3c) = (short)*(u16 *)(state + 0x48);
        break;
    }
}

typedef struct CFTreasSharpyFxSpawnArgs {
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CFTreasSharpyFxSpawnArgs;

#define CFTREAS_PARTFX_SPAWN(obj, id, data, flags, model, arg) \
    ((void (*)(int, int, void *, int, int, int))(*(int *)(*(int *)gPartfxInterface + 8)))(obj, id, data, flags, model, arg)

#pragma scheduling off
#pragma peephole off
void fxemit_emitEffect(int obj)
{
    u8 *state;
    u8 *def;
    int spawnFlags;
    s16 mode;
    s16 count;
    s16 i;
    void *resource;

    state = *(u8 **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    spawnFlags = 0;
    if (*(s16 *)(state + 0xa) == 0x11) {
        fn_80137948(sCFTreasSharpyDebugFormat, obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14));
    }

    mode = *(s16 *)(state + 8);
    switch (def[0x28]) {
    case 0:
        if (mode == 0 || mode == 1 || mode == 2) {
            spawnFlags = 2;
        }
        break;
    case 1:
        if (mode == 0 || mode == 1 || mode == 2) {
            spawnFlags = 4;
        }
        break;
    case 2:
        if (mode == 0) {
            spawnFlags = 0x200001;
        }
        if (mode == 1 || mode == 2) {
            spawnFlags = 1;
        }
        break;
    case 3:
        spawnFlags = 0;
        break;
    default:
        spawnFlags = 2;
        break;
    }

    count = *(s16 *)(state + 0xe);
    if ((spawnFlags & 1) != 0) {
        CFTreasSharpyFxSpawnArgs args;

        args.x = *(f32 *)(obj + 0xc);
        args.y = *(f32 *)(obj + 0x10);
        args.z = *(f32 *)(obj + 0x14);
        args.yaw = *(s16 *)obj;
        args.pitch = *(s16 *)(obj + 2);
        args.roll = *(s16 *)(obj + 4);
        args.scale = lbl_803E3E48;
        if (count < 1) {
            CFTREAS_PARTFX_SPAWN(obj, *(s16 *)(state + 0xc), &args, spawnFlags, -1, 0);
        } else {
            for (i = 0; i < count; i++) {
                CFTREAS_PARTFX_SPAWN(obj, *(s16 *)(state + 0xa), &args, spawnFlags, -1, 0);
            }
        }
    } else {
        switch (mode) {
        case 0:
            if (count < 1) {
                CFTREAS_PARTFX_SPAWN(obj, *(s16 *)(state + 0xa), NULL, spawnFlags, -1, 0);
            } else {
                for (i = 0; i < count; i++) {
                    CFTREAS_PARTFX_SPAWN(obj, *(s16 *)(state + 0xa), NULL, spawnFlags, -1, 0);
                }
            }
            break;
        case 1:
            resource = Resource_Acquire((u16)(*(s16 *)(state + 0xa) + 0x58), 1);
            if (count < 1) {
                ((void (*)(int, int, int, int, int, int))((void **)*(int *)resource)[1])(obj, 0, 0, spawnFlags, -1, 0);
            } else {
                for (i = 0; i < count; i++) {
                    ((void (*)(int, int, int, int, int, int))((void **)*(int *)resource)[1])(obj, 0, 0, spawnFlags, -1, 0);
                }
            }
            Resource_Release(resource);
            break;
        case 2:
            resource = Resource_Acquire((u16)(*(s16 *)(state + 0xa) + 0xab), 1);
            if (count < 1) {
                ((void (*)(int, int, int, int, int, int, int))((void **)*(int *)resource)[1])
                    (obj, 0, 0, spawnFlags, -1, *(u16 *)(state + 0xa) & 0xff, 0);
            } else {
                for (i = 0; i < count; i++) {
                    ((void (*)(int, int, int, int, int, int, int))((void **)*(int *)resource)[1])
                        (obj, 0, 0, spawnFlags, -1, *(u16 *)(state + 0xa) & 0xff, 0);
                }
            }
            Resource_Release(resource);
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#undef CFTREAS_PARTFX_SPAWN

#pragma scheduling off
#pragma peephole off
int fxemit_SeqFn(int obj, int unused, int events)
{
    u8 *state;
    u8 *def;
    u8 event;
    int i;
    s8 delta;

    state = *(u8 **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    for (i = 0; i < *(u8 *)(events + 0x8b); i++) {
        event = *(u8 *)(events + i + 0x81);
        if (event == 1) {
            fxemit_emitEffect(obj);
        }
        if (*(u8 *)(events + i + 0x81) == 2) {
            state[0x1c] = (u8)(1 - state[0x1c]);
        }
        *(u8 *)(events + i + 0x81) = 0;
    }

    if (state[0x1c] != 0) {
        delta = (s8)def[0x27];
        if (delta == 0x7f) {
            *(s16 *)(obj + 0) = *(s16 *)(obj + 0) + framesThisStep * 10;
        } else {
            *(s16 *)(obj + 0) = *(s16 *)(obj + 0) + delta * framesThisStep * 100;
        }

        delta = (s8)def[0x26];
        if (delta == 0x7f) {
            *(s16 *)(obj + 2) = *(s16 *)(obj + 2) + framesThisStep * 10;
        } else {
            *(s16 *)(obj + 2) = *(s16 *)(obj + 2) + delta * framesThisStep * 100;
        }

        delta = (s8)def[0x25];
        if (delta == 0x7f) {
            *(s16 *)(obj + 4) = *(s16 *)(obj + 4) + framesThisStep * 10;
        } else {
            *(s16 *)(obj + 4) = *(s16 *)(obj + 4) + delta * framesThisStep * 100;
        }
        fxemit_emitEffect(obj);
    }

    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: cfccrate_release
 * EN v1.0 Address: 0x8018E6BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E69C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfccrate_release(void)
{
}

/*
 * --INFO--
 *
 * Function: cfccrate_initialise
 * EN v1.0 Address: 0x8018E6C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E6A0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfccrate_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: fxemit_getExtraSize
 * EN v1.0 Address: 0x8018EC20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ED50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fxemit_getExtraSize(void)
{
  return 0x20;
}

/*
 * --INFO--
 *
 * Function: fxemit_getObjectTypeId
 * EN v1.0 Address: 0x8018EC28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ED58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fxemit_getObjectTypeId(void)
{
  return 0;
}

#pragma scheduling off
#pragma peephole off
void fxemit_free(int obj)
{
    ((void (*)(int))((void **)*(int *)gExpgfxInterface)[6])(obj);
    ((void (*)(int))((void **)*(int *)gModgfxInterface)[5])(obj);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fxemit_hitDetect
 * EN v1.0 Address: 0x8018EC90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018EDC0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fxemit_hitDetect(void)
{
}

#pragma peephole off
void fxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset
