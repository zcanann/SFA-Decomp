#include "main/map_block.h"
#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"

typedef struct TexframeanimatorPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x3C - 0x26];
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
} TexframeanimatorPlacement;


typedef struct ExplodeanimatorState {
    u8 pad0[0x2 - 0x0];
    u8 unk2;
    u8 pad3[0x4 - 0x3];
} ExplodeanimatorState;


typedef struct DimbossicesmashPlacement {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
    s16 unk28;
    s16 unk2A;
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    s16 unk36;
    u16 unk38;
    u16 unk3A;
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
    s16 unk40;
    s16 unk42;
    s16 unk44;
    s16 unk46;
} DimbossicesmashPlacement;


typedef struct FogcontrolPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
    s16 unk28;
    s16 unk2A;
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    s16 unk36;
    u16 unk38;
    u16 unk3A;
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
    s16 unk40;
    s16 unk42;
    s16 unk44;
    s16 unk46;
} FogcontrolPlacement;


typedef struct ExplodeanimatorPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
    s16 unk28;
    s16 unk2A;
    u8 pad2C[0x2E - 0x2C];
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    u8 pad36[0x38 - 0x36];
} ExplodeanimatorPlacement;


extern undefined4 FUN_800068c4();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern int FUN_800480a0();
extern int fn_80056800();
extern undefined4 FUN_80055ee8();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern uint FUN_80060058();
extern undefined4 FUN_800600b4();
extern undefined4 FUN_800600c4();
extern int FUN_800600d4();
extern int FUN_800600e4();
extern undefined4 FUN_8006069c();
extern undefined4 FUN_80135814();
extern undefined4 FUN_80194b10();
extern undefined4 FUN_80242114();
extern undefined8 FUN_8028682c();
extern uint FUN_8028683c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_80322fb8;
extern undefined4 DAT_803dc070;
extern undefined4 gNewCloudsInterface;
extern EffectInterface **gPartfxInterface;
extern undefined4 DAT_803de780;
extern f64 DOUBLE_803e4ca8;
extern f64 DOUBLE_803e4cc0;
extern f64 DOUBLE_803e4cd8;
extern f32 lbl_803DC074;
extern f32 lbl_803E4C98;
extern f32 lbl_803E4CA0;
extern f32 lbl_803E4CB0;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CC8;
extern f32 lbl_803E4CCC;
extern f32 lbl_803E4CD0;
extern f32 lbl_803E4CD4;
extern f32 lbl_803E4CE0;
extern f32 lbl_803E4CE4;
extern f32 lbl_803E4CE8;
extern f32 lbl_803E4CEC;
extern f32 lbl_803E4CF0;
extern f32 lbl_803E4CF4;

/*
 * --INFO--
 *
 * Function: xyzanimator_update
 * EN v1.0 Address: 0x80195008
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801950E0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int  objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int *mapGetBlock(int idx);
extern u8  *mapBlockFn_800606ec(int block, int idx);
extern int  mapBlockFn_80060678(void);
extern int  mmAlloc(int size, int pool, int tag);
extern void fn_80194964(u8 *setup, u8 *state, int block);
extern void fn_80194C40(u8 *setup, u8 *state, int block);
extern void Sfx_KeepAliveLoopedObjectSound(int obj);
extern f32  timeDelta;
extern f32  lbl_803E4018;

void xyzanimator_update(int obj)
{
    u8 *setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
    u8 *state = ((GameObject *)obj)->extra;
    int block;
    u8 *row;
    int i;
    int done;
    int alloc, stride;
    int t;

    block = (int)mapGetBlock(objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                                 ((GameObject *)obj)->anim.localPosZ));
    if ((u32)block == 0) {
        ((XyzAnimatorState *)state)->unk4D = 0;
        goto done_lbl;
    }
    if ((*(u16 *)(block + 4) & 8) == 0) {
        goto done_lbl;
    }
    if (((XyzAnimatorState *)state)->unk4 == 0) {
        for (i = 0; i < *(u16 *)(block + 0x9a); i++) {
            row = mapBlockFn_800606ec(block, i);
            t = mapBlockFn_80060678();
            if (((XyzAnimatorPlacement *)setup)->unk28 == t) {
                ((XyzAnimatorState *)state)->unk0 = ((XyzAnimatorState *)state)->unk0 + 1;
                ((XyzAnimatorState *)state)->unk4 =
                    ((XyzAnimatorState *)state)->unk4 + (*(u16 *)(row + 0x14) - *(u16 *)(row + 0));
            }
        }
        if (((XyzAnimatorState *)state)->unk4 == 0) {
            goto done_lbl;
        }
        ((XyzAnimatorState *)state)->unk4 = ((XyzAnimatorState *)state)->unk4 * 3;
        if (((XyzAnimatorPlacement *)setup)->unk18 == -1) {
            ((XyzAnimatorState *)state)->gameBitValue = 1;
        } else {
            ((XyzAnimatorState *)state)->gameBitValue = (s8)GameBit_Get(((XyzAnimatorPlacement *)setup)->unk18);
        }
        ((XyzAnimatorState *)state)->unk8 = *(u8 *)(block + 0xa1);
        ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk1C;
        ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk1E;
        ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk20;
        if (((XyzAnimatorPlacement *)setup)->unk1A != -1 && GameBit_Get(((XyzAnimatorPlacement *)setup)->unk1A) != 0) {
            ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk22;
            ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk24;
            ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk26;
            ((XyzAnimatorState *)state)->gameBitValue = 1;
        }
        t = ((XyzAnimatorState *)state)->unk4 * 6 + ((XyzAnimatorState *)state)->unk0 * 0xc;
        alloc = mmAlloc(t + ((XyzAnimatorState *)state)->unk8 * 0xc, 5, 0);
        ((XyzAnimatorState *)state)->unkC = alloc;
        stride = ((XyzAnimatorState *)state)->unk0 * 2;
        alloc = alloc + ((XyzAnimatorState *)state)->unk4 * 6;
        ((XyzAnimatorState *)state)->unk18 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk1C = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk10 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk14 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk20 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk24 = alloc;
        alloc = alloc + stride;
        stride = ((XyzAnimatorState *)state)->unk8 * 2;
        ((XyzAnimatorState *)state)->unk28 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk2C = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk30 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk34 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState *)state)->unk38 = alloc;
        ((XyzAnimatorState *)state)->unk3C = alloc + stride;
        fn_80194964(setup, state, block);
        if (((XyzAnimatorPlacement *)setup)->unk2C != 4) {
            fn_80194C40(setup, state, block);
            *(u16 *)(block + 4) = *(u16 *)(block + 4) ^ 1;
            fn_80194C40(setup, state, block);
            *(u16 *)(block + 4) = *(u16 *)(block + 4) ^ 1;
        }
    }
    if (((XyzAnimatorPlacement *)setup)->unk2C == 2) {
        t = GameBit_Get(((XyzAnimatorPlacement *)setup)->unk18);
        if (((XyzAnimatorState *)state)->gameBitValue != t) {
            ((XyzAnimatorState *)state)->gameBitValue = (s8)t;
            if (t == 0) {
                if (((XyzAnimatorPlacement *)setup)->unk1A > -1) {
                    GameBit_Set(((XyzAnimatorPlacement *)setup)->unk1A, 0);
                }
            }
            if (((XyzAnimatorState *)state)->unk4D > 2) {
                ((XyzAnimatorState *)state)->unk4D = 0;
            }
        }
        if (((XyzAnimatorState *)state)->unk4D > 2) {
            goto done_lbl;
        }
        if (((XyzAnimatorState *)state)->unk4E != 0) {
            Sfx_KeepAliveLoopedObjectSound(obj);
        }
    } else {
        if (((XyzAnimatorState *)state)->unk4D > 2) {
            goto done_lbl;
        }
        if (((XyzAnimatorState *)state)->gameBitValue == 0) {
            ((XyzAnimatorState *)state)->gameBitValue = (s8)GameBit_Get(((XyzAnimatorPlacement *)setup)->unk18);
            if (((XyzAnimatorState *)state)->gameBitValue == 0) {
                goto done_lbl;
            }
        }
    }
    switch (((XyzAnimatorPlacement *)setup)->unk2C) {
    case 0:
    case 4:
        done = 0;
        if (((XyzAnimatorPlacement *)setup)->unk1C > ((XyzAnimatorPlacement *)setup)->unk22) {
            ((XyzAnimatorState *)state)->unk40 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) - ((XyzAnimatorState *)state)->unk40);
            if (((XyzAnimatorState *)state)->unk40 <= (f32)((XyzAnimatorPlacement *)setup)->unk22) {
                ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk22;
                done = 1;
            }
        } else {
            ((XyzAnimatorState *)state)->unk40 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) + ((XyzAnimatorState *)state)->unk40;
            if (((XyzAnimatorState *)state)->unk40 >= (f32)((XyzAnimatorPlacement *)setup)->unk22) {
                ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk22;
                done = 1;
            }
        }
        if (((XyzAnimatorPlacement *)setup)->unk1E > ((XyzAnimatorPlacement *)setup)->unk24) {
            ((XyzAnimatorState *)state)->unk44 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) - ((XyzAnimatorState *)state)->unk44);
            if (((XyzAnimatorState *)state)->unk44 <= (f32)((XyzAnimatorPlacement *)setup)->unk24) {
                ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk24;
                done += 1;
            }
        } else {
            ((XyzAnimatorState *)state)->unk44 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) + ((XyzAnimatorState *)state)->unk44;
            if (((XyzAnimatorState *)state)->unk44 >= (f32)((XyzAnimatorPlacement *)setup)->unk24) {
                ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk24;
                done += 1;
            }
        }
        if (((XyzAnimatorPlacement *)setup)->unk20 > ((XyzAnimatorPlacement *)setup)->unk26) {
            ((XyzAnimatorState *)state)->unk48 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) - ((XyzAnimatorState *)state)->unk48);
            if (((XyzAnimatorState *)state)->unk48 <= (f32)((XyzAnimatorPlacement *)setup)->unk26) {
                ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk26;
                done += 1;
            }
        } else {
            ((XyzAnimatorState *)state)->unk48 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) + ((XyzAnimatorState *)state)->unk48;
            if (((XyzAnimatorState *)state)->unk48 >= (f32)((XyzAnimatorPlacement *)setup)->unk26) {
                ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk26;
                done += 1;
            }
        }
        if (done == 3) {
            if (((XyzAnimatorPlacement *)setup)->unk1A != -1) {
                GameBit_Set(((XyzAnimatorPlacement *)setup)->unk1A, 1);
            }
            ((XyzAnimatorState *)state)->unk4D += 1;
        }
        break;
    case 1:
        if (((XyzAnimatorPlacement *)setup)->unk1C > ((XyzAnimatorPlacement *)setup)->unk22) {
            ((XyzAnimatorState *)state)->unk40 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) - ((XyzAnimatorState *)state)->unk40);
            if (((XyzAnimatorState *)state)->unk40 < (f32)((XyzAnimatorPlacement *)setup)->unk22) {
                ((XyzAnimatorState *)state)->unk40 =
                    (f32)(((XyzAnimatorPlacement *)setup)->unk1C -
                          (int)((f32)((XyzAnimatorPlacement *)setup)->unk22 - ((XyzAnimatorState *)state)->unk40));
            }
        } else {
            ((XyzAnimatorState *)state)->unk40 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) + ((XyzAnimatorState *)state)->unk40;
            if (((XyzAnimatorState *)state)->unk40 > (f32)((XyzAnimatorPlacement *)setup)->unk1C) {
                ((XyzAnimatorState *)state)->unk40 =
                    (f32)(((XyzAnimatorPlacement *)setup)->unk22 +
                          (int)(((XyzAnimatorState *)state)->unk40 - (f32)((XyzAnimatorPlacement *)setup)->unk22));
            }
        }
        if (((XyzAnimatorPlacement *)setup)->unk1E > ((XyzAnimatorPlacement *)setup)->unk24) {
            ((XyzAnimatorState *)state)->unk44 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) - ((XyzAnimatorState *)state)->unk44);
            if (((XyzAnimatorState *)state)->unk44 < (f32)((XyzAnimatorPlacement *)setup)->unk24) {
                ((XyzAnimatorState *)state)->unk44 =
                    -(lbl_803E4018 *
                          (f32)(int)((f32)((XyzAnimatorPlacement *)setup)->unk24 - ((XyzAnimatorState *)state)->unk44) -
                      (f32)((XyzAnimatorPlacement *)setup)->unk1E);
            }
        } else {
            ((XyzAnimatorState *)state)->unk44 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) + ((XyzAnimatorState *)state)->unk44;
            if (((XyzAnimatorState *)state)->unk44 > (f32)((XyzAnimatorPlacement *)setup)->unk1E) {
                ((XyzAnimatorState *)state)->unk44 =
                    (f32)(((XyzAnimatorPlacement *)setup)->unk24 +
                          (int)(((XyzAnimatorState *)state)->unk44 - (f32)((XyzAnimatorPlacement *)setup)->unk24));
            }
        }
        if (((XyzAnimatorPlacement *)setup)->unk20 > ((XyzAnimatorPlacement *)setup)->unk26) {
            ((XyzAnimatorState *)state)->unk48 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) - ((XyzAnimatorState *)state)->unk48);
            if (((XyzAnimatorState *)state)->unk48 < (f32)((XyzAnimatorPlacement *)setup)->unk26) {
                ((XyzAnimatorState *)state)->unk48 =
                    (f32)(((XyzAnimatorPlacement *)setup)->unk20 -
                          (int)((f32)((XyzAnimatorPlacement *)setup)->unk26 - ((XyzAnimatorState *)state)->unk48));
            }
        } else {
            ((XyzAnimatorState *)state)->unk48 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) + ((XyzAnimatorState *)state)->unk48;
            if (((XyzAnimatorState *)state)->unk48 > (f32)((XyzAnimatorPlacement *)setup)->unk20) {
                ((XyzAnimatorState *)state)->unk48 =
                    (f32)(((XyzAnimatorPlacement *)setup)->unk26 +
                          (int)(((XyzAnimatorState *)state)->unk48 - (f32)((XyzAnimatorPlacement *)setup)->unk26));
            }
        }
        break;
    case 2:
        done = 0;
        if (((XyzAnimatorState *)state)->gameBitValue != 0) {
            if (((XyzAnimatorPlacement *)setup)->unk1C > ((XyzAnimatorPlacement *)setup)->unk22) {
                ((XyzAnimatorState *)state)->unk40 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) -
                      ((XyzAnimatorState *)state)->unk40);
                if (((XyzAnimatorState *)state)->unk40 <= (f32)((XyzAnimatorPlacement *)setup)->unk22) {
                    ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk22;
                    done = 1;
                }
            } else {
                ((XyzAnimatorState *)state)->unk40 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) + ((XyzAnimatorState *)state)->unk40;
                if (((XyzAnimatorState *)state)->unk40 >= (f32)((XyzAnimatorPlacement *)setup)->unk22) {
                    ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk22;
                    done = 1;
                }
            }
            if (((XyzAnimatorPlacement *)setup)->unk1E > ((XyzAnimatorPlacement *)setup)->unk24) {
                ((XyzAnimatorState *)state)->unk44 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) -
                      ((XyzAnimatorState *)state)->unk44);
                if (((XyzAnimatorState *)state)->unk44 <= (f32)((XyzAnimatorPlacement *)setup)->unk24) {
                    ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk24;
                    done += 1;
                }
            } else {
                ((XyzAnimatorState *)state)->unk44 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) + ((XyzAnimatorState *)state)->unk44;
                if (((XyzAnimatorState *)state)->unk44 >= (f32)((XyzAnimatorPlacement *)setup)->unk24) {
                    ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk24;
                    done += 1;
                }
            }
            if (((XyzAnimatorPlacement *)setup)->unk20 > ((XyzAnimatorPlacement *)setup)->unk26) {
                ((XyzAnimatorState *)state)->unk48 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) -
                      ((XyzAnimatorState *)state)->unk48);
                if (((XyzAnimatorState *)state)->unk48 <= (f32)((XyzAnimatorPlacement *)setup)->unk26) {
                    ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk26;
                    done += 1;
                }
            } else {
                ((XyzAnimatorState *)state)->unk48 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) + ((XyzAnimatorState *)state)->unk48;
                if (((XyzAnimatorState *)state)->unk48 >= (f32)((XyzAnimatorPlacement *)setup)->unk26) {
                    ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk26;
                    done += 1;
                }
            }
            if (done == 3) {
                if (((XyzAnimatorPlacement *)setup)->unk1A != -1) {
                    GameBit_Set(((XyzAnimatorPlacement *)setup)->unk1A, 1);
                }
                ((XyzAnimatorState *)state)->unk4D += 1;
            }
        } else {
            if (((XyzAnimatorPlacement *)setup)->unk1C > ((XyzAnimatorPlacement *)setup)->unk22) {
                ((XyzAnimatorState *)state)->unk40 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) + ((XyzAnimatorState *)state)->unk40;
                if (((XyzAnimatorState *)state)->unk40 >= (f32)((XyzAnimatorPlacement *)setup)->unk1C) {
                    ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk1C;
                    done = 1;
                }
            } else {
                ((XyzAnimatorState *)state)->unk40 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk29 * timeDelta) -
                      ((XyzAnimatorState *)state)->unk40);
                if (((XyzAnimatorState *)state)->unk40 <= (f32)((XyzAnimatorPlacement *)setup)->unk1C) {
                    ((XyzAnimatorState *)state)->unk40 = (f32)((XyzAnimatorPlacement *)setup)->unk1C;
                    done = 1;
                }
            }
            if (((XyzAnimatorPlacement *)setup)->unk1E > ((XyzAnimatorPlacement *)setup)->unk24) {
                ((XyzAnimatorState *)state)->unk44 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) + ((XyzAnimatorState *)state)->unk44;
                if (((XyzAnimatorState *)state)->unk44 >= (f32)((XyzAnimatorPlacement *)setup)->unk1E) {
                    ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk1E;
                    done += 1;
                }
            } else {
                ((XyzAnimatorState *)state)->unk44 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2A * timeDelta) -
                      ((XyzAnimatorState *)state)->unk44);
                if (((XyzAnimatorState *)state)->unk44 <= (f32)((XyzAnimatorPlacement *)setup)->unk1E) {
                    ((XyzAnimatorState *)state)->unk44 = (f32)((XyzAnimatorPlacement *)setup)->unk1E;
                    done += 1;
                }
            }
            if (((XyzAnimatorPlacement *)setup)->unk20 > ((XyzAnimatorPlacement *)setup)->unk26) {
                ((XyzAnimatorState *)state)->unk48 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) + ((XyzAnimatorState *)state)->unk48;
                if (((XyzAnimatorState *)state)->unk48 >= (f32)((XyzAnimatorPlacement *)setup)->unk20) {
                    ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk20;
                    done += 1;
                }
            } else {
                ((XyzAnimatorState *)state)->unk48 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement *)setup)->unk2B * timeDelta) -
                      ((XyzAnimatorState *)state)->unk48);
                if (((XyzAnimatorState *)state)->unk48 <= (f32)((XyzAnimatorPlacement *)setup)->unk20) {
                    ((XyzAnimatorState *)state)->unk48 = (f32)((XyzAnimatorPlacement *)setup)->unk20;
                    done += 1;
                }
            }
            if (done == 3) {
                ((XyzAnimatorState *)state)->unk4D += 1;
            }
        }
        break;
    }
    fn_80194C40(setup, state, block);
done_lbl:
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801950ac
 * EN v1.0 Address: 0x801950AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019518C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801954f0
 * EN v1.0 Address: 0x801954F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80195584
 * EN v1.1 Size: 4624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801954f4
 * EN v1.0 Address: 0x801954F4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80196794
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80195b40
 * EN v1.0 Address: 0x80195B40
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80196EA8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80195b74
 * EN v1.0 Address: 0x80195B74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80196ED8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on



/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void explodeanimator_render(void) {}
void explodeanimator_hitDetect(void) {}
void explodeanimator_release(void) {}
void explodeanimator_initialise(void) {}

extern f32 lbl_803E4020;

void explodeanimator_update(int *obj) {
    u8 *sub;
    u8 *def;
    int i;
    f32 buf[6];
    f32 vel[2];

    sub = ((GameObject *)obj)->extra;
    if ((sub[2] & 1) != 0) return;
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (GameBit_Get(((ExplodeanimatorPlacement *)def)->unk34) == 0) return;
    GameBit_Set(((ExplodeanimatorPlacement *)def)->unk32, 1);
    sub[2] = (u8)(sub[2] | 1);
    for (i = 0; i < def[0x2c]; i++) {
        vel[0] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement *)def)->unk2E, ((ExplodeanimatorPlacement *)def)->unk28) * lbl_803E4020;
        vel[1] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement *)def)->unk30, ((ExplodeanimatorPlacement *)def)->unk2A) * lbl_803E4020;
        buf[3] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement *)def)->unk18, ((ExplodeanimatorPlacement *)def)->unk1E);
        buf[4] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement *)def)->unk1A, ((ExplodeanimatorPlacement *)def)->unk20);
        buf[5] = (f32)(s32)randomGetRange(((ExplodeanimatorPlacement *)def)->unk1C, ((ExplodeanimatorPlacement *)def)->unk22);
        (*gPartfxInterface)->spawnObject(obj, ((ExplodeanimatorPlacement *)def)->unk24, buf, 2, -1, vel);
    }
}
void dimbossicesmash_hitDetect(void) {}
void dimbossicesmash_release(void) {}
void dimbossicesmash_initialise(void) {}
void texframeanimator_free(void) {}
void texframeanimator_hitDetect(void) {}
void texframeanimator_release(void) {}
void texframeanimator_initialise(void) {}
void fogcontrol_hitDetect(void) {}

typedef struct TexFrameAnimatorState {
    int textureSlot;
    u8 speed;
    u8 pad5[3];
    int endFrame;
    int wrapFrame;
    int frame;
    u8 flag80 : 1;
    u8 done : 1;
    u8 active : 1;
    u8 flagLow : 5;
} TexFrameAnimatorState;

extern u8 framesThisStep;
extern char sTexFrameAnimDebugFormat[];
extern int *return0_80056694(int *block, int textureSlot);
extern int *mapTextureOverrideGetEntry(int idx);
extern void fn_80137948(char *fmt, ...);

void texframeanimator_update(int *obj)
{
    TexFrameAnimatorState *state;
    u8 *params;
    int *block;
    int *textureHit;
    int *textureEntry;

    state = ((GameObject *)obj)->extra;
    params = *(u8 **)&((GameObject *)obj)->anim.placementData;

    if ((state->active == 0) &&
        ((u32)GameBit_Get(((TexframeanimatorPlacement *)params)->unk20) != 0) &&
        (state->done == 0)) {
        state->active = 1;
        state->frame = 0;
    }

    if ((state->active != 0) && (state->textureSlot != 0)) {
        block = mapGetBlock(objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX,
                                                ((GameObject *)obj)->anim.localPosY,
                                                ((GameObject *)obj)->anim.localPosZ));
        if ((block != NULL) && ((((MapBlockData *)block)->unk4 & 8) != 0)) {
            textureHit = return0_80056694(block, state->textureSlot);
            if (textureHit != NULL) {
                textureEntry = mapTextureOverrideGetEntry(*(s16 *)textureHit);
                state->frame += state->speed * framesThisStep;
                fn_80137948(sTexFrameAnimDebugFormat, state->frame);
                if (state->frame < 0) {
                    state->frame = 0;
                } else if (state->frame > state->endFrame) {
                    if (((TexframeanimatorPlacement *)params)->unk1E != -1) {
                        GameBit_Set(((TexframeanimatorPlacement *)params)->unk1E, 1);
                        state->active = 0;
                        state->done = 1;
                        state->frame = state->endFrame;
                    } else {
                        state->frame = state->wrapFrame;
                    }
                }
                textureEntry[1] = state->frame;
            }
        }
    }
}

void texframeanimator_init(int *obj, u8 *params)
{
    TexFrameAnimatorState *state;
    u8 done;

    state = ((GameObject *)obj)->extra;
    state->textureSlot = (s8)params[0x19];
    state->endFrame = *(s16 *)(params + 0x1a) << 8;
    state->speed = (u8)*(s16 *)(params + 0x1c);
    state->wrapFrame = (s8)params[0x18] << 8;
    done = (u8)GameBit_Get(*(s16 *)(params + 0x1e));
    if ((state->done = done) != 0) {
        state->frame = state->endFrame;
        state->active = 1;
    }
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);
}

/* 8b "li r3, N; blr" returners. */
int explodeanimator_getExtraSize(void) { return 0x4; }
int explodeanimator_getObjectTypeId(void) { return 0x0; }
int dimbossicesmash_getExtraSize(void) { return 0x2a0; }
int texframeanimator_getExtraSize(void) { return 0x18; }
int texframeanimator_getObjectTypeId(void) { return 0x0; }
int fogcontrol_getExtraSize(void) { return 0x8; }
int fogcontrol_getObjectTypeId(void) { return 0x0; }
int lightning_getExtraSize(void) { return 0x28; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4048;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4060;
void dimbossicesmash_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4048); }
void texframeanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4060); }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void explodeanimator_free(int x) { ObjGroup_RemoveObject(x, 0x1a); }

/* state encode: ((obj->_X)->_Y << shift) | const. */
u32 dimbossicesmash_getObjectTypeId(int *obj) { return (*((u8*)((int**)obj)[0x4c/4] + 0x18) << 11) | 0x400; }

/* Drift-recovery: add new fns with v1.0 names. */
extern void disableHeavyFog(void);


void dimbossicesmash_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void fogcontrol_free(int* obj)
{
    u8* state = ((GameObject *)obj)->extra;
    if (((u32)state[4] >> 7) & 1u) {
        disableHeavyFog();
    }
}

extern f32 lbl_803E4070;
extern f32 lbl_803E4074;
extern f32 lbl_803E4078;
extern f32 lbl_803E407C;
extern void enableHeavyFog(u8 mode, f32 a, f32 b, f32 c, f32 d, f32 e);

typedef struct FogControlState {
    f32 blend;
    u8 on : 1;
    u8 full : 1;
    u8 rest : 6;
} FogControlState;


void fogcontrol_init(u8* obj, u8* params) {
    FogControlState *st;
    u8 cv;
    f32 t;

    st = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);
    st->on = 0;
    st->full = 0;
    st->blend = lbl_803E4070;
    if ((params[0x1a] & 0x08) != 0) {
        if (*(s16*)(params + 0x18) == -1) {
            cv = 1;
        } else {
            cv = (u8)GameBit_Get(*(s16*)(params + 0x18));
        }
        if (cv != 0) {
            st->full = 1;
            st->on = 1;
            st->blend = lbl_803E4074;
            t = ((GameObject *)obj)->anim.localPosY +
                (st->blend * ((f32)*(s16 *)(params + 0x1c) - (f32)*(s16 *)(params + 0x20)) +
                 (f32)*(s16 *)(params + 0x20));
            enableHeavyFog(params[0x1a] & 1, t,
                           ((f32)*(s16 *)(params + 0x1e) + t) - (f32)*(s16 *)(params + 0x1c),
                           (f32)*(s16 *)(params + 0x24),
                           (f32)*(s16 *)(params + 0x22) / lbl_803E4078,
                           lbl_803E407C);
        }
    }
}

void explodeanimator_init(int* obj, int* def)
{
    int* state = ((GameObject *)obj)->extra;
    int v;
    if ((u32)GameBit_Get(*(s16*)((char*)def + 50)) != 0u) {
        v = 1;
    } else {
        v = 0;
    }
    ((ExplodeanimatorState *)state)->unk2 = (u8)v;
    ObjGroup_AddObject(obj, 26);
}


void xyzanimator_init(int obj)
{
    int inner = *(int *)&((GameObject *)obj)->extra;
    int id;
    ObjGroup_AddObject(obj, 0x51);
    id = *(int *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x14);
    switch (id) {
    case 0x46406:
    case 0x4BAB1:
        *(s16 *)(inner + 0x4e) = 0x7d;
        break;
    case 0x49275:
    case 0x49CB7:
    case 0x4C797:
        *(s16 *)(inner + 0x4e) = 0x4b7;
        break;
    }
}

extern f32  sqrtf(f32);
extern void Obj_FreeObject(u8 *obj);
extern u8   lbl_803DDB00;
extern f32  lbl_803E4034;
extern f32  lbl_803E404C;
extern f32  lbl_803E4050;
extern f32  lbl_803E4054;
extern f32  lbl_803E4058;
extern f32  lbl_803E405C;

/* EN v1.0 0x80196990  size: 1752b  dimbossicesmash_update: gate on the
 * trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */
void dimbossicesmash_update(u8 *obj)
{
    u8 *state = ((GameObject *)obj)->extra;
    u8 flags = state[0x29e];
    u8 *setup;
    u32 t;
    int a;
    s16 cnt;
    int t1;
    f32 nx, ny, nz;
    f32 len, inv, dot;
    f32 fy, fz, ff;
    f32 dx, dy, dz, k;
    int i;
    f32 stk[3];

    if ((flags & 2) != 0) {
        if ((((GameObject *)obj)->anim.flags & 0x2000U) != 0) {
            Obj_FreeObject(obj);
        }
        ((GameObject *)obj)->anim.alpha = 0;
    } else {
        setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
        if ((flags & 1) == 0) {
            if (((ObjAnimComponent *)obj)->bankIndex == 0) {
                t = GameBit_Get(((DimbossicesmashPlacement *)setup)->unk40);
                if (t != 0 || ((DimbossicesmashPlacement *)setup)->unk40 == -1) {
                    state[0x29e] = state[0x29e] | 1;
                    GameBit_Set(((DimbossicesmashPlacement *)setup)->unk3E, 1);
                    lbl_803DDB00 = 1;
                }
            } else if (lbl_803DDB00 != 0) {
                state[0x29e] = flags | 1;
            }
            ((GameObject *)obj)->anim.alpha = 0;
        } else {
            ((GameObject *)obj)->anim.alpha = 0xff;
            ((DimBossIceSmashState *)state)->unk29C += framesThisStep;
            cnt = ((DimBossIceSmashState *)state)->unk29C;
            if (((DimbossicesmashPlacement *)setup)->unk38 <= cnt) {
                state[0x29e] = state[0x29e] | 2;
            }
            if (((DimBossIceSmashState *)state)->unk29C > ((DimbossicesmashPlacement *)setup)->unk3A &&
                (t1 = ((DimbossicesmashPlacement *)setup)->unk38 - ((DimbossicesmashPlacement *)setup)->unk3A) != 0) {
                a = (int)(lbl_803E404C *
                          (lbl_803E4048 -
                           (f32)(((DimBossIceSmashState *)state)->unk29C - ((DimbossicesmashPlacement *)setup)->unk3A) / (f32)t1));
                if (a > 0xff) {
                    a = 0xff;
                } else if (a < 0) {
                    a = 0;
                }
                ((GameObject *)obj)->anim.alpha = (u8)a;
            }
            ((GameObject *)obj)->anim.velocityX = timeDelta * ((DimBossIceSmashState *)state)->unk290 + ((GameObject *)obj)->anim.velocityX;
            ((GameObject *)obj)->anim.velocityY = timeDelta * ((DimBossIceSmashState *)state)->unk294 + ((GameObject *)obj)->anim.velocityY;
            ((GameObject *)obj)->anim.velocityZ = timeDelta * ((DimBossIceSmashState *)state)->unk298 + ((GameObject *)obj)->anim.velocityZ;
            ((DimBossIceSmashState *)state)->unk278 =
                timeDelta * ((DimBossIceSmashState *)state)->unk284 + ((DimBossIceSmashState *)state)->unk278;
            ((DimBossIceSmashState *)state)->unk27C =
                timeDelta * ((DimBossIceSmashState *)state)->unk288 + ((DimBossIceSmashState *)state)->unk27C;
            ((DimBossIceSmashState *)state)->unk280 =
                timeDelta * ((DimBossIceSmashState *)state)->unk28C + ((DimBossIceSmashState *)state)->unk280;
            if ((state[0x29f] & 1) != 0) {
                if (((GameObject *)obj)->anim.velocityX < *(f32 *)&lbl_803E4034) {
                    ((GameObject *)obj)->anim.velocityX = lbl_803E4034;
                }
            } else if (((GameObject *)obj)->anim.velocityX > *(f32 *)&lbl_803E4034) {
                ((GameObject *)obj)->anim.velocityX = lbl_803E4034;
            }
            if ((state[0x29f] & 2) != 0) {
                if (((GameObject *)obj)->anim.velocityZ < *(f32 *)&lbl_803E4034) {
                    ((GameObject *)obj)->anim.velocityZ = lbl_803E4034;
                }
            } else if (((GameObject *)obj)->anim.velocityZ > *(f32 *)&lbl_803E4034) {
                ((GameObject *)obj)->anim.velocityZ = lbl_803E4034;
            }
            if ((state[0x29f] & 4) != 0) {
                if (((DimBossIceSmashState *)state)->unk278 < *(f32 *)&lbl_803E4034) {
                    ((DimBossIceSmashState *)state)->unk278 = lbl_803E4034;
                }
            } else if (((DimBossIceSmashState *)state)->unk278 > *(f32 *)&lbl_803E4034) {
                ((DimBossIceSmashState *)state)->unk278 = lbl_803E4034;
            }
            if ((state[0x29f] & 8) != 0) {
                if (((DimBossIceSmashState *)state)->unk27C < *(f32 *)&lbl_803E4034) {
                    ((DimBossIceSmashState *)state)->unk27C = lbl_803E4034;
                }
            } else if (((DimBossIceSmashState *)state)->unk27C > *(f32 *)&lbl_803E4034) {
                ((DimBossIceSmashState *)state)->unk27C = lbl_803E4034;
            }
            if ((state[0x29f] & 0x10) != 0) {
                if (((DimBossIceSmashState *)state)->unk280 < *(f32 *)&lbl_803E4034) {
                    ((DimBossIceSmashState *)state)->unk280 = lbl_803E4034;
                }
            } else if (((DimBossIceSmashState *)state)->unk280 > *(f32 *)&lbl_803E4034) {
                ((DimBossIceSmashState *)state)->unk280 = lbl_803E4034;
            }
            ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
            ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
            ((GameObject *)obj)->anim.rotX = ((DimBossIceSmashState *)state)->unk278 * timeDelta + (f32)((GameObject *)obj)->anim.rotX;
            ((GameObject *)obj)->anim.rotY = ((DimBossIceSmashState *)state)->unk27C * timeDelta + (f32)((GameObject *)obj)->anim.rotY;
            ((GameObject *)obj)->anim.rotZ = ((DimBossIceSmashState *)state)->unk280 * timeDelta + (f32)((GameObject *)obj)->anim.rotZ;
            if ((((DimbossicesmashPlacement *)setup)->unk3C & 2) != 0) {
                (*gPathControlInterface)->update(obj, state, timeDelta);
                (*gPathControlInterface)->apply(obj, state);
                (*gPathControlInterface)->advance(obj, state, timeDelta);
                if (((DimBossIceSmashState *)state)->unk261 != 0) {
                    nx = -((GameObject *)obj)->anim.velocityX;
                    ny = -((GameObject *)obj)->anim.velocityY;
                    nz = -((GameObject *)obj)->anim.velocityZ;
                    len = sqrtf(nz * nz + (nx * nx + ny * ny));
                    if (lbl_803E4034 != len) {
                        inv = lbl_803E4048 / len;
                        nx = nx * inv;
                        ny = ny * inv;
                        nz = nz * inv;
                    }
                    fy = ((DimBossIceSmashState *)state)->unk6C;
                    fz = ((DimBossIceSmashState *)state)->unk70;
                    dot = lbl_803E4050 *
                          (nz * fz + (nx * ((DimBossIceSmashState *)state)->unk68 + ny * fy));
                    ((GameObject *)obj)->anim.velocityX = ((DimBossIceSmashState *)state)->unk68 * dot;
                    ((GameObject *)obj)->anim.velocityY = fy * dot;
                    ((GameObject *)obj)->anim.velocityZ = fz * dot;
                    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX - nx;
                    ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY - ny;
                    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ - nz;
                    ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * len;
                    ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * lbl_803E4054;
                    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * len;
                    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * len;
                    ff = lbl_803E4058;
                    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * ff;
                    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * ff;
                }
            }
            if ((((DimbossicesmashPlacement *)setup)->unk3C & 4) != 0 && ((GameObject *)obj)->anim.alpha == 0xff) {
                dx = ((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX;
                dy = ((GameObject *)obj)->anim.localPosY - ((GameObject *)obj)->anim.previousLocalPosY;
                dz = ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ;
                i = 0;
                do {
                    k = (f32)i * lbl_803E405C;
                    stk[0] = dx * k + ((GameObject *)obj)->anim.previousLocalPosX;
                    stk[1] = dy * k + ((GameObject *)obj)->anim.previousLocalPosY;
                    stk[2] = dz * k + ((GameObject *)obj)->anim.previousLocalPosZ;
                    (*gPartfxInterface)->spawnObject(obj, 1000, stk, 0x200001, -1, NULL);
                    i++;
                } while (i < 2);
            }
        }
    }
}

extern f32 lbl_803E4030;
extern f32 lbl_803E4038;
extern f32 lbl_803E403C;
extern u8  lbl_80322368[0xC];
extern u8  lbl_803DBDF8[8];

/* EN v1.0 0x80196520  size: 1008b  fn_80196520: seed the icesmash launch
 * state from the setup record: spawn position/rotation, launch velocity
 * (optionally homing on the target point), rotation velocities and the
 * gravity/clamp direction flags. */
void fn_80196520(u8 *obj, u8 *state, u8 *setup)
{
    f32 vx, vy, vz;
    f32 spd, len;

    ((GameObject *)obj)->anim.localPosX = ((DimBossIceSmashState *)state)->unk26C * ((GameObject *)obj)->anim.rootMotionScale + ((ObjPlacement *)setup)->posX;
    ((GameObject *)obj)->anim.localPosY = ((DimBossIceSmashState *)state)->unk270 * ((GameObject *)obj)->anim.rootMotionScale + ((ObjPlacement *)setup)->posY;
    ((GameObject *)obj)->anim.localPosZ = ((DimBossIceSmashState *)state)->unk274 * ((GameObject *)obj)->anim.rootMotionScale + ((ObjPlacement *)setup)->posZ;
    ((GameObject *)obj)->anim.rotX = *(s16 *)(setup + 0x1a);
    ((GameObject *)obj)->anim.rotY = *(s16 *)(setup + 0x1c);
    ((GameObject *)obj)->anim.rotZ = *(s16 *)(setup + 0x1e);
    if ((*(u8 *)(setup + 0x3c) & 1) != 0) {
        spd = (f32)*(s16 *)(setup + 0x20) / lbl_803E4030;
        vx = ((GameObject *)obj)->anim.localPosX - (f32)*(s16 *)(setup + 0x42);
        vy = ((GameObject *)obj)->anim.localPosY - (f32)*(s16 *)(setup + 0x44);
        vz = ((GameObject *)obj)->anim.localPosZ - (f32)*(s16 *)(setup + 0x46);
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (lbl_803E4034 != len) {
            vx = vx / len;
            vy = vy / len;
            vz = vz / len;
        }
        ((GameObject *)obj)->anim.velocityX = spd * vx;
        ((GameObject *)obj)->anim.velocityY = spd * vy;
        ((GameObject *)obj)->anim.velocityZ = spd * vz;
    } else {
        ((GameObject *)obj)->anim.velocityX = (f32)*(s16 *)(setup + 0x20) / (spd = lbl_803E4030);
        ((GameObject *)obj)->anim.velocityY = (f32)*(s16 *)(setup + 0x22) / spd;
        ((GameObject *)obj)->anim.velocityZ = (f32)*(s16 *)(setup + 0x24) / spd;
    }
    ((DimBossIceSmashState *)state)->unk278 = (f32)*(s16 *)(setup + 0x2c);
    ((DimBossIceSmashState *)state)->unk27C = (f32)*(s16 *)(setup + 0x2e);
    ((DimBossIceSmashState *)state)->unk280 = (f32)*(s16 *)(setup + 0x30);
    if (((GameObject *)obj)->anim.velocityX > lbl_803E4034) {
        state[0x29f] = state[0x29f] | 1;
    }
    if (((GameObject *)obj)->anim.velocityZ > lbl_803E4034) {
        state[0x29f] = state[0x29f] | 2;
    }
    if (((DimBossIceSmashState *)state)->unk278 > lbl_803E4034) {
        state[0x29f] = state[0x29f] | 4;
    }
    if (((DimBossIceSmashState *)state)->unk27C > lbl_803E4034) {
        state[0x29f] = state[0x29f] | 8;
    }
    if (((DimBossIceSmashState *)state)->unk280 > lbl_803E4034) {
        state[0x29f] = state[0x29f] | 0x10;
    }
    ((DimBossIceSmashState *)state)->unk284 = (f32)*(s16 *)(setup + 0x32) / (spd = lbl_803E4038);
    ((DimBossIceSmashState *)state)->unk288 = (f32)*(s16 *)(setup + 0x34) / spd;
    ((DimBossIceSmashState *)state)->unk28C = (f32)*(s16 *)(setup + 0x36) / spd;
    ((DimBossIceSmashState *)state)->unk290 = (f32)*(s16 *)(setup + 0x26) / (spd = lbl_803E403C);
    ((DimBossIceSmashState *)state)->unk294 = (f32)*(s16 *)(setup + 0x28) / spd;
    ((DimBossIceSmashState *)state)->unk298 = (f32)*(s16 *)(setup + 0x2a) / spd;
    ((DimBossIceSmashState *)state)->unk29C = 0;
}

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */
void dimbossicesmash_init(u8 *obj, u8 *params)
{
    u8 *state;
    f32 fz;
    u8 t;
    u8 buf[12];

    buf[0] = 5;
    ((ObjAnimComponent *)obj)->bankIndex = params[0x18];
    fz = lbl_803E4034;
    state = ((GameObject *)obj)->extra;
    ((DimBossIceSmashState *)state)->unk26C = lbl_803E4034;
    ((DimBossIceSmashState *)state)->unk270 = fz;
    ((DimBossIceSmashState *)state)->unk274 = fz;
    fn_80196520(obj, state, params);
    if (GameBit_Get(*(s16 *)(params + 0x3e)) == 0) {
        t = 0;
    } else {
        t = 2;
    }
    state[0x29e] = t;
    lbl_803DDB00 = 0;
    if ((*(u8 *)(params + 0x3c) & 2) != 0) {
        (*gPathControlInterface)->init(state, 0, 0x40002, 1);
        (*gPathControlInterface)->setup(state, 1, lbl_80322368, lbl_803DBDF8, buf);
        (*gPathControlInterface)->attachObject(obj, state);
    }
}

extern f32 lbl_803E4068;
extern f32 lbl_803E406C;

/* EN v1.0 0x80197474  size: 648b  fogcontrol_update: ramp the fog blend
 * toward the gamebit-selected target and feed the heavy fog params. */
void fogcontrol_update(int obj)
{
    u8 *setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
    FogControlState *st = ((GameObject *)obj)->extra;
    u8 cv;
    u8 run;
    f32 t;

    if (((FogcontrolPlacement *)setup)->unk18 == -1) {
        cv = 1;
    } else {
        cv = (u8)GameBit_Get(((FogcontrolPlacement *)setup)->unk18);
    }
    if ((cv != 0 && st->full == 0) || (cv == 0 && st->on != 0)) {
        run = 1;
    } else {
        run = 0;
    }
    if (run != 0) {
        if (cv != 0) {
            if ((*(u8 *)(setup + 0x1a) & 2) != 0) {
                st->blend = lbl_803E4068 * timeDelta + st->blend;
            } else {
                st->blend = lbl_803E406C * timeDelta + st->blend;
            }
            st->on = 1;
        } else {
            if ((*(u8 *)(setup + 0x1a) & 4) != 0) {
                st->blend = -(lbl_803E4068 * timeDelta - st->blend);
            } else {
                st->blend = -(lbl_803E406C * timeDelta - st->blend);
            }
            st->full = 0;
        }
        if (st->blend <= lbl_803E4070) {
            st->blend = *(f32 *)&lbl_803E4070;
            st->on = 0;
            disableHeavyFog();
        } else {
            st->on = 1;
            if (st->blend > lbl_803E4074) {
                st->blend = *(f32 *)&lbl_803E4074;
                st->full = 1;
            }
            t = st->blend * ((f32)((FogcontrolPlacement *)setup)->unk1C - (f32)((FogcontrolPlacement *)setup)->unk20) +
                (f32)((FogcontrolPlacement *)setup)->unk20;
            t = ((GameObject *)obj)->anim.localPosY + t;
            enableHeavyFog(*(u8 *)(setup + 0x1a) & 1, t,
                           ((f32)((FogcontrolPlacement *)setup)->unk1E + t) - (f32)((FogcontrolPlacement *)setup)->unk1C,
                           (f32)((FogcontrolPlacement *)setup)->unk24,
                           (f32)((FogcontrolPlacement *)setup)->unk22 / lbl_803E4078,
                           lbl_803E407C);
        }
    }
}
