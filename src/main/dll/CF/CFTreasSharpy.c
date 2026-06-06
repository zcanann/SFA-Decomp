#include "main/dll/CF/CFTreasSharpy.h"
#include "main/objanim_internal.h"

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
extern void fn_80137948(char *fmt, ...);
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
    ObjAnimComponent *objAnim;
    CfCcrateState *state;
    short id;
    f32 zeroF;

    objAnim = (ObjAnimComponent *)obj;
    id = *(short *)(aux + 0x0);
    state = *(CfCcrateState **)(obj + 0xb8);
    zeroF = lbl_803E3DD8;
    state->unk2C = zeroF;

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
        state->lingerTimer = *(short *)(aux + 0x1a);
        break;
    case 0x6be:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->latch3E = 0;
        state->gameBit2 = *(short *)(aux + 0x20);
        break;
    case 0x828:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->latch3E = 0;
        state->gameBit2 = *(short *)(aux + 0x20);
        if ((GameBit_Get(state->gameBit2) != 0) && (state->latch3E == 0)) {
            *(short *)(obj + 4) = 0x7fff;
            state->latch3E = 1;
        }
        break;
    case 0x6bf:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        state->gameBit2 = *(short *)(aux + 0x20);
        break;
    case 0x708:
        objAnim->bankIndex = (s8)*(short *)(aux + 0x1a);
        state->gameBit = *(short *)(aux + 0x20);
        if (objAnim->bankIndex >= 3) {
            objAnim->bankIndex = 0;
        }
        Obj_SetActiveModelIndex(obj, objAnim->bankIndex);
        break;
    case 0x6fc:
        state->gameBit = *(short *)(aux + 0x20);
        break;
    case 0x622:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->gameBit = *(short *)(aux + 0x20);
        break;
    case 0x6b4:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E3E30, 0);
        break;
    case 0x66c:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->gameBit = *(short *)(aux + 0x20);
        break;
    case 0x216:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        break;
    case 0x4bf:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        objAnim->bankIndex = *(u8 *)(aux + 0x19);
        state->gameBit = *(short *)(aux + 0x20);
        if (GameBit_Get(state->gameBit) != 0) {
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
        state->latch3E = 0;
        state->homeX = *(f32 *)(aux + 0x8);
        state->homeY = *(f32 *)(aux + 0xc);
        state->homeZ = *(f32 *)(aux + 0x10);
        state->oscPosA = state->oscPosB = lbl_803E3E30;
        state->unk28 = lbl_803E3DF4;
        state->unk20 = lbl_803E3E38;
        state->oscVelA = state->oscVelB = lbl_803E3DEC;
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
        state->oscVelB = (f32)(s32)*(short *)(aux + 0x1a);
        state->gameBit = *(short *)(aux + 0x20);
        if (GameBit_Get(state->gameBit) != 0) {
            state->oscVelB = state->oscVelB * lbl_803E3E3C;
        }
        break;
    case 0xd7:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(f32 *)(obj + 8) = zeroF;
        state->latch3E = 0;
        state->homeX = *(f32 *)(aux + 0x8);
        state->homeY = *(f32 *)(aux + 0xc);
        state->homeZ = *(f32 *)(aux + 0x10);
        state->oscVelA = state->oscVelB = state->unk20 = state->unk28 = state->oscPosA = state->oscPosB = lbl_803E3E30;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x125:
        *(short *)(obj + 0) = 0;
        *(short *)(obj + 2) = 0;
        *(short *)(obj + 4) = 0;
        *(f32 *)(obj + 8) = zeroF;
        *(int *)(obj + 0xf4) = 0;
        *(int *)(obj + 0xf8) = 0;
        state->oscVelB = lbl_803E3E40;
        state->oscVelA = lbl_803E3DEC;
        state->unk32 = 0;
        state->unk34 = (short)randomGetRange(0x3e8, 0x1388);
        state->proximityLatch = 1;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x10d:
        *(int *)(obj + 0x54) = 0;
        if (*(short *)(aux + 0x1a) == 0) {
            state->sfxTable = (u16 *)&lbl_803DBDE8;
            state->sfxCount = 1;
        }
        state->sfxPeriod = (u16)*(short *)(aux + 0x1c);
        state->sfxTimer = (short)state->sfxPeriod;
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
    FxEmitState *state;
    u8 *def;
    int spawnFlags;

    state = *(FxEmitState **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    spawnFlags = 0;
    if (state->effectId == 0x11) {
        fn_80137948(sCFTreasSharpyDebugFormat, obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14));
    }

    switch (def[0x28]) {
    case 0: {
        s16 mode = state->effectMode;
        if (mode == 0) {
            spawnFlags = 2;
        }
        if (mode == 1) {
            spawnFlags = 2;
        }
        if (mode == 2) {
            spawnFlags = 2;
        }
        break;
    }
    case 1: {
        s16 mode = state->effectMode;
        if (mode == 0) {
            spawnFlags = 4;
        }
        if (mode == 1) {
            spawnFlags = 4;
        }
        if (mode == 2) {
            spawnFlags = 4;
        }
        break;
    }
    case 2: {
        s16 mode = state->effectMode;
        if (mode == 0) {
            spawnFlags = 0x200001;
        }
        if (mode == 1) {
            spawnFlags = 1;
        }
        if (mode == 2) {
            spawnFlags = 1;
        }
        break;
    }
    case 3:
        spawnFlags = 0;
        break;
    default:
        spawnFlags = 2;
        break;
    }

    if ((spawnFlags & 1) != 0) {
        CFTreasSharpyFxSpawnArgs args;
        s16 i;

        args.x = *(f32 *)(obj + 0xc);
        args.y = *(f32 *)(obj + 0x10);
        args.z = *(f32 *)(obj + 0x14);
        args.yaw = *(s16 *)(obj + 0);
        args.roll = *(s16 *)(obj + 4);
        args.pitch = *(s16 *)(obj + 2);
        args.scale = lbl_803E3E48;
        if (state->emitCount > 0) {
            for (i = 0; i < state->emitCount; i++) {
                CFTREAS_PARTFX_SPAWN(obj, state->effectId, &args, spawnFlags, -1, 0);
            }
        } else {
            CFTREAS_PARTFX_SPAWN(obj, state->altEffectId, &args, spawnFlags, -1, 0);
        }
    } else {
        s16 i;
        void *resource;
        s16 mode = state->effectMode;

        if (mode == 0) {
            if (state->emitCount > 0) {
                for (i = 0; i < state->emitCount; i++) {
                    CFTREAS_PARTFX_SPAWN(obj, state->effectId, NULL, spawnFlags, -1, 0);
                }
            } else {
                CFTREAS_PARTFX_SPAWN(obj, state->effectId, NULL, spawnFlags, -1, 0);
            }
        } else if (mode == 1) {
            resource = Resource_Acquire((u16)(state->effectId + 0x58), 1);
            if (state->emitCount > 0) {
                for (i = 0; i < state->emitCount; i++) {
                    ((void (*)(int, int, int, int, int, int))((void **)*(int *)resource)[1])(obj, 0, 0, spawnFlags, -1, 0);
                }
            } else {
                ((void (*)(int, int, int, int, int, int))((void **)*(int *)resource)[1])(obj, 0, 0, spawnFlags, -1, 0);
            }
            Resource_Release(resource);
        } else if (mode == 2) {
            resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
            if (state->emitCount > 0) {
                for (i = 0; i < state->emitCount; i++) {
                    ((void (*)(int, int, int, int, int, int, int))((void **)*(int *)resource)[1])
                        (obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
                }
            } else {
                ((void (*)(int, int, int, int, int, int, int))((void **)*(int *)resource)[1])
                    (obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
            }
            Resource_Release(resource);
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
    FxEmitState *state;
    u8 *def;
    u8 event;
    int i;
    s8 delta;

    state = *(FxEmitState **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    for (i = 0; i < *(u8 *)(events + 0x8b); i++) {
        event = *(u8 *)(events + i + 0x81);
        if (event == 1) {
            fxemit_emitEffect(obj);
        }
        if (*(u8 *)(events + i + 0x81) == 2) {
            state->seqToggle = (u8)(1 - state->seqToggle);
        }
        *(u8 *)(events + i + 0x81) = 0;
    }

    if (state->seqToggle != 0) {
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

extern f32 timeDelta;
extern f32 sqrtf(f32);
extern u8 *Obj_GetPlayerObject(void);
extern int Sfx_PlayFromObject(int obj, int sfx);
extern f32 lbl_803E3E4C;

#pragma scheduling off
#pragma peephole off
void fxemit_update(int obj)
{
    FxEmitState *state;
    u8 *def;
    u8 *player;
    s16 e;
    s8 delta;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;

    state = *(FxEmitState **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    if (state->startDelay != 0) {
        state->startDelay -= (int)timeDelta;
        if (state->startDelay < 0) {
            state->startDelay = 0;
        }
    } else {
        *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0x24) * timeDelta + *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x2c) * timeDelta + *(f32 *)(obj + 0x14);
        *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            if (def == NULL) {
            } else {
            if (def[0x29] != 0 && def[0x29] != 0xff) {
                if (state->sfxTimer <= 0) {
                    int sfx;
                    state->suppressed = 0;
                    state->sfxTimer = def[0x29] * 100;
                    sfx = *(s16 *)(def + 0x2a);
                    if (sfx != 0) {
                        Sfx_PlayFromObject(obj, (u16)sfx);
                    }
                } else {
                    state->suppressed = 1;
                }
                state->sfxTimer -= framesThisStep;
            }

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

            if (state->enableBit == -1 || GameBit_Get(state->enableBit) != 0) {
                if (state->suppressed != 0) {
                } else {
                if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0) {
                    state->suppressed = 1;
                }
                if (def[0x29] == 0xff) {
                    state->suppressed = 1;
                }
                e = state->emitCount;
                if (e >= 0 || (e < 0 && *(int *)(obj + 0xf4) <= 0)) {
                    dx = *(f32 *)(obj + 0x18) - *(f32 *)(player + 0x18);
                    dy = *(f32 *)(obj + 0x1c) - *(f32 *)(player + 0x1c);
                    dz = *(f32 *)(obj + 0x20) - *(f32 *)(player + 0x20);
                    if (e == 0) {
                        state->suppressed = 1;
                    }
                    dist = sqrtf(dx * dx + dy * dy + dz * dz);
                    if (dist <= state->triggerRadius || lbl_803E3E4C == state->triggerRadius) {
                        fxemit_emitEffect(obj);
                    }
                    *(int *)(obj + 0xf4) = -(int)state->emitCount;
                } else if (e < 0 && *(int *)(obj + 0xf4) > 0) {
                    *(int *)(obj + 0xf4) -= framesThisStep;
                }
                }
            }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
