#include "main/dll/CF/CFTreasSharpy.h"
#include "main/dll/CF/dll_179.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/resource.h"

extern undefined4 FUN_80017a78();
extern undefined4 FUN_800305f8();

extern u32 GameBit_Get(int bit);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern u32 randomGetRange(int min, int max);

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
extern EffectInterface **gExpgfxInterface;
extern void *gModgfxInterface;
extern void *gPartfxInterface;
extern u8 framesThisStep;
extern f32 lbl_803E3E48;
extern char sCFTreasSharpyDebugFormat[];
extern void fn_80137948(char *fmt, ...);

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
    state = ((GameObject *)obj)->extra;
    zeroF = lbl_803E3DD8;
    state->unk2C = zeroF;

    switch (id) {
    case 0x2bb:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        ((GameObject *)obj)->anim.rotY = *(short *)(aux + 0x1a);
        ((GameObject *)obj)->anim.rotZ = *(short *)(aux + 0x1c);
        ((GameObject *)obj)->anim.rootMotionScale = zeroF;
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
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        break;
    case 0x726:
        ((GameObject *)obj)->animEventCallback = (void *)CFCrate_SeqFn;
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        break;
    case 0x71b:
        state->lingerTimer = *(short *)(aux + 0x1a);
        break;
    case 0x6be:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->latch3E = 0;
        state->gameBit2 = *(short *)(aux + 0x20);
        break;
    case 0x828:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->latch3E = 0;
        state->gameBit2 = *(short *)(aux + 0x20);
        if ((GameBit_Get(state->gameBit2) != 0) && (state->latch3E == 0)) {
            ((GameObject *)obj)->anim.rotZ = 0x7fff;
            state->latch3E = 1;
        }
        break;
    case 0x6bf:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        ((GameObject *)obj)->anim.rotY = *(short *)(aux + 0x1a);
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
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->gameBit = *(short *)(aux + 0x20);
        break;
    case 0x6b4:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        ((GameObject *)obj)->anim.rotY = *(short *)(aux + 0x1a);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E3E30, 0);
        break;
    case 0x66c:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        state->gameBit = *(short *)(aux + 0x20);
        break;
    case 0x216:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        ((GameObject *)obj)->anim.rotY = *(short *)(aux + 0x1a);
        break;
    case 0x4bf:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        objAnim->bankIndex = *(u8 *)(aux + 0x19);
        state->gameBit = *(short *)(aux + 0x20);
        if (GameBit_Get(state->gameBit) != 0) {
            ((GameObject *)obj)->anim.localPosY = lbl_803E3DFC + *(f32 *)(aux + 0xc);
        }
        break;
    case 0x8e:
        ((GameObject *)obj)->anim.rotX = 0;
        ((GameObject *)obj)->anim.rotY = 0;
        if (*(short *)(aux + 0x1c) >= 0x3e8) {
            ((GameObject *)obj)->anim.rootMotionScale = zeroF / ((f32)(s32)*(short *)(aux + 0x1c) / lbl_803E3DF4);
        } else {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3E34;
        }
        state->latch3E = 0;
        state->homeX = *(f32 *)(aux + 0x8);
        state->homeY = *(f32 *)(aux + 0xc);
        state->homeZ = *(f32 *)(aux + 0x10);
        state->oscPosA = state->oscPosB = lbl_803E3E30;
        state->unk28 = lbl_803E3DF4;
        state->unk20 = lbl_803E3E38;
        state->oscVelA = state->oscVelB = lbl_803E3DEC;
        ((GameObject *)obj)->anim.rotZ = 0;
        ((GameObject *)obj)->animEventCallback = (void *)CFCrate_SeqFn;
        break;
    case 0x7de:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        ((GameObject *)obj)->anim.rotY = 0;
        if (*(short *)(aux + 0x1c) >= 0x3e8) {
            ((GameObject *)obj)->anim.rootMotionScale = zeroF / ((f32)(s32)*(short *)(aux + 0x1c) / lbl_803E3DF4);
        } else {
            ((GameObject *)obj)->anim.rootMotionScale = zeroF;
        }
        state->oscVelB = (f32)(s32)*(short *)(aux + 0x1a);
        state->gameBit = *(short *)(aux + 0x20);
        if (GameBit_Get(state->gameBit) != 0) {
            state->oscVelB = state->oscVelB * lbl_803E3E3C;
        }
        break;
    case 0xd7:
        ((GameObject *)obj)->anim.rotX = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        ((GameObject *)obj)->anim.rootMotionScale = zeroF;
        state->latch3E = 0;
        state->homeX = *(f32 *)(aux + 0x8);
        state->homeY = *(f32 *)(aux + 0xc);
        state->homeZ = *(f32 *)(aux + 0x10);
        state->oscVelA = state->oscVelB = state->unk20 = state->unk28 = state->oscPosA = state->oscPosB = lbl_803E3E30;
        ((GameObject *)obj)->animEventCallback = (void *)CFCrate_SeqFn;
        break;
    case 0x125:
        ((GameObject *)obj)->anim.rotX = 0;
        ((GameObject *)obj)->anim.rotY = 0;
        ((GameObject *)obj)->anim.rotZ = 0;
        ((GameObject *)obj)->anim.rootMotionScale = zeroF;
        ((GameObject *)obj)->unkF4 = 0;
        ((GameObject *)obj)->unkF8 = 0;
        state->oscVelB = lbl_803E3E40;
        state->oscVelA = lbl_803E3DEC;
        state->unk32 = 0;
        state->unk34 = (short)randomGetRange(0x3e8, 0x1388);
        state->proximityLatch = 1;
        ((GameObject *)obj)->animEventCallback = (void *)CFCrate_SeqFn;
        break;
    case 0x10d:
        *(int *)&((GameObject *)obj)->anim.hitReactState = 0;
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
    ((void (*)(int, int, void *, int, int, int))(*(int *)(*(int *)gPartfxInterface + 8)))((int)(obj), id, data, flags, model, arg)

#pragma scheduling off
#pragma peephole off
void fxemit_emitEffect(FxEmitObject *obj)
{
    FxEmitState *state;
    FxEmitPlacement *def;
    int spawnFlags;

    state = obj->state;
    def = (FxEmitPlacement *)obj->objAnim.placementData;
    spawnFlags = 0;
    if (state->effectId == 0x11) {
        fn_80137948(sCFTreasSharpyDebugFormat, (int)obj, obj->objAnim.localPosX, obj->objAnim.localPosZ);
    }

    switch (def->spawnMode) {
    case FXEMIT_SPAWN_MODE_OBJECT: {
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
    case FXEMIT_SPAWN_MODE_OBJECT_ALT: {
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
    case FXEMIT_SPAWN_MODE_WORLD: {
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
    case FXEMIT_SPAWN_MODE_NONE:
        spawnFlags = 0;
        break;
    default:
        spawnFlags = 2;
        break;
    }

    if ((spawnFlags & 1) != 0) {
        CFTreasSharpyFxSpawnArgs args;
        s16 i;

        args.x = obj->objAnim.localPosX;
        args.y = obj->objAnim.localPosY;
        args.z = obj->objAnim.localPosZ;
        args.yaw = obj->objAnim.rotX;
        args.roll = obj->objAnim.rotZ;
        args.pitch = obj->objAnim.rotY;
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
                    ((void (*)(int, int, int, int, int, int))((void **)*(int *)resource)[1])((int)obj, 0, 0, spawnFlags, -1, 0);
                }
            } else {
                ((void (*)(int, int, int, int, int, int))((void **)*(int *)resource)[1])((int)obj, 0, 0, spawnFlags, -1, 0);
            }
            Resource_Release(resource);
        } else if (mode == 2) {
            resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
            if (state->emitCount > 0) {
                for (i = 0; i < state->emitCount; i++) {
                    ((void (*)(int, int, int, int, int, int, int))((void **)*(int *)resource)[1])
                        ((int)obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
                }
            } else {
                ((void (*)(int, int, int, int, int, int, int))((void **)*(int *)resource)[1])
                    ((int)obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
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
int fxemit_SeqFn(FxEmitObject *obj, int unused, int events)
{
    FxEmitState *state;
    FxEmitPlacement *def;
    u8 event;
    int i;
    s8 delta;

    state = obj->state;
    def = (FxEmitPlacement *)obj->objAnim.placementData;
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
        delta = def->yawStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO) {
            obj->objAnim.rotX = obj->objAnim.rotX + framesThisStep * 10;
        } else {
            obj->objAnim.rotX = obj->objAnim.rotX + delta * framesThisStep * 100;
        }

        delta = def->pitchStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO) {
            obj->objAnim.rotY = obj->objAnim.rotY + framesThisStep * 10;
        } else {
            obj->objAnim.rotY = obj->objAnim.rotY + delta * framesThisStep * 100;
        }

        delta = def->rollStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO) {
            obj->objAnim.rotZ = obj->objAnim.rotZ + framesThisStep * 10;
        } else {
            obj->objAnim.rotZ = obj->objAnim.rotZ + delta * framesThisStep * 100;
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
void fxemit_free(FxEmitObject *obj)
{
    (*gExpgfxInterface)->freeObject(obj);
    ((void (*)(int))((void **)*(int *)gModgfxInterface)[5])((int)obj);
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
extern ObjAnimComponent *Obj_GetPlayerObject(void);
extern int Sfx_PlayFromObject(int obj, int sfx);
extern f32 lbl_803E3E4C;

#pragma scheduling off
#pragma peephole off
void fxemit_update(FxEmitObject *obj)
{
    FxEmitState *state;
    FxEmitPlacement *def;
    ObjAnimComponent *player;
    s16 e;
    s8 delta;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;

    state = obj->state;
    def = (FxEmitPlacement *)obj->objAnim.placementData;
    if (state->startDelay != 0) {
        state->startDelay -= (int)timeDelta;
        if (state->startDelay < 0) {
            state->startDelay = 0;
        }
    } else {
        obj->objAnim.localPosX = obj->objAnim.velocityX * timeDelta + obj->objAnim.localPosX;
        obj->objAnim.localPosY = obj->objAnim.velocityY * timeDelta + obj->objAnim.localPosY;
        obj->objAnim.localPosZ = obj->objAnim.velocityZ * timeDelta + obj->objAnim.localPosZ;
        obj->objAnim.worldPosX = obj->objAnim.localPosX;
        obj->objAnim.worldPosY = obj->objAnim.localPosY;
        obj->objAnim.worldPosZ = obj->objAnim.localPosZ;
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            if (def == NULL) {
            } else {
            if (def->sfxPeriod != 0 && def->sfxPeriod != FXEMIT_SFX_SUPPRESS) {
                if (state->sfxTimer <= 0) {
                    int sfx;
                    state->suppressed = 0;
                    state->sfxTimer = def->sfxPeriod * 100;
                    sfx = def->sfxId;
                    if (sfx != 0) {
                        Sfx_PlayFromObject((int)obj, (u16)sfx);
                    }
                } else {
                    state->suppressed = 1;
                }
                state->sfxTimer -= framesThisStep;
            }

            delta = def->yawStep;
            if (delta == FXEMIT_ROTATION_STEP_AUTO) {
                obj->objAnim.rotX = obj->objAnim.rotX + framesThisStep * 10;
            } else {
                obj->objAnim.rotX = obj->objAnim.rotX + delta * framesThisStep * 100;
            }

            delta = def->pitchStep;
            if (delta == FXEMIT_ROTATION_STEP_AUTO) {
                obj->objAnim.rotY = obj->objAnim.rotY + framesThisStep * 10;
            } else {
                obj->objAnim.rotY = obj->objAnim.rotY + delta * framesThisStep * 100;
            }

            delta = def->rollStep;
            if (delta == FXEMIT_ROTATION_STEP_AUTO) {
                obj->objAnim.rotZ = obj->objAnim.rotZ + framesThisStep * 10;
            } else {
                obj->objAnim.rotZ = obj->objAnim.rotZ + delta * framesThisStep * 100;
            }

            if (state->enableBit == -1 || GameBit_Get(state->enableBit) != 0) {
                if (state->suppressed != 0) {
                } else {
                if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0) {
                    state->suppressed = 1;
                }
                if (def->sfxPeriod == FXEMIT_SFX_SUPPRESS) {
                    state->suppressed = 1;
                }
                e = state->emitCount;
                if (e >= 0 || (e < 0 && obj->emitCooldown <= 0)) {
                    dx = obj->objAnim.worldPosX - player->worldPosX;
                    dy = obj->objAnim.worldPosY - player->worldPosY;
                    dz = obj->objAnim.worldPosZ - player->worldPosZ;
                    if (e == 0) {
                        state->suppressed = 1;
                    }
                    dist = sqrtf(dx * dx + dy * dy + dz * dz);
                    if (dist <= state->triggerRadius || lbl_803E3E4C == state->triggerRadius) {
                        fxemit_emitEffect(obj);
                    }
                    obj->emitCooldown = -(int)state->emitCount;
                } else if (e < 0 && obj->emitCooldown > 0) {
                    obj->emitCooldown -= framesThisStep;
                }
                }
            }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
