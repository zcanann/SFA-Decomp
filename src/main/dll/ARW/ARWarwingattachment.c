#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "global.h"

/* Per-object extra state for the WM laser beam emitter. */
typedef struct LaserBeamState {
    int texture;
    f32 unk04;        /* 0x04: cur/prev pair A (reset each update) */
    f32 unk08;

    f32 beamX;        /* 0x0c: beam base position */
    f32 beamX2;       /* 0x10 */
    f32 beamZ;        /* 0x14 */
    f32 beamZ2;       /* 0x18 */
    f32 sweepPhase;   /* 0x1c */
    u8 pad20[4];
    u8 unk24;
    u8 unk25;
    u8 unk26;
    s8 unk27;
    s16 unk28;
    s16 sweepYaw;     /* 0x2a */
    s16 fireTimer;    /* 0x2c */
    s16 unk2E;
    s16 firePeriod;   /* 0x30 */
    s16 emitterSlot;  /* 0x32: modgfx handle head */
    u8 pad34[0xc];
    f32 targetX;      /* 0x40 */
    u8 pad44[4];
    f32 targetZ;      /* 0x48 */
    u8 unk4C;
    u8 active;        /* 0x4d */
    u8 beamKind;      /* 0x4e: 30/1/other texture pick */
} LaserBeamState;
STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */
typedef struct PressureSwitchState {
    s8 holdTimer;      /* frames the switch stays pressed */
    s8 chimeLatch;
    s16 retriggerTimer;
    s16 mapGameBit;    /* 0xf45/0xf46 per-map bit, -1 none */
    u8 flags;          /* PressureSwitchFlags / PswFlags overlay */
    u8 pad7;
} PressureSwitchState;

/* wmlasertarget_getExtraSize == 0x4. */
typedef struct WmLaserTargetState {
    s16 cooldown;
    u8 toggleQueued;
    u8 pad3;
} WmLaserTargetState;

/* WM_colrise_getExtraSize == 0x4. */
typedef struct WMColriseState {
    s16 gameBit;
    u8 raiseTimer;
    u8 pad3;
} WMColriseState;

/* wmtorch_getExtraSize == 0x10. */
typedef struct WmTorchState {
    void *linkedObj;
    f32 unk04;
    u8 pad08[2];
    s16 unk0A;
    u8 torchType;  /* params[0x19]: 0 / 0x7f / other */
    u8 pad0D[3];
} WmTorchState;

/* lightsource_getExtraSize == 0x1c. */
typedef struct LightSourceState {
    void *light;
    f32 fxTimer;
    u8 pad08[4];
    f32 sparkTimer;
    int gameBit;    /* 0x10: -1 none */
    u8 mode;        /* 0x14: 1 = hit-toggleable */
    u8 fxType;
    u8 fxArg;
    u8 lit;         /* 0x17 */
    u8 litPrev;
    u8 sparks;      /* 0x19 */
    u8 loopFlags;   /* 0x1a: LightSourceFlagByte */
    u8 pad1B;
} LightSourceState;
STATIC_ASSERT(sizeof(LightSourceState) == 0x1c);

/* dll_1FF_getExtraSize == 0x8 (grabbable hook). */
typedef struct Dll1FFState {
    s16 msgLo;
    s16 msgHi;
    u8 pad4;
    s8 grabPhase;  /* 0 free, 1 held, 2 releasing */
    u8 sendFlag;   /* 0x6 */
    u8 pad7;
} Dll1FFState;

/* dll_200_getExtraSize == 0x28 (kid attachment actor). */
typedef struct Dll200State {
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    f32 animSpeed;    /* 0x0c */
    f32 hitReactVec;  /* 0x10: head of the f32 pair ObjHitReact_Update fills */
    f32 unk14;
    s16 unk18;
    u8 pad1A[2];
    u32 unk1C;
    s16 modeTimer;    /* 0x20 */
    u8 mode;          /* 0x22: 1-5 wander, 12 turn, 13 play */
    u8 prevMode;      /* 0x23 */
    u8 latch24;       /* 0x24: GameBit 0xd0 latch */
    u8 mode25;        /* 0x25: trigger pick */
    u8 defNoLow;      /* 0x26 */
    s8 counter27;     /* 0x27: hug/talk counter */
} Dll200State;
STATIC_ASSERT(sizeof(Dll200State) == 0x28);

#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern uint FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined8 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053754();
extern int FUN_8005398c();
extern int FUN_800632f4();
extern undefined4 FUN_80135814();
extern uint FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294cc0();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();
extern int FUN_80294d6c();

extern undefined4 DAT_802c2bf0;
extern undefined4 DAT_802c2bf4;
extern undefined4 DAT_802c2bf8;
extern undefined4 DAT_802c2bfc;
extern undefined4 DAT_802c2c00;
extern undefined4 DAT_802c2c04;
extern undefined4 DAT_803294d8;
extern undefined4 DAT_803295b4;
extern undefined4 DAT_803295b8;
extern undefined4 DAT_803295bc;
extern undefined4 DAT_803295c0;
extern undefined4 DAT_803295c4;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern MapEventInterface **DAT_803dd72c;
extern undefined4* DAT_803de900;
extern f64 DOUBLE_803e69e8;
extern f64 DOUBLE_803e6a38;
extern f64 DOUBLE_803e6a50;
extern f32 lbl_803DC074;
extern f32 lbl_803E699C;
extern f32 lbl_803E69A0;
extern f32 lbl_803E69A8;
extern f32 lbl_803E69AC;
extern f32 lbl_803E69B0;
extern f32 lbl_803E69B4;
extern f32 lbl_803E69C0;
extern f32 lbl_803E69C4;
extern f32 lbl_803E69C8;
extern f32 lbl_803E69CC;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D4;
extern f32 lbl_803E69D8;
extern f32 lbl_803E69DC;
extern f32 lbl_803E69E0;
extern f32 lbl_803E69F4;
extern f32 lbl_803E69F8;
extern f32 lbl_803E69FC;
extern f32 lbl_803E6A00;
extern f32 lbl_803E6A04;
extern f32 lbl_803E6A08;
extern f32 lbl_803E6A0C;
extern f32 lbl_803E6A10;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A30;
extern f32 lbl_803E6A34;
extern f32 lbl_803E6A40;
extern f32 lbl_803E6A44;
extern f32 lbl_803E6A48;
extern f32 lbl_803E6A4C;
extern f32 lbl_803E6A58;
extern f32 lbl_803E6A64;
extern f32 lbl_803E6A68;
extern f32 lbl_803E6A6C;
extern f32 lbl_803E6A70;
extern f32 lbl_803E6A74;
extern f32 lbl_803E6A78;
extern f32 lbl_803E6A80;

/*
 * --INFO--
 *
 * Function: LaserBeam_update
 * EN v1.0 Address: 0x801F0B50
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801F0DA4
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void LaserBeam_update(int param_1)
{
    extern void *Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int id);
    extern void GameBit_Set(int slot, int val);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfx);
    extern int objGetAnimState80A(void *obj);
    extern f32 mathCosf(f32 x);
    extern f32 mathSinf(f32 x);
    extern int *lbl_803DDC80;
    extern int *gModgfxInterface;
    extern EffectInterface **gPartfxInterface;
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D10;
    extern f32 lbl_803E5D14;
    extern f32 lbl_803E5D18;
    extern f32 lbl_803E5D1C;
    extern f32 lbl_803E5D20;
    extern f32 lbl_803E5D24;
    extern f32 lbl_803E5D28;
    extern f32 lbl_803E5D2C;
    extern f32 lbl_803E5D30;
    extern f32 lbl_803E5D34;
    extern f32 lbl_803E5D38;
    extern f32 lbl_803E5D3C;
    extern f32 lbl_803E5D40;
    extern f32 lbl_803E5D44;
    extern f32 lbl_803E5D48;
    char *t;
    LaserBeamState *b;
    char *player;
    u8 c;
    int i;
    u16 sfx;
    f32 dz;
    f32 dz2;
    f32 sinv;
    f32 cosv;
    f32 range;
    f32 dot;
    f32 dy;
    f32 dx;
    f32 dzp;
    f32 a;
    f32 lat;
    f32 spread;
    f32 fz;

    t = *(char **)(param_1 + 0x4c);
    b = *(LaserBeamState **)(param_1 + 0xb8);
    b->fireTimer -= framesThisStep;
    if (GameBit_Get(*(s16 *)(t + 0x1e)) == 0) {
        if (b->fireTimer < 0) {
            if (b->unk25 == 0) {
                c = b->beamKind;
                if (c == 3 || c == 30) {
                    b->fireTimer = b->firePeriod;
                } else {
                    if (c == 0 && b->emitterSlot != -1) {
                        ((ModgfxInterface *)*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                    }
                    b->fireTimer = b->firePeriod;
                }
                b->sweepPhase = lbl_803E5D10;
            } else {
                b->fireTimer = 150;
            }
            b->active = 0;
        } else if (b->fireTimer < b->unk2E) {
            if (b->active == 0) {
                b->active = 1;
                c = b->beamKind;
                if (c == 1) {
                    if (lbl_803DDC80 != NULL) {
                        (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                            param_1, 2, 0, 0x10004, -1, 0);
                    }
                } else if (c != 30 && c != 0) {
                    (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                        param_1, 0, 0, 0x10004, -1, 0);
                }
            }
            if (b->fireTimer < 0x28) {
                if (b->sweepPhase >= lbl_803E5D10 && b->unk25 == 0) {
                    b->sweepPhase = -(lbl_803E5D14 * timeDelta - b->sweepPhase);
                }
            } else if (b->fireTimer < 0x8c) {
                if (b->active == 1) {
                    b->active = 2;
                    c = b->beamKind;
                    if (c == 1) {
                        if (lbl_803DDC80 != NULL) {
                            (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                param_1, 3, 0, 0x10004, -1, 0);
                        }
                    } else if (c == 30) {
                        if (lbl_803DDC80 != NULL) {
                            b->emitterSlot =
                                (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                    param_1, 30, 0, 0x10004, -1, 0);
                        }
                    } else if (c != 0) {
                        if (lbl_803DDC80 != NULL) {
                            (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                param_1, 1, 0, 0x10004, -1, 0);
                        }
                    } else {
                        if (lbl_803DDC80 != NULL && b->emitterSlot == -1) {
                            if (b->emitterSlot != -1) {
                                ((ModgfxInterface *)*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                            }
                            if (lbl_803DDC80 != NULL) {
                                b->emitterSlot =
                                    (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                        param_1, 0, 0, 0x10004, -1, 0);
                            }
                        }
                    }
                }
            } else if (b->sweepPhase <= lbl_803E5D18) {
                b->sweepPhase = lbl_803E5D1C * timeDelta + b->sweepPhase;
            }
        }
    } else if (b->beamKind == 0 && b->emitterSlot != -1) {
        ((ModgfxInterface *)*gModgfxInterface)->releaseHandle(&b->emitterSlot);
    }
    dz = (f32)(int)*(s16 *)(t + 0x1a);
    dz2 = dz * dz;
    sinv = mathCosf((lbl_803E5D20 * (f32)(int)*(s16 *)param_1) / lbl_803E5D24);
    cosv = mathSinf((lbl_803E5D20 * (f32)(int)*(s16 *)param_1) / lbl_803E5D24);
    dot = -(*(f32 *)(param_1 + 0xc) * sinv + *(f32 *)(param_1 + 0x14) * cosv);
    player = Obj_GetPlayerObject();
    b->unk27 = (s8)(b->unk27 - framesThisStep);
    if (b->unk27 <= 0) {
        b->unk27 = 0;
    } else if (b->beamKind == 0 && b->emitterSlot != -1) {
        ((ModgfxInterface *)*gModgfxInterface)->releaseHandle(&b->emitterSlot);
    }
    if ((dot + (sinv * *(f32 *)(player + 0xc) + cosv * *(f32 *)(player + 0x14)) > lbl_803E5D10 &&
         b->beamKind != 2) ||
        b->beamKind == 30) {
        b->sweepYaw -= framesThisStep;
        if (b->sweepYaw < 0) {
            b->sweepYaw = 0;
            b->unk25 = 0;
        }
    } else {
        b->sweepYaw += framesThisStep;
        if (b->sweepYaw > 60) {
            b->sweepYaw = 60;
            b->unk25 = 1;
        }
    }
    if (b->unk25 == 0) {
        b->unk24 = (u8)(b->active & 3);
    } else {
        b->unk24 = 2;
    }
    if (GameBit_Get(*(s16 *)(t + 0x1e)) != 0) {
        b->unk24 = 0;
    }
    if (b->unk27 == 0) {
        b->unk28 = 0;
    }
    if (player != NULL && b->unk27 == 0 && b->unk24 == 2) {
        range = lbl_803E5D28 + (f32)(int)*(s8 *)&b->unk26;
        dy = *(f32 *)(player + 0x10) - *(f32 *)(param_1 + 0x10);
        if (dy < range && dy > -(lbl_803E5D2C + range)) {
            dx = *(f32 *)(player + 0xc) - *(f32 *)(param_1 + 0xc);
            dzp = *(f32 *)(player + 0x14) - *(f32 *)(param_1 + 0x14);
            if (dx * dx + dzp * dzp < dz2) {
                lat = dot + (sinv * *(f32 *)(player + 0xc) + cosv * *(f32 *)(player + 0x14));
                a = lat;
                if (lat < lbl_803E5D10) {
                    a = -lat;
                }
                if (a > lbl_803E5D30) {
                    a = lbl_803E5D30;
                }
                b->unk28 = (s16)(int)((lbl_803E5D30 - a) * lbl_803E5D34);
                if (!(lat < lbl_803E5D38 && lat > lbl_803E5D3C) && b->unk4C == 1) {
                    ((ModgfxInterface *)*gModgfxInterface)->detachSource((void *)param_1);
                    b->unk4C = 0;
                }
                if (lat < range && lat > -range) {
                    if (objGetAnimState80A(player) == 0x1d7 && b->beamKind != 1) {
                        GameBit_Set(0x468, 1);
                    } else {
                        if (dot + (sinv * *(f32 *)(player + 0x80) +
                                   cosv * *(f32 *)(player + 0x88)) < lbl_803E5D10) {
                            spread = lbl_803E5D40;
                        } else {
                            spread = lbl_803E5D44;
                        }
                        Sfx_PlayAtPositionFromObject(param_1, *(f32 *)(player + 0xc),
                                                     *(f32 *)(param_1 + 0x10),
                                                     *(f32 *)(player + 0x14), 0x1c9);
                        if (*(s16 *)(*(char **)(player + 0xb8) + 0x81a) == 0) {
                            sfx = 31;
                        } else {
                            sfx = 35;
                        }
                        Sfx_PlayFromObject((int)player, sfx);
                        for (i = 0; i < 4; i++) {
                            (*gPartfxInterface)->spawnObject(Obj_GetPlayerObject(), 0x198,
                                                             NULL, 4, -1, NULL);
                        }
                        b->targetX = sinv * spread + *(f32 *)(player + 0xc);
                        b->targetZ = cosv * spread + *(f32 *)(player + 0x14);
                        c = b->beamKind;
                        if (c == 0 || c == 1) {
                            ObjMsg_SendToObject(player, 0x60003, (char *)b + 0x34, 0);
                        } else if ((u8)(c - 2) <= 1 || c == 30) {
                            ObjMsg_SendToObject(player, 0x60004, (char *)b + 0x34, 0);
                        }
                        *(u8 *)&b->unk27 = 2;
                    }
                }
            }
        }
    }
    if (b->unk24 == 0) {
        if (b->beamKind == 30 && b->emitterSlot != -1) {
            ((ModgfxInterface *)*gModgfxInterface)->releaseHandle(&b->emitterSlot);
        }
        if (b->unk4C == 1) {
            ((ModgfxInterface *)*gModgfxInterface)->detachSource((void *)param_1);
            b->unk4C = 0;
        }
    }
    fz = lbl_803E5D10;
    b->unk04 = fz;
    b->beamX = fz;
    b->beamZ = fz;
    b->unk08 = b->unk04;
    b->beamX2 = b->beamX;
    b->beamZ2 = b->beamZ + dz;
    b->unk26 = 8;
    *(f32 *)(param_1 + 0x98) = lbl_803E5D48 * timeDelta + *(f32 *)(param_1 + 0x98);
    if (*(f32 *)(param_1 + 0x98) > lbl_803E5D18) {
        *(f32 *)(param_1 + 0x98) = *(f32 *)(param_1 + 0x98) - lbl_803E5D18;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801f0cb8
 * EN v1.0 Address: 0x801F0CB8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801F0F8C
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0cb8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if ((visible != 0) && (*(char *)(*(int *)(param_1 + 0xb8) + 9) == '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0cf0
 * EN v1.0 Address: 0x801F0CF0
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801F0FD4
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0cf0(int param_1)
{
  uint uVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(short *)(*(int *)(param_1 + 0xb8) + 6) == 2)) &&
     (uVar1 = FUN_80017690(0x9ad), uVar1 == 0)) {
    (*gObjectTriggerInterface)->runSequence(4, (void *)param_1, -1);
    FUN_80006ba8(0,0x100);
    FUN_80017698(0x9ad,1);
  }
  ObjAnim_AdvanceCurrentMove((double)lbl_803E699C,(double)lbl_803DC074,param_1,
                             (ObjAnimEventList *)0x0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0d8c
 * EN v1.0 Address: 0x801F0D8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F1078
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0d8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f0d90
 * EN v1.0 Address: 0x801F0D90
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801F112C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0d90(int param_1)
{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6fc + 0x18))();
  if (*piVar1 != 0) {
    FUN_80053754();
    *piVar1 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0de8
 * EN v1.0 Address: 0x801F0DE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F1188
 * EN v1.1 Size: 2376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0de8(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f0dec
 * EN v1.0 Address: 0x801F0DEC
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801F1AD0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0dec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  int *piVar4;
  undefined8 uVar5;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  uVar5 = ObjMsg_AllocQueue((int)param_9,2);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  if (*(short *)(param_10 + 0x1c) == 0) {
    uVar3 = 0x50;
    uVar1 = randomGetRange(0xffffffb0,0x50);
    *(short *)(piVar4 + 0xc) = (short)uVar1 + 400;
  }
  else {
    *(short *)(piVar4 + 0xc) = *(short *)(param_10 + 0x1c);
    uVar3 = extraout_r4;
  }
  *(undefined2 *)(piVar4 + 0xb) = *(undefined2 *)(piVar4 + 0xc);
  *(undefined *)((int)piVar4 + 0x4d) = 0;
  piVar4[7] = (int)lbl_803E69A8;
  *(undefined *)((int)piVar4 + 0x4e) = *(undefined *)(param_10 + 0x19);
  *(undefined2 *)((int)piVar4 + 0x2e) = 0x118;
  *(undefined2 *)((int)piVar4 + 0x32) = 0xffff;
  if (*(char *)((int)piVar4 + 0x4e) == '\x1e') {
    if (*piVar4 == 0) {
      iVar2 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e9,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*(char *)((int)piVar4 + 0x4e) == '\x01') {
    if (*piVar4 == 0) {
      iVar2 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x23d,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*piVar4 == 0) {
    iVar2 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xd9,uVar3,
                         param_11,param_12,param_13,param_14,param_15,param_16);
    *piVar4 = iVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f10ac
 * EN v1.0 Address: 0x801F10AC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801F1BEC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f10ac(void)
{
  FUN_80006b0c(DAT_803de900);
  DAT_803de900 = (undefined4*)0x0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f10d8
 * EN v1.0 Address: 0x801F10D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F1C18
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f10d8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f10dc
 * EN v1.0 Address: 0x801F10DC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F1C70
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f10dc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1104
 * EN v1.0 Address: 0x801F1104
 * EN v1.0 Size: 1192b
 * EN v1.1 Address: 0x801F1CA4
 * EN v1.1 Size: 1104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1104(void)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar6;
  uint uVar5;
  int iVar7;
  int iVar8;
  char *pcVar9;
  int iVar10;
  bool bVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  
  uVar3 = FUN_8028683c();
  iVar4 = FUN_80017a98();
  iVar10 = *(int *)(uVar3 + 0x4c);
  pcVar9 = *(char **)(uVar3 + 0xb8);
  dVar13 = (double)FUN_8001771c((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18));
  dVar12 = (double)lbl_803E69F4;
  *pcVar9 = *pcVar9 + -1;
  if (*pcVar9 < '\0') {
    *pcVar9 = '\0';
    pcVar9[1] = '\0';
  }
  iVar4 = 0;
  pcVar9[6] = pcVar9[6] & 0x7f;
  if ((*(int *)(uVar3 + 0x58) == 0) || (*(char *)(*(int *)(uVar3 + 0x58) + 0x10f) < '\x01')) {
    if ((*(char *)(uVar3 + 0xac) == '\v') &&
       (((cVar6 = (*DAT_803dd72c)->getMode((int)*(char *)(uVar3 + 0xac)), cVar6 == '\x03' &&
         (iVar4 = FUN_80017a90(), iVar4 != 0)) &&
        (dVar14 = (double)FUN_8001771c((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18)),
        dVar14 < (double)lbl_803E69FC)))) {
      *pcVar9 = '\x05';
    }
  }
  else {
    *(short *)(pcVar9 + 2) = *(short *)(iVar10 + 0x1e) * 0x3c;
    dVar14 = (double)lbl_803E69F8;
    for (iVar8 = 0; iVar8 < *(char *)(*(int *)(uVar3 + 0x58) + 0x10f); iVar8 = iVar8 + 1) {
      iVar7 = *(int *)(*(int *)(uVar3 + 0x58) + iVar4 + 0x100);
      if (*(short *)(iVar7 + 0x46) == 0x6d) {
        pcVar9[6] = pcVar9[6] & 0x7fU | 0x80;
      }
      if (dVar14 < (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar3 + 0x10))) {
        *pcVar9 = '\x05';
      }
      if (((pcVar9[1] == '\0') && (iVar7 != 0)) && (*(short *)(iVar7 + 0x46) == 0x146)) {
        if (dVar13 <= dVar12) {
          FUN_80006824(uVar3,SFXmn_sml_trex_fstep);
        }
        pcVar9[1] = '\x01';
      }
      iVar4 = iVar4 + 4;
    }
  }
  if (((*(char *)(uVar3 + 0xac) == '\v') &&
      (cVar6 = (*DAT_803dd72c)->getMode((int)*(char *)(uVar3 + 0xac)), cVar6 == '\x01')) && (dVar13 <= dVar12)) {
    if (*pcVar9 == '\0') {
      uVar5 = FUN_80017690(0x905);
      if (uVar5 != 0) {
        FUN_80017698(0x905,0);
      }
    }
    else {
      fVar1 = *(float *)(iVar10 + 0xc) - *(float *)(uVar3 + 0x10);
      if (((fVar1 <= lbl_803E6A00) || (lbl_803E6A04 <= fVar1)) ||
         (uVar5 = FUN_80017690((int)*(short *)(pcVar9 + 4)), uVar5 != 0)) {
        uVar5 = FUN_80017690(0x905);
        if (uVar5 != 0) {
          FUN_80017698(0x905,0);
        }
      }
      else {
        FUN_80017698(0x905,1);
      }
    }
  }
  bVar11 = false;
  if (*pcVar9 == '\0') {
    if (*(short *)(pcVar9 + 2) == 0) {
      *(float *)(uVar3 + 0x10) = lbl_803E6A0C * lbl_803DC074 + *(float *)(uVar3 + 0x10);
      bVar11 = *(float *)(uVar3 + 0x10) <= *(float *)(iVar10 + 0xc);
      if (!bVar11) {
        *(float *)(uVar3 + 0x10) = *(float *)(iVar10 + 0xc);
      }
      FUN_80017698((int)*(short *)(iVar10 + 0x1c),0);
      if (((int)*(short *)(pcVar9 + 4) != 0xffffffff) && (((byte)pcVar9[6] >> 6 & 1) == 0)) {
        FUN_80017698((int)*(short *)(pcVar9 + 4),0);
      }
    }
  }
  else {
    fVar2 = *(float *)(iVar10 + 0xc) - lbl_803E6A04;
    fVar1 = *(float *)(uVar3 + 0x10);
    if (fVar2 <= fVar1) {
      *(float *)(uVar3 + 0x10) = -(lbl_803E6A0C * lbl_803DC074 - fVar1);
      if (fVar2 <= *(float *)(uVar3 + 0x10)) {
        bVar11 = true;
      }
      else {
        *(float *)(uVar3 + 0x10) = fVar2;
        FUN_80017698((int)*(short *)(iVar10 + 0x1c),1);
        if ((int)*(short *)(pcVar9 + 4) != 0xffffffff) {
          FUN_80017698((int)*(short *)(pcVar9 + 4),1);
          if (pcVar9[6] < '\0') {
            pcVar9[6] = pcVar9[6] & 0xbfU | 0x40;
          }
        }
      }
    }
    else {
      *(float *)(uVar3 + 0x10) = lbl_803E6A08 * lbl_803DC074 + fVar1;
      if (fVar2 < *(float *)(uVar3 + 0x10)) {
        *(float *)(uVar3 + 0x10) = fVar2;
      }
      FUN_80017698((int)*(short *)(iVar10 + 0x1c),1);
      if (pcVar9[6] < '\0') {
        FUN_80017698((int)*(short *)(pcVar9 + 4),1);
      }
    }
  }
  if (bVar11) {
    FUN_80006824(uVar3,SFXmn_sml_trex_roar);
  }
  else {
    FUN_8000680c(uVar3,8);
  }
  if ((*(short *)(pcVar9 + 2) != 0) &&
     (*(ushort *)(pcVar9 + 2) = *(short *)(pcVar9 + 2) - (ushort)DAT_803dc070,
     *(short *)(pcVar9 + 2) < 0)) {
    pcVar9[2] = '\0';
    pcVar9[3] = '\0';
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f15ac
 * EN v1.0 Address: 0x801F15AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F20F4
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f15ac(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f15b0
 * EN v1.0 Address: 0x801F15B0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801F2228
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f15b0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 renderState)
{
  if (*(int *)(param_1 + 0xf8) == 0) {
    if (renderState == 0) {
      return;
    }
  }
  else if (renderState != -1) {
    return;
  }
  if (((ObjAnimComponent *)param_1)->modelInstance->shadowType == 2) {
    if (*(short *)(param_1 + 0xb4) == -1) {
      ((ObjAnimComponent *)param_1)->modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_FADE_OUT;
    }
    else {
      ((ObjAnimComponent *)param_1)->modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
    }
  }
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1634
 * EN v1.0 Address: 0x801F1634
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801F22BC
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1634(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined uVar8;
  float *pfVar6;
  uint uVar7;
  int iVar9;
  float fVar10;
  int iVar11;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar12;
  undefined8 uVar13;
  int local_18 [3];
  
  puVar12 = *(undefined2 **)(param_9 + 0xb8);
  iVar5 = FUN_80017a98();
  if (*(char *)((int)puVar12 + 5) == '\0') {
    uVar8 = 0;
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) && (*(int *)(param_9 + 0xf8) == 0)) {
      *puVar12 = 0;
      puVar12[1] = 0x28;
      FUN_80006ba8(0,0x100);
      uVar8 = 1;
    }
    *(undefined *)((int)puVar12 + 5) = uVar8;
    if (*(char *)((int)puVar12 + 5) != '\0') {
      *(undefined *)(puVar12 + 3) = 1;
    }
    if (*(int *)(param_9 + 0xf8) == 0) {
      ObjHits_EnableObject(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
      *(float *)(param_9 + 0x28) = -(lbl_803E6A1C * lbl_803DC074 - *(float *)(param_9 + 0x28));
      *(float *)(param_9 + 0x10) =
           *(float *)(param_9 + 0x28) * lbl_803DC074 + *(float *)(param_9 + 0x10);
      iVar5 = FUN_800632f4((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                           (double)*(float *)(param_9 + 0x14),param_9,local_18,0,1);
      fVar4 = lbl_803E6A24;
      fVar3 = lbl_803E6A20;
      fVar10 = 0.0;
      iVar11 = 0;
      iVar9 = 0;
      if (0 < iVar5) {
        do {
          pfVar6 = *(float **)(local_18[0] + iVar9);
          if (*(char *)(pfVar6 + 5) != '\x0e') {
            fVar2 = *pfVar6;
            if ((*(float *)(param_9 + 0x10) < fVar2) &&
               ((fVar2 - fVar3 < *(float *)(param_9 + 0x10) || (iVar11 == 0)))) {
              fVar10 = pfVar6[4];
              *(float *)(param_9 + 0x10) = fVar2;
              *(float *)(param_9 + 0x28) = fVar4;
            }
          }
          iVar9 = iVar9 + 4;
          iVar11 = iVar11 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      if (fVar10 != 0.0) {
        iVar5 = *(int *)((int)fVar10 + 0x58);
        cVar1 = *(char *)(iVar5 + 0x10f);
        *(char *)(iVar5 + 0x10f) = cVar1 + '\x01';
        *(uint *)(iVar5 + cVar1 * 4 + 0x100) = param_9;
      }
    }
  }
  else {
    uVar13 = ObjHits_DisableObject(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar7 = FUN_80006c00(0);
    if ((uVar7 & 0x100) != 0) {
      *(undefined *)(puVar12 + 3) = 0;
      uVar13 = FUN_80006ba8(0,0x100);
    }
    if (*(int *)(param_9 + 0xf8) == 1) {
      *(undefined *)((int)puVar12 + 5) = 2;
    }
    if ((*(char *)((int)puVar12 + 5) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) {
      *(undefined *)((int)puVar12 + 5) = 0;
      *(undefined *)(puVar12 + 3) = 0;
    }
    if (*(char *)(puVar12 + 3) != '\0') {
      ObjMsg_SendToObject(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x100008,
                   param_9,CONCAT22(puVar12[1],*puVar12),in_r7,in_r8,in_r9,in_r10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1934
 * EN v1.0 Address: 0x801F1934
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F2568
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1934(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f195c
 * EN v1.0 Address: 0x801F195C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801F259C
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f195c(int param_1)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 != 0) {
    *(undefined *)(psVar3 + 1) = 1;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  if ((*psVar3 < 1) && (*(char *)(psVar3 + 1) != '\0')) {
    uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x1e));
    if (uVar2 == 0) {
      FUN_80017a78(param_1,1);
      FUN_80017698((int)*(short *)(iVar4 + 0x1e),1);
      FUN_80017698((int)*(short *)(iVar4 + 0x20),1);
    }
    else {
      FUN_80017a78(param_1,0);
      FUN_80017698((int)*(short *)(iVar4 + 0x1e),0);
      FUN_80017698((int)*(short *)(iVar4 + 0x20),0);
    }
    *(undefined *)(psVar3 + 1) = 0;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  else if (0 < *psVar3) {
    *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1a64
 * EN v1.0 Address: 0x801F1A64
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801F26A4
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1a64(int param_1,int param_2)
{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  ((ObjAnimComponent *)param_1)->bankIndex = (s8)uVar1;
  *puVar2 = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(puVar2 + 1) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1ac0
 * EN v1.0 Address: 0x801F1AC0
 * EN v1.0 Size: 636b
 * EN v1.1 Address: 0x801F270C
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1ac0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  FUN_80017a98();
  local_28 = DAT_802c2bfc;
  local_24 = DAT_802c2c00;
  local_20 = DAT_802c2c04;
  if ((*(byte *)(param_9 + 0xaf) & 8) != 0) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) ^ 8;
  }
  uVar1 = FUN_80017690(0x2fb);
  if (uVar1 == 0) {
    if (*(short *)(param_9 + 0xa0) != 7) {
      ObjAnim_SetCurrentMove((int)param_9,7,lbl_803E6A30,0);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    ObjAnim_AdvanceCurrentMove((double)lbl_803E6A34,
                               (f64)(f32)(s32)uStack_14,param_9,(ObjAnimEventList *)0x0);
  }
  else {
    if (*(short *)(param_9 + 0xa0) != 2) {
      ObjAnim_SetCurrentMove((int)param_9,2,lbl_803E6A30,0);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    ObjAnim_AdvanceCurrentMove((double)lbl_803E6A34,
                               (f64)(f32)(s32)uStack_14,param_9,(ObjAnimEventList *)0x0);
  }
  if (((*(byte *)(param_9 + 0xaf) & 1) == 0) || (uVar1 = FUN_80017690(0x2fb), uVar1 != 0)) {
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
       (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_28,3), -1 < iVar2)) {
      FUN_80017698(0x310,1);
      *(char *)(iVar3 + 0x27) = *(char *)(iVar3 + 0x27) + '\x01';
      FUN_80006ba8(0,0x100);
    }
  }
  else {
    FUN_80017698(0x2fb,1);
    *(undefined *)(iVar3 + 0x27) = 0;
    FUN_80006ba8(0,0x100);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1d3c
 * EN v1.0 Address: 0x801F1D3C
 * EN v1.0 Size: 1668b
 * EN v1.1 Address: 0x801F28C8
 * EN v1.1 Size: 1364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1d3c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined8 local_50;
  
  pfVar5 = *(float **)(param_9 + 0x5c);
  FUN_80017a98();
  local_78 = DAT_802c2bf0;
  local_74 = DAT_802c2bf4;
  local_70 = DAT_802c2bf8;
  *(float *)(param_9 + 8) = pfVar5[1];
  uVar3 = FUN_80017690(0x1fc);
  if (uVar3 == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    if (*(short *)(pfVar5 + 8) < 1) {
      uVar3 = randomGetRange(1,4);
      if (uVar3 == 3) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 3;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 3) {
        if (uVar3 == 1) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 1;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
        else if (0 < (int)uVar3) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 2;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
      }
      else if (uVar3 == 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 5;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 4;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
    }
    else {
      uVar3 = (uint)*(byte *)((int)pfVar5 + 0x22);
      if (uVar3 == 0xc) {
        dVar7 = (double)*(float *)(&DAT_803295b8 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
        iVar4 = FUN_80017730();
        sVar2 = (short)iVar4 - *param_9;
        FUN_80135814();
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -100;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 100;
          }
        }
        else {
          local_50 = (double)(longlong)
                             (int)*(float *)(&DAT_803295bc +
                                            (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          ObjAnim_SetCurrentMove((int)param_9,
                                 (int)*(float *)(&DAT_803295bc +
                                                 (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14),
                                 lbl_803E6A30,0);
          pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          *(undefined *)((int)pfVar5 + 0x22) = 0xd;
        }
      }
      else if (uVar3 == 0xd) {
        dVar7 = (double)lbl_803DC074;
        iVar4 = ObjAnim_AdvanceCurrentMove((double)pfVar5[3],dVar7,(int)param_9,
                                           (ObjAnimEventList *)0x0);
        if (iVar4 != 0) {
          local_50 = (double)CONCAT44(0x43300000,(int)param_9[0x50] ^ 0x80000000);
          iVar4 = (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14;
          if ((float)(local_50 - DOUBLE_803e6a50) == *(float *)(&DAT_803295bc + iVar4)) {
            local_50 = (double)(longlong)(int)*(float *)(&DAT_803295c0 + iVar4);
            ObjAnim_SetCurrentMove((int)param_9,(int)*(float *)(&DAT_803295c0 + iVar4),
                                   lbl_803E6A30,0);
            pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          }
        }
        *(ushort *)(pfVar5 + 8) = *(short *)(pfVar5 + 8) - (ushort)DAT_803dc070;
        if (*(short *)(pfVar5 + 8) < 1) {
          *(undefined2 *)(pfVar5 + 8) = 0;
        }
      }
      else {
        dVar9 = (double)(*(float *)(&DAT_803295b4 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 6) - *pfVar5));
        dVar8 = (double)(*(float *)(&DAT_803295b8 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 10) - pfVar5[2]));
        dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
        dVar7 = dVar8;
        iVar4 = FUN_80017730();
        sVar2 = (short)iVar4 - *param_9;
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (param_9[0x50] != 0xc) {
            ObjAnim_SetCurrentMove((int)param_9,0xc,lbl_803E6A30,0);
            pfVar5[3] = lbl_803E6A48;
          }
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -300;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 300;
          }
        }
        else {
          if (param_9[0x50] != 0x3b) {
            ObjAnim_SetCurrentMove((int)param_9,0x3b,lbl_803E6A30,0);
            pfVar5[3] = lbl_803E6A40;
          }
          dVar8 = (double)lbl_803E6A44;
          *(float *)(param_9 + 0x12) = (float)(dVar8 * (double)(float)(dVar9 / dVar6));
          *(float *)(param_9 + 0x16) = (float)(dVar8 * (double)(float)(dVar7 / dVar6));
          ObjAnim_SampleRootCurvePhase((float)dVar8,(ObjAnimComponent *)param_9,pfVar5 + 3);
        }
        if (dVar6 < (double)lbl_803E6A4C) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 0xc;
          fVar1 = lbl_803E6A30;
          *(float *)(param_9 + 0x12) = lbl_803E6A30;
          *(float *)(param_9 + 0x16) = fVar1;
        }
        *(float *)(param_9 + 6) =
             *(float *)(param_9 + 0x12) * lbl_803DC074 + *(float *)(param_9 + 6);
        *(float *)(param_9 + 10) =
             *(float *)(param_9 + 0x16) * lbl_803DC074 + *(float *)(param_9 + 10);
        ObjAnim_AdvanceCurrentMove((double)pfVar5[3],(double)lbl_803DC074,(int)param_9,
                                   (ObjAnimEventList *)0x0);
      }
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    if (((*(byte *)((int)param_9 + 0xaf) & 1) != 0) &&
       (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_78,3), -1 < iVar4)) {
      FUN_80017698(0x4d1,1);
      *(char *)((int)pfVar5 + 0x27) = *(char *)((int)pfVar5 + 0x27) + '\x01';
      FUN_80017698(0x310,1);
      FUN_80006ba8(0,0x100);
    }
  }
  return;
}

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801F20D4(int obj)
{
  extern void *Obj_GetPlayerObject(void);
  extern int *gGameUIInterface;
  extern int lbl_802C247C[];
  extern void buttonDisable(int a, int b);
  extern u8 framesThisStep;
  extern f32 lbl_803E5D98;
  extern f32 lbl_803E5D9C;
  extern f32 lbl_803E5DA0;
  extern void GameBit_Set(int slot, int val);
  extern uint GameBit_Get(int id);
  int sub;
  int stk[3];

  sub = *(int *)&((GameObject *)obj)->extra;
  Obj_GetPlayerObject();
  stk[0] = lbl_802C247C[0];
  stk[1] = lbl_802C247C[1];
  stk[2] = lbl_802C247C[2];
  if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x8) != 0) {
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode ^= 0x8;
  }
  if (GameBit_Get(763) == 0) {
    if (((GameObject *)obj)->anim.currentMove != 7) {
      ObjAnim_SetCurrentMove(obj, 7, lbl_803E5D98, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
  } else {
    if (((GameObject *)obj)->anim.currentMove != 2) {
      ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
  }
  if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x1) != 0 && GameBit_Get(763) == 0) {
    GameBit_Set(763, 1);
    *(u8 *)(sub + 0x27) = 0;
    buttonDisable(0, 256);
  } else if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x1) != 0) {
    if ((**(int (**)(int *, int))(*gGameUIInterface + 0x24))(stk, 3) > -1) {
      GameBit_Set(784, 1);
      *(u8 *)(sub + 0x27) = *(u8 *)(sub + 0x27) + 1;
      buttonDisable(0, 256);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_801f23c0
 * EN v1.0 Address: 0x801F23C0
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x801F2E1C
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f23c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(short *)(param_9 + 0xa0) != 2) {
    ObjAnim_SetCurrentMove((int)param_9,2,lbl_803E6A30,0);
  }
  ObjAnim_AdvanceCurrentMove((double)lbl_803E6A34,
                             (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) -
                                             DOUBLE_803e6a38),param_9,(ObjAnimEventList *)0x0);
  *(undefined *)(iVar3 + 0x24) = 1;
  if (*(char *)(iVar3 + 0x24) == '\0') {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_80017698(0xd0,1);
      *(undefined *)(iVar3 + 0x24) = 1;
      FUN_80006ba8(0,0x100);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      iVar1 = FUN_80017a98();
      iVar1 = FUN_80294d38(iVar1);
      if (iVar1 < 1) {
        uVar2 = FUN_80017690(0xb1);
        if (((uVar2 == 0) || (uVar2 = FUN_80017690(0xb2), uVar2 == 0)) ||
           (uVar2 = FUN_80017690(0xb3), uVar2 == 0)) {
          *(undefined *)(iVar3 + 0x25) = 1;
          (*gObjectTriggerInterface)->runSequence(1, (void *)param_9, -1);
          FUN_80006ba8(0,0x100);
        }
      }
      else {
        *(undefined *)(iVar3 + 0x25) = 2;
        (*gObjectTriggerInterface)->runSequence(2, (void *)param_9, -1);
        FUN_80006ba8(0,0x100);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f25b4
 * EN v1.0 Address: 0x801F25B4
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801F2FAC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801f25b4(int param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = FUN_80017a98();
  iVar4 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(iVar4 + 0x25);
    if (cVar1 == '\x01') {
      if (*(char *)(param_3 + iVar3 + 0x81) == '\x04') {
        FUN_80294d40(iVar2,5);
      }
    }
    else if (cVar1 != '\x02') {
      cVar1 = *(char *)(param_3 + iVar3 + 0x81);
      if (cVar1 == '\x01') {
        FUN_80017698(0xd0,1);
        *(undefined *)(iVar4 + 0x24) = 1;
      }
      else if (cVar1 == '\x02') {
        FUN_80294cc0(iVar2,0,1);
        FUN_80294d40(iVar2,5);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f26a8
 * EN v1.0 Address: 0x801F26A8
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801F30A8
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801f26a8(int param_1,undefined4 param_2,int param_3)
{
  undefined uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = (*DAT_803dd72c)->getMode((int)*(char *)(param_1 + 0xac));
  switch(uVar1) {
  case 1:
    FUN_801f25b4(param_1,param_2,param_3);
    break;
  case 4:
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    break;
  case 6:
    iVar2 = *(int *)(param_1 + 0xb8);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      if ((*(char *)(param_3 + iVar3 + 0x81) == '\x01') && (1 < *(byte *)(iVar2 + 0x27))) {
        FUN_80017698(0x314,1);
      }
    }
  }
  return 0;
}

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801F27E4(int obj)
{
  extern void *Obj_GetPlayerObject(void);
  extern int fn_80296A14(void);
  extern ObjectTriggerInterface **gObjectTriggerInterface;
  extern void buttonDisable(int a, int b);
  extern u8 framesThisStep;
  extern f32 lbl_803E5D98;
  extern f32 lbl_803E5D9C;
  extern f32 lbl_803E5DA0;
  extern void GameBit_Set(int slot, int val);
  extern uint GameBit_Get(int id);
  int sub;

  sub = *(int *)&((GameObject *)obj)->extra;
  if (((GameObject *)obj)->anim.currentMove != 2) {
    ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
  }
  ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
      (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
  *(u8 *)(sub + 0x24) = 1;
  if (*(u8 *)(sub + 0x24) == 0) {
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x1) != 0) {
      GameBit_Set(208, 1);
      *(u8 *)(sub + 0x24) = 1;
      buttonDisable(0, 256);
    }
  } else {
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x1) != 0) {
      Obj_GetPlayerObject();
      if (fn_80296A14() > 0) {
        *(u8 *)(sub + 0x25) = 2;
        (*gObjectTriggerInterface)->runSequence(2, (void *)obj, -1);
        buttonDisable(0, 256);
      } else {
        if (GameBit_Get(177) == 0 || GameBit_Get(178) == 0 || GameBit_Get(179) == 0) {
          *(u8 *)(sub + 0x25) = 1;
          (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
          buttonDisable(0, 256);
        }
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_801f284c
 * EN v1.0 Address: 0x801F284C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801F31D8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f284c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  char cVar3;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  if (visible != 0) {
    cVar3 = (*DAT_803dd72c)->getMode((int)*(char *)(iVar1 + 0xac));
    if (cVar3 == '\x04') {
      uVar2 = FUN_80017690(0x2bd);
      if (uVar2 != 0) {
        FUN_8003b818(iVar1);
      }
    }
    else {
      FUN_8003b818(iVar1);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f28d4
 * EN v1.0 Address: 0x801F28D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F329C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f28d8
 * EN v1.0 Address: 0x801F28D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F33F4
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28d8(undefined2 *param_1,undefined2 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f28dc
 * EN v1.0 Address: 0x801F28DC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F34E4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28dc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2904
 * EN v1.0 Address: 0x801F2904
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801F3518
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2904(uint param_1)
{
  float fVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_1 + 0x4c);
  psVar7 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar7 + 1) = *(char *)(psVar7 + 1) + -1;
  if (*(char *)(psVar7 + 1) < '\0') {
    *(undefined *)(psVar7 + 1) = 0;
  }
  fVar1 = lbl_803E6A64;
  if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
    iVar5 = 0;
    for (iVar6 = 0; iVar6 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar6 = iVar6 + 1) {
      if (fVar1 < *(float *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x10) -
                  *(float *)(param_1 + 0x10)) {
        *(undefined *)(psVar7 + 1) = 0x3c;
      }
      iVar5 = iVar5 + 4;
    }
  }
  bVar3 = false;
  if ((((int)*psVar7 == 0xffffffff) || (uVar4 = FUN_80017690((int)*psVar7), uVar4 != 0)) &&
     (*(char *)(psVar7 + 1) != '\0')) {
    fVar2 = lbl_803E6A68 + lbl_803E6A6C + *(float *)(iVar8 + 0xc);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= fVar2) {
      *(float *)(param_1 + 0x10) = lbl_803E6A74 * lbl_803DC074 + fVar1;
      if (*(float *)(param_1 + 0x10) <= fVar2) {
        bVar3 = true;
      }
      else {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
    else {
      *(float *)(param_1 + 0x10) = -(lbl_803E6A70 * lbl_803DC074 - fVar1);
      if (fVar2 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = -(lbl_803E6A78 * lbl_803DC074 - *(float *)(param_1 + 0x10));
    fVar1 = *(float *)(iVar8 + 0xc);
    if (fVar1 <= *(float *)(param_1 + 0x10)) {
      bVar3 = true;
    }
    else {
      *(float *)(param_1 + 0x10) = fVar1;
    }
  }
  if (bVar3) {
    FUN_80006824(param_1,SFXmn_crusty9c);
  }
  else {
    FUN_8000680c(param_1,8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2ac8
 * EN v1.0 Address: 0x801F2AC8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801F3724
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2ac8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  if ((param_10 == 0) && (**(int **)(param_9 + 0xb8) != 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 **(int **)(param_9 + 0xb8));
  }
  (**(code **)(*DAT_803dd6fc + 0x18))(param_9);
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2b94
 * EN v1.0 Address: 0x801F2B94
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801F37A8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2b94(short *param_1)
{
  int iVar1;
  double dVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0xc) == '\x02') {
    *param_1 = *param_1 + 0x32;
  }
  iVar1 = FUN_80017a98();
  dVar2 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_1 + 0xc));
  if ((double)lbl_803E6A80 <= dVar2) {
    FUN_8000680c((int)param_1,0x40);
  }
  else {
    FUN_80006824((uint)param_1,SFXmn_eggylaugh216);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void pressureswitch_free(void) {}
void pressureswitch_hitDetect(void) {}
void pressureswitch_release(void) {}
void pressureswitch_initialise(void) {}

extern f32 lbl_803E5D78;

typedef struct PressureSwitchFlags {
    u8 unusedHighBit : 1;
    u8 mapBitLatched : 1;
    u8 otherFlags : 6;
} PressureSwitchFlags;

#pragma scheduling off
#pragma peephole off
void pressureswitch_init(int *obj, u8 *init) {
    extern uint GameBit_Get(int id);
    PressureSwitchState *sub;
    uint mapId;

    sub = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)PressureSwitch_SeqFn;
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    sub->retriggerTimer = (s16)(*(s16*)(init + 0x1e) * 0x3c);
    sub->chimeLatch = 0;
    mapId = *(int*)(*(int *)&((GameObject *)obj)->anim.placementData + 0x14);
    if (mapId == 0x1f1a) {
        sub->mapGameBit = 0xf45;
    } else if (mapId == 0x47293) {
        sub->mapGameBit = 0xf46;
    } else {
        sub->mapGameBit = -1;
    }
    if (sub->mapGameBit != -1) {
        if (GameBit_Get(sub->mapGameBit) != 0) {
            ((PressureSwitchFlags *)&sub->flags)->mapBitLatched = 1;
        }
    }
    if (GameBit_Get(*(s16*)(init + 0x1c)) != 0) {
        ((GameObject *)obj)->anim.localPosY = *(f32*)(init + 0xc) - lbl_803E5D78;
        sub->holdTimer = 0x1e;
    }
}
#pragma peephole reset
#pragma scheduling reset
void dll_1FF_free_nop(void) {}
void dll_1FF_hitDetect_nop(void) {}
void dll_1FF_release_nop(void) {}
void dll_1FF_initialise_nop(void) {}
void wmlasertarget_free(void) {}
void wmlasertarget_hitDetect(void) {}
void wmlasertarget_release(void) {}
void wmlasertarget_initialise(void) {}

extern void Obj_SetActiveModelIndex(int *obj, int idx);

#pragma scheduling off
#pragma peephole off
void wmlasertarget_update(int *obj) {
    extern u8 framesThisStep;
    extern void GameBit_Set(int slot, int val);
    extern u32 GameBit_Get(int slot);
    u8 *def;
    WmLaserTargetState *sub;

    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    sub = ((GameObject *)obj)->extra;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
        sub->toggleQueued = 1;
        sub->cooldown = *(s16*)(def + 0x1a);
    }
    if (sub->cooldown <= 0 && sub->toggleQueued != 0) {
        if (GameBit_Get(*(s16*)(def + 0x1e)) != 0) {
            Obj_SetActiveModelIndex(obj, 0);
            GameBit_Set(*(s16*)(def + 0x1e), 0);
            GameBit_Set(*(s16*)(def + 0x20), 0);
        } else {
            Obj_SetActiveModelIndex(obj, 1);
            GameBit_Set(*(s16*)(def + 0x1e), 1);
            GameBit_Set(*(s16*)(def + 0x20), 1);
        }
        sub->toggleQueued = 0;
        sub->cooldown = *(s16*)(def + 0x1a);
    } else if (sub->cooldown > 0) {
        u8 fs = framesThisStep;
        sub->cooldown -= fs;
    }
}
#pragma peephole reset
#pragma scheduling reset
void dll_200_free_nop(void) {}
void dll_200_hitDetect_nop(void) {}
void dll_200_release_nop(void) {}
void dll_200_initialise_nop(void) {}
void WM_colrise_free(void) {}
void WM_colrise_hitDetect(void) {}
void WM_colrise_release(void) {}
void WM_colrise_initialise(void) {}

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 timeDelta;
extern f32 lbl_803E5DCC;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;
extern f32 lbl_803E5DE0;

#pragma scheduling off
#pragma peephole off
void WM_colrise_update(int *obj) {
    u8 *def;
    WMColriseState *sub;
    s32 reached;
    f32 detectDistance;
    f32 target;
    int i;

    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    sub = ((GameObject *)obj)->extra;
    sub->raiseTimer -= 1;
    if ((s8)sub->raiseTimer < 0) sub->raiseTimer = 0;
    if ((s8)*(s8*)((char*)*(int**)((char*)obj + 0x58) + 0x10f) > 0) {
        detectDistance = lbl_803E5DCC;
        for (i = 0; i < (s8)*(s8*)((char*)*(int**)((char*)obj + 0x58) + 0x10f); i++) {
            int *p = *(int**)((char*)*(int**)((char*)obj + 0x58) + 0x100 + i * 4);
            if (*(f32*)((char*)p + 0x10) - ((GameObject *)obj)->anim.localPosY > detectDistance) {
                sub->raiseTimer = 0x3c;
            }
        }
    }
    reached = 0;
    if ((sub->gameBit == -1 || (u32)GameBit_Get(sub->gameBit) != 0) && (s8)sub->raiseTimer != 0) {
        target = lbl_803E5DD0 + (lbl_803E5DD4 + *(f32*)(def + 0xc));
        if (((GameObject *)obj)->anim.localPosY > target) {
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E5DD8 * timeDelta;
            if (((GameObject *)obj)->anim.localPosY > target) {
                ((GameObject *)obj)->anim.localPosY = target;
            }
        } else {
            ((GameObject *)obj)->anim.localPosY = lbl_803E5DDC * timeDelta + ((GameObject *)obj)->anim.localPosY;
            if (((GameObject *)obj)->anim.localPosY > target) {
                ((GameObject *)obj)->anim.localPosY = target;
            } else {
                reached = 1;
            }
        }
    } else {
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E5DE0 * timeDelta;
        if (((GameObject *)obj)->anim.localPosY < *(f32*)(def + 0xc)) {
            ((GameObject *)obj)->anim.localPosY = *(f32*)(def + 0xc);
        } else {
            reached = 1;
        }
    }
    if ((s8)reached != 0) {
        Sfx_PlayFromObject((int)obj, SFXmn_crusty9c);
    } else {
        Sfx_StopObjectChannel((int)obj, 8);
    }
}
#pragma peephole reset
#pragma scheduling reset
void wmtorch_hitDetect(void) {}
void wmtorch_release(void) {}
void wmtorch_initialise(void) {}

extern f32 lbl_803E5DEC;
extern f32 lbl_803E5DF0;
extern f32 lbl_803E5DF4;
extern f32 lbl_803E5DF8;
#pragma peephole off
#pragma scheduling off
void wmtorch_init(u8* obj, u8* params) {
    WmTorchState* sub;
    void *res;
    f32 v[5];

    sub = ((GameObject *)obj)->extra;
    if (*(s16*)(params + 0x1a) != 0) {
        sub->unk04 = (f32)(s32)*(s16*)(params + 0x1a);
    } else {
        sub->unk04 = lbl_803E5DEC;
    }
    if (*(s16*)(params + 0x1c) != 0) {
        sub->unk0A = *(s16*)(params + 0x1c);
    } else {
        sub->unk0A = 0x8c;
    }
    sub->torchType = params[0x19];
    v[4] = lbl_803E5DF0;
    if (sub->torchType == 0) {
        res = Resource_Acquire(0x69, 1);
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((void(*)(u8*, int, f32*, int, int, int))((void**)*(int*)res)[1])(obj, 1, v, 0x10004, -1, 0);
    } else if (sub->torchType == 0x7f) {
        res = Resource_Acquire(0x69, 1);
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((void(*)(u8*, int, f32*, int, int, int))((void**)*(int*)res)[1])(obj, 2, v, 0x10004, -1, 0);
    } else {
        res = Resource_Acquire(0x63, 1);
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((void(*)(u8*, int, f32*, int, int, int))((void**)*(int*)res)[1])(obj, 2, v, 0x10004, -1, 0);
    }
    ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * lbl_803E5DF8;
    Resource_Release(res);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
}
#pragma scheduling reset
#pragma peephole reset
#pragma peephole off
void wmtorch_render(int *obj, int p1, int p2, int p3, int p4, s8 visible) {
    if (visible == 0) return;
}
#pragma peephole reset

extern void *lbl_803DDC80;
#pragma scheduling off
#pragma peephole off
void LaserBeam_initialise(void) {
    lbl_803DDC80 = Resource_Acquire(0x81, 1);
}
#pragma peephole reset
#pragma scheduling reset
void lightsource_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int pressureswitch_getExtraSize(void) { return 0x8; }
int pressureswitch_getObjectTypeId(void) { return 0x0; }
int dll_1FF_getExtraSize_ret_8(void) { return 0x8; }
int wmlasertarget_getExtraSize(void) { return 0x4; }
int wmlasertarget_getObjectTypeId(void) { return 0x0; }
int dll_200_getExtraSize_ret_40(void) { return 0x28; }
int dll_200_getObjectTypeId(void) { return 0x1; }
int WM_colrise_getExtraSize(void) { return 0x4; }
int WM_colrise_getObjectTypeId(void) { return 0x0; }
int wmtorch_getExtraSize(void) { return 0x10; }
int wmtorch_getObjectTypeId(void) { return 0x1; }
int lightsource_getExtraSize(void) { return 0x1c; }
int lightsource_getObjectTypeId(void) { return 0x1; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5D58;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5D90;
extern f32 lbl_803E5DC8;
extern f32 lbl_803E5E08;
extern void queueGlowRender(void *light);
#pragma peephole off
void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5D58); }
void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5D90); }
void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5DC8); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void lightsource_render(void *obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void *obj, int p1, int p2, int p3, int p4, f32 alpha);
    void *light = (*(LightSourceState **)&((GameObject *)obj)->extra)->light;
    if (light != NULL && *(u8 *)((char *)light + 0x2f8) != 0 && *(u8 *)((char *)light + 0x4c) != 0) {
        queueGlowRender(light);
    }
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5E08);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma scheduling off
#pragma peephole off
int dll_1FF_getObjectTypeId(int *obj) { if (((GameObject *)obj)->anim.seqId == 0x146) return 0x2; return 0x0; }
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

/* init pattern: short=-1; byte=0; return 0; */
#pragma scheduling off
#pragma peephole off
int PressureSwitch_SeqFn(int p1, int p2, void* p3) { *(s16*)((char*)p3 + 0x6e) = -1; *(u8*)((char*)p3 + 0x56) = 0; return 0; }
int WM_colrise_SeqFn(int p1, int p2, void* p3) { *(s16*)((char*)p3 + 0x6e) = -1; *(u8*)((char*)p3 + 0x56) = 0; return 0; }
#pragma peephole reset
#pragma scheduling reset

/* fn_X(lbl); lbl = 0; */
#pragma scheduling off
#pragma peephole off
void LaserBeam_release(void) { Resource_Release(lbl_803DDC80); lbl_803DDC80 = NULL; }
#pragma peephole reset
#pragma scheduling reset

/* dll_1FF_init: stash (s8 b[0x18] << 8) into a[0] and -0x8000 into a[1]. */
#pragma scheduling off
#pragma peephole off
void dll_1FF_init(s16* a, s8* b)
{
    a[0] = (s16)((s32)b[0x18] << 8);
    a[1] = -0x8000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void WM_colrise_init(s16 *a, s8 *b) {
    WMColriseState *inner = ((GameObject *)a)->extra;
    ((GameObject *)a)->animEventCallback = (void *)WM_colrise_SeqFn;
    a[0] = (s16)((s32)b[0x18] << 8);
    inner->gameBit = *(s16 *)(b + 0x1e);
}
#pragma peephole reset
#pragma scheduling reset

extern int GameBit_Get(int id);
#pragma scheduling off
#pragma peephole off
void wmlasertarget_init(char *obj, s8 *p) {
    WmLaserTargetState *inner = ((GameObject *)obj)->extra;
    ((ObjAnimComponent *)obj)->bankIndex = (s8)GameBit_Get(*(s16 *)(p + 0x1e));
    inner->cooldown = *(s16 *)(p + 0x1a);
    inner->toggleQueued = 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 *a, f32 *b);
extern f32 lbl_803E5DE8;
#pragma scheduling off
#pragma peephole off
void wmtorch_update(int obj) {
    int state = *(int *)&((GameObject *)obj)->extra;
    if (((WmTorchState *)state)->torchType == 2) {
        *(s16 *)obj += 0x32;
    }
    if (Vec_distance((f32 *)(Obj_GetPlayerObject() + 0x18), (f32 *)(obj + 0x18)) < lbl_803E5DE8) {
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    } else {
        Sfx_StopObjectChannel(obj, 0x40);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int *gModgfxInterface;
extern ExpgfxInterface **gExpgfxInterface;
extern void Obj_FreeObject(void *o);
#pragma scheduling off
#pragma peephole off
void wmtorch_free(int obj, int mode) {
    int state = *(int *)&((GameObject *)obj)->extra;
    if (mode == 0 && ((WmTorchState *)state)->linkedObj != 0) {
        Obj_FreeObject(((WmTorchState *)state)->linkedObj);
    }
    ((ModgfxInterface *)*gModgfxInterface)->detachSource((void *)obj);
    (*gExpgfxInterface)->freeSource(obj);
}
#pragma peephole reset
#pragma scheduling reset

extern void ModelLightStruct_free(void *light);
#pragma scheduling off
#pragma peephole off
void lightsource_free(int obj) {
    int state = *(int *)&((GameObject *)obj)->extra;
    ((EffectInterface *)*gExpgfxInterface)->freeObject((void *)obj);
    if (((LightSourceState *)state)->light != 0) {
        ModelLightStruct_free(((LightSourceState *)state)->light);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */
extern f32 lbl_803E5D80;
#pragma scheduling off
#pragma peephole off
void dll_1FF_render(int *obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    s32 v;
    if (((GameObject *)obj)->unkF8 != 0) {
        v = visible;
        if (v != -1) return;
    } else {
        v = visible;
        if (v == 0) return;
    }
    if (((ObjAnimComponent *)obj)->modelInstance->shadowType == 2) {
        if (((GameObject *)obj)->unkB4 == -1) {
            ((GameObject *)obj)->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        } else {
            ((GameObject *)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5D80);
}
#pragma peephole reset
#pragma scheduling reset

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */
extern MapEventInterface **gMapEventInterface;
extern f32 lbl_803E5DC0;
#pragma scheduling off
#pragma peephole off
void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    s32 v = visible;
    int areaId;
    if (v == 0) return;
    areaId = (*gMapEventInterface)->getMode((int)*(char *)((char*)obj + 0xac));
    if ((u8)areaId == 4) {
        if ((u32)GameBit_Get(0x2bd) == 0u) return;
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5DC0);
        return;
    }
    objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5DC0);
}
#pragma peephole reset
#pragma scheduling reset

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */
extern f32 lbl_803E5D98;
#pragma scheduling off
#pragma peephole off
void dll_200_init(int* obj, int* arg)
{
    Dll200State* b;
    ((GameObject *)obj)->unkF4 = 0;
    *(s16*)obj = (s16)((s32)*(s8*)((char*)arg + 0x18) << 8);
    ((GameObject *)obj)->animEventCallback = (void *)dll_200_SeqFn;
    b = ((GameObject *)obj)->extra;
    b->defNoLow = (u8)*(s16*)arg;
    b->unk1C = 0;
    b->unk18 = 0;
    b->homeX = *(f32*)((char*)arg + 0x8);
    b->homeY = *(f32*)((char*)arg + 0xc);
    b->homeZ = *(f32*)((char*)arg + 0x10);
    b->latch24 = (u8)GameBit_Get(0xd0);
    b->counter27 = 0;
    b->mode = 1;
    b->prevMode = 0xc;
    b->modeTimer = 0x12c;
    b->animSpeed = lbl_803E5D98;
    b->unk14 = lbl_803E5DC0;
}
#pragma peephole reset
#pragma scheduling reset

extern void playerAddRemoveMagic(int player, int amount);
extern void fn_80296474(int player, int a, int b);
extern void GameBit_Set(int slot, int val);

int fn_801F2974(int* arg0, int arg1, int* arg2, int arg3);

#pragma scheduling off
#pragma peephole off
#pragma opt_strength_reduction off
int dll_200_SeqFn(int p1, int p2, int p3, int p4)
{
    u8 ev;
    int i;
    int state;

    ev = (*gMapEventInterface)->getMode((int)*(s8 *)((char *)p1 + 0xac));
    switch (ev) {
    case 1:
        fn_801F2974((int *)p1, p2, (int *)p3, p4);
        break;
    case 4:
        *(u8 *)((char *)p1 + 0xaf) = (u8)(*(u8 *)((char *)p1 + 0xaf) | 8);
        break;
    case 6:
        state = *(int *)((char *)p1 + 0xb8);
        *(u8 *)((char *)p1 + 0xaf) = (u8)(*(u8 *)((char *)p1 + 0xaf) | 8);
        for (i = 0; i < (int)*(u8 *)((char *)p3 + 0x8b); i++) {
            switch (*((u8 *)p3 + (i + 0x81))) {
            case 0:
                break;
            case 1:
                if (*(u8 *)&((Dll200State *)state)->counter27 >= 2) {
                    GameBit_Set(0x314, 1);
                }
                break;
            }
        }
        break;
    case 0:
        return 0;
    case 2:
        return 0;
    case 3:
        return 0;
    case 5:
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_strength_reduction off
int fn_801F2974(int* arg0, int arg1, int* arg2, int arg3)
{
    int state;
    int player;
    int i;

    player = Obj_GetPlayerObject();
    state = *(int*)((char*)arg0 + 0xb8);
    *(u8*)((char*)arg0 + 0xaf) = (u8)(*(u8*)((char*)arg0 + 0xaf) | 8);

    for (i = 0; i < (int)*(u8*)((char*)arg2 + 0x8b); i++) {
        u8 mode = ((Dll200State *)state)->mode25;
        if (mode == 1) {
            if (*((u8*)arg2 + (i + 0x81)) == 4) {
                playerAddRemoveMagic(player, 5);
            }
        } else if (mode != 2) {
            u8 v = *((u8*)arg2 + (i + 0x81));
            if (v == 1) {
                GameBit_Set(208, 1);
                ((Dll200State *)state)->latch24 = 1;
            } else if (v == 2) {
                fn_80296474(player, 0, 1);
                playerAddRemoveMagic(player, 5);
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int textureLoadAsset(int id);
extern f32 lbl_803E5D10;

#pragma scheduling off
#pragma peephole off
void LaserBeam_free(s16 *obj, char *arg)
{
    LaserBeamState *b;

    b = ((GameObject *)obj)->extra;
    ObjMsg_AllocQueue(obj, 2);
    *obj = (s16)((s32)*(s8 *)(arg + 0x18) << 8);
    if (*(s16 *)(arg + 0x1c) == 0) {
        b->firePeriod = (s16)(randomGetRange(-80, 80) + 400);
    } else {
        b->firePeriod = *(s16 *)(arg + 0x1c);
    }
    b->fireTimer = b->firePeriod;
    b->active = 0;
    b->sweepPhase = lbl_803E5D10;
    b->beamKind = *(u8 *)(arg + 0x19);
    b->unk2E = 0x118;
    b->emitterSlot = -1;
    if (b->beamKind == 30) {
        if (*(void **)&b->texture == NULL) {
            b->texture = textureLoadAsset(0x3e9);
        }
    } else if (b->beamKind == 1) {
        if (*(void **)&b->texture == NULL) {
            b->texture = textureLoadAsset(0x23d);
        }
    } else if (*(void **)&b->texture == NULL) {
        b->texture = textureLoadAsset(0xd9);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern ObjHitReactEntry lbl_80328898[];
void fn_801F2290(int obj);

#pragma scheduling off
#pragma peephole off
#pragma opt_strength_reduction off
void dll_200_update(int obj)
{
    extern u8 framesThisStep;
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    u8 ev;
    u8 ret;
    Dll200State *b;

    b = ((GameObject *)obj)->extra;
    ret = ObjHitReact_Update(obj, lbl_80328898, 11,
                             (u8)((b->mode & 0x80) ? 1 : 0),
                             &b->hitReactVec);
    if (ret != 0) {
        b->mode = (u8)(b->mode | 0x80);
    } else {
        b->mode = (u8)(b->mode & ~0x80);
        ev = (*gMapEventInterface)->getMode((int)*(s8 *)(obj + 0xac));
        switch (ev) {
        case 1:
            fn_801F27E4(obj);
            break;
        case 2:
            fn_801F2290(obj);
            break;
        case 4:
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
            if (((GameObject *)obj)->anim.currentMove != 2) {
                ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
            }
            ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
            break;
        case 6:
            fn_801F20D4(obj);
            break;
        case 0:
            return;
        case 3:
            return;
        case 5:
            return;
        }
    }
}
#pragma opt_strength_reduction reset
#pragma peephole reset
#pragma scheduling reset

typedef struct LightSourceFlagByte {
    u8 looped : 1;
} LightSourceFlagByte;

#pragma scheduling off
#pragma peephole off
#pragma opt_strength_reduction off
void lightsource_update(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern int ObjHits_GetPriorityHit(int obj, int a, int b, int c);
    extern uint GameBit_Get(int id);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_AddLoopedObjectSound(int obj, int sfx);
    extern void Sfx_RemoveLoopedObjectSound(int obj, int sfx);
    extern void fn_80098B18(int obj, f32 scale, u8 a, u8 b, int c, f32 *vec);
    extern ExpgfxInterface **gExpgfxInterface;
    extern EffectInterface **gPartfxInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E5E08;
    extern f32 lbl_803E5E0C;
    extern f32 lbl_803E5E10;
    extern f32 lbl_803E5E14;
    extern f32 lbl_803E5E18;
    extern f32 lbl_803E5E1C;
    LightSourceState *b;
    char *t;
    s16 sum;
    u8 sfxFlag;
    f32 vec[3];
    struct {
        u8 pad[8];
        f32 scale;
        u8 pad2[0xc];
    } fx;

    b = ((GameObject *)obj)->extra;
    switch (b->mode) {
    case 0:
        break;
    case 1:
        b->litPrev = b->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            b->lit = (u8)(1 - b->lit);
        }
        if (b->lit != b->litPrev) {
            if (b->lit != 0) {
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) == 0) {
                    GameBit_Set(b->gameBit, 1);
                }
                Sfx_PlayFromObject(obj, 0x80);
            } else {
                (*gExpgfxInterface)->freeSource(obj);
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) != 0) {
                    GameBit_Set(b->gameBit, 0);
                }
            }
        }
        break;
    }
    if (b->lit != 0 && (((GameObject *)obj)->objectFlags & 0x800)) {
        b->fxTimer = b->fxTimer - timeDelta;
        if (b->fxTimer <= lbl_803E5E0C) {
            sfxFlag = b->fxArg;
            b->fxTimer = b->fxTimer + lbl_803E5E10;
        } else {
            sfxFlag = 0;
        }
        if (b->fxType != 0 || b->fxArg != 0) {
            vec[0] = lbl_803E5E0C;
            if (((GameObject *)obj)->anim.seqId == 0x717) {
                vec[1] = vec[0];
            } else {
                vec[1] = lbl_803E5E14;
            }
            vec[2] = lbl_803E5E0C;
            fn_80098B18(obj, lbl_803E5E18 * ((GameObject *)obj)->anim.rootMotionScale, b->fxType, sfxFlag, 0, vec);
        }
        if (b->sparks != 0) {
            b->sparkTimer = b->sparkTimer - timeDelta;
            if (b->sparkTimer <= lbl_803E5E0C) {
                fx.scale = lbl_803E5E08;
                (*gPartfxInterface)->spawnObject((void *)obj, 0x7cb, &fx, 2, -1, NULL);
                b->sparkTimer = b->sparkTimer + lbl_803E5E1C;
            }
        }
    }
    t = (char *)b->light;
    if (t != NULL && *(u8 *)(t + 0x2f8) != 0 && *(u8 *)(t + 0x4c) != 0) {
        sum = (s16)(*(u8 *)(t + 0x2f9) + *(s8 *)(t + 0x2fa));
        if (sum < 0) {
            sum = 0;
            *(u8 *)(t + 0x2fa) = 0;
        } else if (sum > 255) {
            sum = 255;
            *(u8 *)(t + 0x2fa) = 0;
        }
        *(u8 *)((char *)b->light + 0x2f9) = (u8)sum;
    }
    if (((GameObject *)obj)->anim.seqId != 0x705 && ((GameObject *)obj)->anim.seqId != 0x712) {
        if (b->lit != 0) {
            if (!((LightSourceFlagByte *)&b->loopFlags)->looped) {
                Sfx_AddLoopedObjectSound(obj, 0x72);
                ((LightSourceFlagByte *)&b->loopFlags)->looped = 1;
            }
        } else {
            if (((LightSourceFlagByte *)&b->loopFlags)->looped) {
                Sfx_RemoveLoopedObjectSound(obj, 0x72);
                ((LightSourceFlagByte *)&b->loopFlags)->looped = 0;
            }
        }
    }
}
#pragma opt_strength_reduction reset
#pragma peephole reset
#pragma scheduling reset

typedef struct Dll1FFSlot {
    int obj;
} Dll1FFSlot;
typedef struct Dll1FFSlots {
    u8 pad[0x100];
    Dll1FFSlot slots[3];
    u8 pad2[3];
    u8 count;
} Dll1FFSlots;

#pragma scheduling off
#pragma peephole off
void dll_1FF_update(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern void buttonDisable(int a, int b);
    extern uint getButtonsJustPressed(int pad);
    extern void objFn_80035F20(int obj);
    extern void objFn_80035F00(int obj);
    extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int *list, int a, int b);
    extern void objFn_800378C4(void *player, int msg, int obj, int data);
    extern f32 timeDelta;
    extern f32 lbl_803E5D84;
    extern const f32 lbl_803E5D88;
    extern const f32 lbl_803E5D8C;
    void *player;
    Dll1FFState *b;
    int flag;
    int count;
    char *found;
    int i;
    char *t;
    u8 c;
    char *p;
    int stk[2];

    b = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    if (b->grabPhase == 0) {
        flag = 0;
        if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0 && ((GameObject *)obj)->unkF8 == 0) {
            b->msgLo = (s16)flag;
            b->msgHi = 0x28;
            buttonDisable(0, 0x100);
            flag = 1;
        }
        b->grabPhase = (s8)flag;
        if (b->grabPhase != 0) {
            b->sendFlag = 1;
        }
        if (((GameObject *)obj)->unkF8 == 0) {
            ObjHits_EnableObject(obj);
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8);
            ((GameObject *)obj)->anim.velocityY = -(lbl_803E5D84 * timeDelta - ((GameObject *)obj)->anim.velocityY);
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
            count = hitDetectFn_80065e50(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                         ((GameObject *)obj)->anim.localPosZ, stk, 0, 1);
            found = NULL;
            for (i = 0; i < count; i++) {
                p = ((char **)stk[0])[i];
                if (*(s8 *)(p + 0x14) != 14) {
                    if (((GameObject *)obj)->anim.localPosY < *(f32 *)p) {
                        if (((GameObject *)obj)->anim.localPosY > *(f32 *)p - lbl_803E5D88 || i == 0) {
                            found = *(char **)(p + 0x10);
                            ((GameObject *)obj)->anim.localPosY = *(f32 *)p;
                            ((GameObject *)obj)->anim.velocityY = lbl_803E5D8C;
                        }
                    }
                }
            }
            if (found != NULL) {
                Dll1FFSlots *ts = *(Dll1FFSlots **)(found + 0x58);
                c = ts->count;
                ts->count += 1;
                ts->slots[(s8)c].obj = obj;
            }
        }
    } else {
        ObjHits_DisableObject(obj);
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
        if ((getButtonsJustPressed(0) & 0x100) != 0) {
            b->sendFlag = 0;
            buttonDisable(0, 0x100);
        }
        if (((GameObject *)obj)->unkF8 == 1) {
            b->grabPhase = 2;
        }
        if (b->grabPhase == 2 && ((GameObject *)obj)->unkF8 == 0) {
            b->grabPhase = 0;
            b->sendFlag = 0;
        }
        if (*(s8 *)&b->sendFlag != 0) {
            ObjMsg_SendToObject(player, 0x100008, obj,
                                ((int)b->msgHi << 16) | ((int)b->msgLo & 0xffff));
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

typedef struct PswFlags {
    u8 active : 1;
    u8 latched : 1;
} PswFlags;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void pressureswitch_update(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern void *getTrickyObject(void);
    extern f32 Vec_distance(void *a, void *b);
    extern uint GameBit_Get(int id);
    extern void GameBit_Set(int slot, int val);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_StopObjectChannel(int obj, int ch);
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D5C;
    extern f32 lbl_803E5D60;
    extern f32 lbl_803E5D64;
    extern f32 lbl_803E5D68;
    extern f32 lbl_803E5D6C;
    extern f32 lbl_803E5D74;
    extern f32 lbl_803E5D70;
    char *t;
    PressureSwitchState *b;
    s8 far;
    int i;
    void *player;
    void *tricky;
    int ac;
    int v;
    s8 played;
    char *slots;
    f32 cur;
    f32 lim;
    f32 thr;
    f32 f;

    player = Obj_GetPlayerObject();
    t = *(char **)&((GameObject *)obj)->anim.placementData;
    b = ((GameObject *)obj)->extra;
    far = 0;
    if (Vec_distance((char *)obj + 0x18, (char *)player + 0x18) > lbl_803E5D5C) {
        far = 1;
    }
    b->holdTimer -= 1;
    if (b->holdTimer < 0) {
        b->holdTimer = 0;
        b->chimeLatch = 0;
    }
    ((PswFlags *)&b->flags)->active = 0;
    if (*(char **)(obj + 0x58) != NULL && *(s8 *)(*(char **)(obj + 0x58) + 0x10f) > 0) {
        b->retriggerTimer = (s16)(*(s16 *)(t + 0x1e) * 60);
        i = 0;
        thr = lbl_803E5D60;
        for (; i < *(s8 *)((slots = *(char **)(obj + 0x58)) + 0x10f); i++) {
            char *ent = *(char **)(slots + i * 4 + 0x100);
            if (*(s16 *)(ent + 0x46) == 0x6d) {
                ((PswFlags *)&b->flags)->active = 1;
            }
            if (*(f32 *)(ent + 0x10) - ((GameObject *)obj)->anim.localPosY > thr) {
                b->holdTimer = 5;
            }
            if (b->chimeLatch == 0 && ent != NULL && *(s16 *)(ent + 0x46) == 0x146) {
                if (far == 0) {
                    Sfx_PlayFromObject(obj, 0x7e);
                }
                b->chimeLatch = 1;
            }
        }
    } else {
        ac = *(s8 *)(obj + 0xac);
        if (ac == 11 && (*gMapEventInterface)->getMode(ac) == 3 &&
            (tricky = getTrickyObject()) != NULL &&
            Vec_distance((char *)obj + 0x18, (char *)tricky + 0x18) < lbl_803E5D64) {
            b->holdTimer = 5;
        }
    }
    ac = *(s8 *)(obj + 0xac);
    if (ac == 11 && (*gMapEventInterface)->getMode(ac) == 1 && far == 0) {
        if (b->holdTimer != 0) {
            f = *(f32 *)(t + 0xc) - ((GameObject *)obj)->anim.localPosY;
            if (f > lbl_803E5D68 && f < lbl_803E5D6C && GameBit_Get(b->mapGameBit) == 0) {
                GameBit_Set(0x905, 1);
            } else if (GameBit_Get(0x905) != 0) {
                GameBit_Set(0x905, 0);
            }
        } else if (GameBit_Get(0x905) != 0) {
            GameBit_Set(0x905, 0);
        }
    }
    played = 0;
    if (b->holdTimer != 0) {
        lim = *(f32 *)(t + 0xc) - lbl_803E5D6C;
        cur = ((GameObject *)obj)->anim.localPosY;
        if (cur < lim) {
            ((GameObject *)obj)->anim.localPosY = lbl_803E5D70 * timeDelta + cur;
            if (((GameObject *)obj)->anim.localPosY > lim) {
                ((GameObject *)obj)->anim.localPosY = lim;
            }
            GameBit_Set(*(s16 *)(t + 0x1c), 1);
            if (((PswFlags *)&b->flags)->active) {
                GameBit_Set(b->mapGameBit, 1);
            }
        } else {
            ((GameObject *)obj)->anim.localPosY = -(lbl_803E5D74 * timeDelta - cur);
            if (((GameObject *)obj)->anim.localPosY < lim) {
                ((GameObject *)obj)->anim.localPosY = lim;
                GameBit_Set(*(s16 *)(t + 0x1c), 1);
                v = b->mapGameBit;
                if (v != -1) {
                    GameBit_Set(v, 1);
                    if (((PswFlags *)&b->flags)->active) {
                        ((PswFlags *)&b->flags)->latched = 1;
                    }
                }
            } else {
                played = 1;
            }
        }
    } else {
        if (b->retriggerTimer == 0) {
            ((GameObject *)obj)->anim.localPosY = lbl_803E5D74 * timeDelta + ((GameObject *)obj)->anim.localPosY;
            if (((GameObject *)obj)->anim.localPosY > *(f32 *)(t + 0xc)) {
                ((GameObject *)obj)->anim.localPosY = *(f32 *)(t + 0xc);
            } else {
                played = 1;
            }
            GameBit_Set(*(s16 *)(t + 0x1c), 0);
            v = b->mapGameBit;
            if (v != -1) {
                if (!((PswFlags *)&b->flags)->latched) {
                    GameBit_Set(v, 0);
                }
            }
        }
    }
    if (played != 0) {
        Sfx_PlayFromObject(obj, 0x7f);
    } else {
        Sfx_StopObjectChannel(obj, 8);
    }
    if (b->retriggerTimer != 0) {
        b->retriggerTimer -= framesThisStep;
        if (b->retriggerTimer < 0) {
            b->retriggerTimer = 0;
        }
    }
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

typedef struct IntVec3 {
    int a;
    int b;
    int c;
} IntVec3;

typedef struct ArwAttachTarget {
    f32 x;
    f32 y;
    f32 moveId;
    f32 altMoveId;
    f32 speed;
} ArwAttachTarget;

#pragma scheduling off
#pragma peephole off
void fn_801F2290(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int id);
    extern void GameBit_Set(int slot, int val);
    extern void buttonDisable(int a, int b);
    extern int getAngle(f32 x, f32 y);
    extern f32 sqrtf(f32 x);
    extern void fn_80137948(char *fmt, ...);
    extern int *gGameUIInterface;
    extern int lbl_802C2470[];
    extern ArwAttachTarget lbl_80328974[];
    extern char sArwingAttachmentDiffFormat[];
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5DA8;
    extern f32 lbl_803E5DAC;
    extern f32 lbl_803E5DB0;
    extern f32 lbl_803E5DB4;
    Dll200State *b;
    u8 m;
    s16 ang;
    s16 diff;
    f32 dx;
    f32 dy;
    f32 dist;
    f32 spd;
    IntVec3 stk;
    ObjAnimEventList animEvents;

    b = ((GameObject *)obj)->extra;
    Obj_GetPlayerObject();
    stk = *(IntVec3 *)lbl_802C2470;
    ((GameObject *)obj)->anim.localPosY = b->homeY;
    if (GameBit_Get(0x1fc) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8);
        if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0 &&
            (**(int (**)(IntVec3 *, int))(*gGameUIInterface + 0x24))(&stk, 3) > -1) {
            GameBit_Set(0x4d1, 1);
            b->counter27 += 1;
            GameBit_Set(0x310, 1);
            buttonDisable(0, 0x100);
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
        if (b->modeTimer <= 0) {
            switch (randomGetRange(1, 4)) {
            case 1:
                b->prevMode = (u8)b->mode;
                b->mode = 1;
                b->modeTimer = 400;
                break;
            case 2:
                b->prevMode = (u8)b->mode;
                b->mode = 2;
                b->modeTimer = 400;
                break;
            case 3:
                b->prevMode = (u8)b->mode;
                b->mode = 3;
                b->modeTimer = 400;
                break;
            case 4:
                b->prevMode = (u8)b->mode;
                b->mode = 4;
                b->modeTimer = 400;
                break;
            case 5:
                b->prevMode = (u8)b->mode;
                b->mode = 5;
                b->modeTimer = 400;
                break;
            }
        } else {
            m = b->mode;
            if (m == 12) {
                ang = getAngle(lbl_80328974[b->prevMode].x,
                               lbl_80328974[b->prevMode].y);
                diff = (s16)(ang - *(s16 *)obj);
                fn_80137948(sArwingAttachmentDiffFormat, diff);
                if (diff < -1000 || diff > 1000) {
                    if (diff > 0) {
                        *(s16 *)obj = (s16)(*(s16 *)obj + framesThisStep * 100);
                    } else {
                        *(s16 *)obj = (s16)(*(s16 *)obj - framesThisStep * 100);
                    }
                } else {
                    ObjAnim_SetCurrentMove(obj, (int)lbl_80328974[b->prevMode].moveId,
                                           lbl_803E5D98, 0);
                    b->animSpeed = lbl_80328974[b->prevMode].speed;
                    b->mode = 13;
                }
            } else if (m == 13) {
                if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                        (obj, b->animSpeed, timeDelta, &animEvents) != 0) {
                    if ((f32)(int)((GameObject *)obj)->anim.currentMove ==
                        lbl_80328974[b->prevMode].moveId) {
                        ObjAnim_SetCurrentMove(obj,
                                               (int)lbl_80328974[b->prevMode].altMoveId,
                                               lbl_803E5D98, 0);
                        b->animSpeed = lbl_80328974[b->prevMode].speed;
                    }
                }
                b->modeTimer -= framesThisStep;
                if (b->modeTimer <= 0) {
                    b->modeTimer = 0;
                }
            } else {
                dx = lbl_80328974[m].x - (((GameObject *)obj)->anim.localPosX - b->homeX);
                dy = lbl_80328974[m].y - (((GameObject *)obj)->anim.localPosZ - b->homeZ);
                dist = sqrtf(dx * dx + dy * dy);
                ang = getAngle(dx, dy);
                diff = (s16)(ang - *(s16 *)obj);
                if (diff >= -1000 && diff <= 1000) {
                    if (((GameObject *)obj)->anim.currentMove != 59) {
                        ObjAnim_SetCurrentMove(obj, 59, lbl_803E5D98, 0);
                        b->animSpeed = lbl_803E5DA8;
                    }
                    spd = lbl_803E5DAC;
                    ((GameObject *)obj)->anim.velocityX = spd * (dx / dist);
                    ((GameObject *)obj)->anim.velocityZ = spd * (dy / dist);
                    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)
                        (obj, spd, &b->animSpeed);
                } else {
                    if (((GameObject *)obj)->anim.currentMove != 12) {
                        ObjAnim_SetCurrentMove(obj, 12, lbl_803E5D98, 0);
                        b->animSpeed = lbl_803E5DB0;
                    }
                    if (diff > 0) {
                        *(s16 *)obj = (s16)(*(s16 *)obj + framesThisStep * 300);
                    } else {
                        *(s16 *)obj = (s16)(*(s16 *)obj - framesThisStep * 300);
                    }
                }
                if (dist < lbl_803E5DB4) {
                    b->prevMode = (u8)b->mode;
                    b->mode = 12;
                    spd = lbl_803E5D98;
                    ((GameObject *)obj)->anim.velocityX = spd;
                    ((GameObject *)obj)->anim.velocityZ = spd;
                }
                ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
                ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
                ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, b->animSpeed, timeDelta, &animEvents);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
