#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2projrock.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"

typedef struct Dim2lavacontrolPlacement {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 unk19;
    u8 unk1A;
    u8 unk1B;
    s16 unk1C;
    s16 unk1E;
} Dim2lavacontrolPlacement;


typedef struct Dim2iciclePlacement {
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 unkC;
    u8 pad10[0x1E - 0x10];
    s16 unk1E;
} Dim2iciclePlacement;


typedef struct Dll1DAState {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} Dll1DAState;


typedef struct Dll1DFState {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x24 - 0x7];
    f32 unk24;
} Dll1DFState;


typedef struct Dll1DBPlacement {
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 unkC;
    u8 pad10[0x1E - 0x10];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} Dll1DBPlacement;


typedef struct Dim2lavacontrolState {
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s8 unk2;
    u8 pad3[0x24 - 0x3];
    f32 unk24;
} Dim2lavacontrolState;


typedef struct Dll1DBState {
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s8 unk2;
    u8 pad3[0x4 - 0x3];
    u8 unk4;
    u8 pad5[0x24 - 0x5];
    f32 unk24;
} Dll1DBState;


extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80017af8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_AddContactObject();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80047fdc();
extern undefined4 FUN_80053b3c();
extern int FUN_800620e8();
extern int FUN_800632f4();
extern undefined4 FUN_80080f14();
extern undefined4 FUN_800e8630();
extern int FUN_800e8b98();
extern undefined4 FUN_800ea9b8();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern uint FUN_80294d00();
extern undefined4 FUN_80294da0();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb90;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e57c0;
extern f64 DOUBLE_803e57d8;
extern f64 DOUBLE_803e57f8;
extern f64 DOUBLE_803e5820;
extern f32 lbl_803DC074;
extern f32 lbl_803E5770;
extern f32 lbl_803E5774;
extern f32 lbl_803E5778;
extern f32 lbl_803E577C;
extern f32 lbl_803E5780;
extern f32 lbl_803E5784;
extern f32 lbl_803E5788;
extern f32 lbl_803E5790;
extern f32 lbl_803E5794;
extern f32 lbl_803E5798;
extern f32 lbl_803E579C;
extern f32 lbl_803E57A4;
extern f32 lbl_803E57A8;
extern f32 lbl_803E57AC;
extern f32 lbl_803E57B0;
extern f32 lbl_803E57B4;
extern f32 lbl_803E57B8;
extern f32 lbl_803E57BC;
extern f32 lbl_803E57CC;
extern f32 lbl_803E57D0;
extern f32 lbl_803E57D4;
extern f32 lbl_803E57E0;
extern f32 lbl_803E57E4;
extern f32 lbl_803E57E8;
extern f32 lbl_803E57EC;
extern f32 lbl_803E57F0;
extern f32 lbl_803E5804;
extern f32 lbl_803E5808;
extern f32 lbl_803E580C;
extern f32 lbl_803E5810;
extern f32 lbl_803E5814;
extern f32 lbl_803E5818;
extern f32 lbl_803E5828;
extern f32 lbl_803E5834;
extern f32 lbl_803E5838;
extern f32 lbl_803E583C;
extern undefined uRam803dcb93;

/*
 * --INFO--
 *
 * Function: FUN_801b8c60
 * EN v1.0 Address: 0x801B8C60
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B8D60
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
 * Function: FUN_801b9728
 * EN v1.0 Address: 0x801B9728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B9578
 * EN v1.1 Size: 576b
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
 * Function: FUN_801b972c
 * EN v1.0 Address: 0x801B972C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801B97B8
 * EN v1.1 Size: 524b
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
 * Function: FUN_801b9cc4
 * EN v1.0 Address: 0x801B9CC4
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801B9DC4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9cc4(int param_1)
{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = ((GameObject *)param_1)->extra;
  if ((pcVar1[2] & 1U) == 0) {
    iVar2 = *(int *)&((GameObject *)param_1)->anim.placementData;
    if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0')) {
      pcVar1[2] = pcVar1[2] | 1;
      GameBit_Set((int)*(short *)(iVar2 + 0x1e),1);
    }
  }
  return;
}



/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_1DA_release(void) {}
void dll_1DA_initialise(void) {}
void dll_1DB_free(void) {}
void dll_1DB_hitDetect(void) {}
void dll_1DB_release(void) {}
void dll_1DB_initialise(void) {}
void dim2icefloe_free(void) {}
void dim2icefloe_hitDetect(void) {}
void dim2icefloe_release(void) {}
void dim2icefloe_initialise(void) {}
void dim2icicle_free(void) {}
void dim2icicle_hitDetect(void) {}
void dim2icicle_release(void) {}
void dim2icicle_initialise(void) {}

extern u32 GameBit_Get(int id);
extern f32 lbl_803E4B80;
void dim2icicle_init(int obj, s8 *p) {
    char *inner = ((GameObject *)obj)->extra;
    if (GameBit_Get(*(s16 *)(p + 0x1e)) != 0) {
        inner[6] = 2;
        ((GameObject *)obj)->anim.alpha = 0;
    } else {
        inner[6] = 0;
        ((GameObject *)obj)->anim.alpha = 0xff;
    }
    *(s16 *)obj = (s16)((s32)p[0x18] << 8);
    ((GameObject *)obj)->anim.velocityY = lbl_803E4B80;
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

/* dim2icefloe: per-frame curve-follow update + path-param init. */
typedef struct {
    u8 finished : 1;
    u8 rest : 7;
} IceFloeFlags;

extern int ObjList_FindObjectById(int id);
extern f32 Curve_EvalHermite(f32 t, f32 *values, f32 *outTangent);
extern void Curve_BuildHermiteCoeffs();
extern void curvesMove(int curves);
extern int Curve_AdvanceAlongPath(int curve, f32 t);
extern void fn_80296D20(void *player, int obj);
extern int Obj_FreeObject(int obj);
extern u8 framesThisStep;
extern f32 timeDelta;
extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803E4B34;
extern f32 lbl_803E4B38;
extern f32 lbl_803E4B3C;

void dim2icefloe_update(int obj)
{
    int sub = *(int *)&((GameObject *)obj)->extra;
    if (*(void **)&((Dim2IceFloeState *)sub)->unk9C != NULL && (*(u16 *)(((Dim2IceFloeState *)sub)->unk9C + 0xb0) & 0x40) != 0) {
        ((Dim2IceFloeState *)sub)->unkB6 &= ~1;
        ((Dim2IceFloeState *)sub)->unk9C = 0;
    } else {
        int v;
        int reached;
        if ((int)((Dim2IceFloeState *)sub)->unkB8 != 0) {
            return;
        }
        v = ((GameObject *)obj)->anim.alpha + framesThisStep * 4;
        if (v > 0xff) {
            v = 0xff;
        }
        ((GameObject *)obj)->anim.alpha = v;
        if ((((Dim2IceFloeState *)sub)->unkB6 & 1) == 0) {
            ((Dim2IceFloeState *)sub)->unk9C = ObjList_FindObjectById(((Dim2IceFloeState *)sub)->objectId);
            ((Dim2IceFloeState *)sub)->unk90 = (*(code *)(**(int **)(((Dim2IceFloeState *)sub)->unk9C + 0x68) + 0x20))(
                ((Dim2IceFloeState *)sub)->unk9C, sub + 0x84, sub + 0x88, sub + 0x8c, 0);
            ((Dim2IceFloeState *)sub)->unk80 = 0;
            ((Dim2IceFloeState *)sub)->unk94 = (void *)Curve_EvalHermite;
            ((Dim2IceFloeState *)sub)->unk98 = (void *)Curve_BuildHermiteCoeffs;
            curvesMove(sub);
            ((Dim2IceFloeState *)sub)->unkB6 |= 1;
        }
        Curve_AdvanceAlongPath(sub, ((Dim2IceFloeState *)sub)->unkA4);
        reached = ((Dim2IceFloeState *)sub)->unk10 >= ((Dim2IceFloeState *)sub)->unk90 - 4;
        ((GameObject *)obj)->anim.localPosX = ((Dim2IceFloeState *)sub)->unk68;
        if (!((IceFloeFlags *)(sub + 0xb9))->finished) {
            ((GameObject *)obj)->anim.localPosY = lbl_803E4B34 + ((Dim2IceFloeState *)sub)->unk6C;
        }
        ((GameObject *)obj)->anim.localPosZ = ((Dim2IceFloeState *)sub)->unk70;
        if (reached) {
            ((IceFloeFlags *)(sub + 0xb9))->finished = 1;
        }
        ((Dim2IceFloeState *)sub)->unkB4 = timeDelta * ((Dim2IceFloeState *)sub)->unkAC + (f32)*(u16 *)&((Dim2IceFloeState *)sub)->unkB4;
        if (((IceFloeFlags *)(sub + 0xb9))->finished) {
            ((GameObject *)obj)->anim.localPosY = -(lbl_803E4B38 * timeDelta - ((GameObject *)obj)->anim.localPosY);
            if (((GameObject *)obj)->anim.localPosY < ((Dim2IceFloeState *)sub)->unk6C) {
                ObjHits_DisableObject(obj);
                ((GameObject *)obj)->objectFlags |= 0x100;
                fn_80296D20(Obj_GetPlayerObject(), obj);
            }
            if (((GameObject *)obj)->anim.localPosY < ((Dim2IceFloeState *)sub)->unk6C - lbl_803E4B3C) {
                Obj_FreeObject(obj);
            }
        }
    }
}

extern f32 lbl_803E4B48;
extern f32 lbl_803E4B4C;
extern f32 lbl_803E4B50;
extern f32 lbl_803E4B54;
extern f32 lbl_803E4B58;

void dim2icefloe_init(int obj, int p)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int sub = *(int *)&((GameObject *)obj)->extra;
    ((Dim2IceFloeState *)sub)->objectId = *(int *)(p + 0x14);
    ((Dim2IceFloeState *)sub)->unkA4 = (f32)*(s16 *)(p + 0x1c) / lbl_803E4B48;
    ((Dim2IceFloeState *)sub)->unkA8 = (f32)(s32)randomGetRange(-0x1e, 0x1e);
    *(int *)(p + 0x14) = -1;
    objAnim->bankIndex = (s8)randomGetRange(0, objAnim->modelInstance->modelCount - 1);
    ((GameObject *)obj)->anim.rotX = (s16)((s32)*(s8 *)(p + 0x18) << 8);
    ((GameObject *)obj)->anim.rotX = (s16)randomGetRange(0, 0xffff);
    ((GameObject *)obj)->anim.alpha = 0;
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x109:
        ((Dim2IceFloeState *)sub)->unkAC = lbl_803E4B4C + (f32)(s32)randomGetRange(0, 0x28);
        ((Dim2IceFloeState *)sub)->unkB0 = lbl_803E4B50;
        break;
    case 0x10d:
        ((Dim2IceFloeState *)sub)->unkAC = lbl_803E4B54 + (f32)(s32)randomGetRange(0, 0x32);
        ((Dim2IceFloeState *)sub)->unkB0 = lbl_803E4B50;
        break;
    case 0x111:
    default:
        ((Dim2IceFloeState *)sub)->unkAC = lbl_803E4B58 + (f32)(s32)randomGetRange(0, 0x28);
        ((Dim2IceFloeState *)sub)->unkB0 = lbl_803E4B50;
        break;
    }
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int *out, int a, int b);
extern WaterfxInterface **gWaterfxInterface;
extern f32 lbl_803E4B6C;
extern f32 lbl_803E4B70;
extern f32 lbl_803E4B74;
extern f32 lbl_803E4B78;
extern f32 lbl_803E4B7C;

void dim2icicle_update(int obj)
{
    int sub;
    int state;
    state = *(int *)&((GameObject *)obj)->anim.placementData;
    sub = *(int *)&((GameObject *)obj)->extra;
    switch (((Dim2IcicleState *)sub)->mode) {
    case 0:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0xe) {
            break;
        }
        ((Dim2IcicleState *)sub)->unk4 = (s16)randomGetRange(0x320, 0x4b0);
        ((Dim2IcicleState *)sub)->mode = 3;
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
        Sfx_PlayFromObject(obj, SFXmv_cflap2_c);
        break;
    case 3:
        ((GameObject *)obj)->anim.rotY = ((Dim2IcicleState *)sub)->unk4;
        ((Dim2IcicleState *)sub)->unk4 = (f32)((Dim2IcicleState *)sub)->unk4 * lbl_803E4B6C;
        if (((GameObject *)obj)->anim.rotY >= 10) {
            break;
        }
        ((GameObject *)obj)->anim.rotY = 0;
        ((Dim2IcicleState *)sub)->mode = 1;
        ((Dim2IcicleState *)sub)->timer = 0x3c;
        break;
    case 1:
        if (((Dim2IcicleState *)sub)->unk7 == 0) {
            int n;
            int i;
            int list;
            n = hitDetectFn_80065e50(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                     ((GameObject *)obj)->anim.localPosZ, obj, &list, 0, 0);
            ((Dim2IcicleState *)sub)->dropY = lbl_803E4B70;
            for (i = 0; i < n; i++) {
                int p = *(int *)(list + i * 4);
                if (*(s8 *)(p + 0x14) == 0xe) {
                    ((Dim2IcicleState *)sub)->dropY = *(f32 *)p;
                    i = n;
                }
            }
            if (lbl_803E4B70 != ((Dim2IcicleState *)sub)->dropY) {
                ((Dim2IcicleState *)sub)->unk7 = 1;
            }
        }
        if (((Dim2IcicleState *)sub)->timer > 0) {
            ((Dim2IcicleState *)sub)->timer -= framesThisStep;
            if (((Dim2IcicleState *)sub)->timer <= 0) {
                Sfx_PlayFromObject(obj, SFXmv_blockscrape_lp);
            }
        }
        ((GameObject *)obj)->anim.velocityY = -(lbl_803E4B74 * timeDelta - ((GameObject *)obj)->anim.velocityY);
        if (((GameObject *)obj)->anim.velocityY < lbl_803E4B78) {
            ((GameObject *)obj)->anim.velocityY = *(f32 *)&lbl_803E4B78;
        }
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
        if (((GameObject *)obj)->anim.localPosY < ((Dim2IcicleState *)sub)->dropY) {
            GameBit_Set(((Dim2iciclePlacement *)state)->unk1E, 1);
            ((Dim2IcicleState *)sub)->mode = 2;
            (*gWaterfxInterface)->spawnSplashBurst(
                (void *)obj, ((GameObject *)obj)->anim.localPosX,
                ((Dim2IcicleState *)sub)->dropY, ((GameObject *)obj)->anim.localPosZ,
                lbl_803E4B7C);
            ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                ((GameObject *)obj)->anim.localPosX, ((Dim2IcicleState *)sub)->dropY,
                ((GameObject *)obj)->anim.localPosZ, 0, lbl_803E4B80, 2);
            Sfx_PlayFromObject(obj, SFXmv_missingcog_lp);
            ((Dim2IcicleState *)sub)->timer = 0x96;
        }
        break;
    case 2:
    default:
        if (((Dim2IcicleState *)sub)->timer > 0) {
            ((Dim2IcicleState *)sub)->timer -= framesThisStep;
            if (((Dim2IcicleState *)sub)->timer <= 0) {
                Sfx_PlayFromObject(obj, SFXwp_sexpl2_c);
            }
        }
        {
            int v = ((GameObject *)obj)->anim.alpha - framesThisStep * 8;
            if (v < 0) {
                v = 0;
                ((GameObject *)obj)->anim.localPosY = ((Dim2iciclePlacement *)state)->unkC;
                ((GameObject *)obj)->anim.velocityY = lbl_803E4B80;
            }
            ((GameObject *)obj)->anim.alpha = v;
        }
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
        break;
    }
}

/* dll_1DB_update: geyser state machine driven by player standing on it. */
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 lbl_803E4B0C;
extern f32 lbl_803E4B10;
extern f32 lbl_803E4B14;
extern f32 lbl_803E4B18;
extern f32 lbl_803E4B1C;
extern f32 lbl_803E4B20;
extern f32 lbl_803E4B24;

void dll_1DB_update(int obj)
{
    int sub;
    int state;
    int found;
    u32 player;
    int i;
    int n;
    int base;

    sub = *(int *)&((GameObject *)obj)->extra;
    player = (u32)Obj_GetPlayerObject();
    state = *(int *)&((GameObject *)obj)->anim.placementData;
    found = 0;
    i = 0;
    base = *(int *)(obj + 0x58);
    for (n = (int)*(s8 *)(base + 0x10f); n > 0; n--) {
        u32 entry = *(u32 *)(base + i + 0x100);
        if (entry == player) {
            found = 1;
            break;
        }
        i += 4;
    }
    switch (((Dll1DBState *)sub)->unk4) {
    case 1:
        Sfx_StopObjectChannel(obj, 8);
        if (found == 0) {
            *(u8 *)(sub + 6) = 1;
        } else if (*(u8 *)(sub + 6) != 0 && *(u8 *)(sub + 5) != 0) {
            Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
            ((Dll1DBState *)sub)->unk4 = 4;
            *(f32 *)sub = lbl_803E4B0C;
        }
        if (GameBit_Get(((Dll1DBPlacement *)state)->unk20) != 0) {
            Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
            ((Dll1DBState *)sub)->unk4 = 4;
            *(f32 *)sub = lbl_803E4B0C;
        }
        break;
    case 2:
        Sfx_StopObjectChannel(obj, 8);
        if (*(u8 *)(sub + 5) != 0) {
            if (found == 0) {
                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
                ((Dll1DBState *)sub)->unk4 = 3;
                *(f32 *)sub = lbl_803E4B0C;
                *(u8 *)(sub + 5) = 0;
                GameBit_Set(((Dll1DBPlacement *)state)->unk1E, 0);
            }
        } else {
            if (GameBit_Get(((Dll1DBPlacement *)state)->unk20) == 0) {
                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt3);
                ((Dll1DBState *)sub)->unk4 = 3;
                *(f32 *)sub = lbl_803E4B0C;
                *(u8 *)(sub + 5) = 0;
                GameBit_Set(((Dll1DBPlacement *)state)->unk1E, 0);
            }
        }
        break;
    case 3:
        *(f32 *)sub = *(f32 *)sub + (lbl_803E4B10 * timeDelta +
                                     lbl_803E4B14 * (f32)(s32)(*(f32 *)sub < lbl_803E4B0C));
        {
            f32 v = *(f32 *)sub;
            if (v > lbl_803E4B18) {
                *(f32 *)sub = *(f32 *)&lbl_803E4B18;
            }
        }
        ((GameObject *)obj)->anim.localPosY = *(f32 *)sub * timeDelta + ((GameObject *)obj)->anim.localPosY;
        if (((GameObject *)obj)->anim.localPosY > ((Dll1DBPlacement *)state)->unkC) {
            Sfx_PlayFromObject(obj, SFXchar_on_firelp);
            ((GameObject *)obj)->anim.localPosY = ((Dll1DBPlacement *)state)->unkC;
            ((Dll1DBState *)sub)->unk4 = 1;
            if (found != 0) {
                *(u8 *)(sub + 5) = 1;
                *(u8 *)(sub + 6) = 0;
            }
        }
        break;
    case 4:
        *(f32 *)sub = lbl_803E4B1C * timeDelta + *(f32 *)sub;
        {
            f32 v = *(f32 *)sub;
            if (v < lbl_803E4B20) {
                *(f32 *)sub = *(f32 *)&lbl_803E4B20;
            }
        }
        ((GameObject *)obj)->anim.localPosY = *(f32 *)sub * timeDelta + ((GameObject *)obj)->anim.localPosY;
        if (((GameObject *)obj)->anim.localPosY < ((Dll1DBPlacement *)state)->unkC - lbl_803E4B24) {
            Sfx_PlayFromObject(obj, SFXchar_on_firelp);
            ((GameObject *)obj)->anim.localPosY = ((Dll1DBPlacement *)state)->unkC - lbl_803E4B24;
            ((Dll1DBState *)sub)->unk4 = 2;
            GameBit_Set(((Dll1DBPlacement *)state)->unk1E, 1);
        }
        if (*(u8 *)(sub + 5) == 0) {
            if (GameBit_Get(((Dll1DBPlacement *)state)->unk20) == 0) {
                ((Dll1DBState *)sub)->unk4 = 3;
                GameBit_Set(((Dll1DBPlacement *)state)->unk1E, 0);
            }
        }
        break;
    }
}

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int objBboxFn_800640cc(int a, int b, f32 r, int c, int *out, int obj, int d, int e, int f,
                              int g);
extern f32 sqrtf(f32 x);
extern void saveGame_saveObjectPos(int obj);
extern f32 lbl_803E4AD8;
extern f32 lbl_803E4ADC;
extern f32 lbl_803E4AE0;
extern f32 lbl_803E4AE4;
extern f32 lbl_803E4AE8;
extern f32 lbl_803E4AEC;
extern f32 lbl_803E4AF0;
extern f32 lbl_803E4AF4;
extern f32 lbl_803E4AF8;
extern f32 lbl_803E4AFC;
extern f32 lbl_803E4B00;
extern const f32 lbl_803E4B04;

typedef struct {
    int hit[7];
    f32 nx;
    f32 ny;
    f32 nz;
    int pad[8];
} RockHitInfo;

void dll_1DA_update(int obj)
{
    int sub;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 len;
    f32 k;
    f32 hi;
    f32 lo;
    f32 e;
    f32 d;
    int n;
    int list;
    int p;
    int i;
    RockHitInfo out;

    sub = *(int *)&((GameObject *)obj)->extra;
    if (((Dll1DAState *)sub)->unk4 != 0) {
        ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4AE0);
        ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
    } else {
        ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4AE4);
        ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
    }
    if (((GameObject *)obj)->anim.velocityX < (hi = lbl_803E4AE8) && ((GameObject *)obj)->anim.velocityX > (lo = lbl_803E4AEC) &&
        ((GameObject *)obj)->anim.velocityZ < hi && ((GameObject *)obj)->anim.velocityZ > lo) {
        ((GameObject *)obj)->anim.velocityX = (k = lbl_803E4AF0);
        ((GameObject *)obj)->anim.velocityZ = k;
    }
    objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, lbl_803E4AF0, ((GameObject *)obj)->anim.velocityZ * timeDelta);
    n = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E4AF4, 1, out.hit, obj, 8, -1, 0xff, 0);
    if (n != 0) {
        vx = -((GameObject *)obj)->anim.velocityX;
        vy = -((GameObject *)obj)->anim.velocityY;
        vz = -((GameObject *)obj)->anim.velocityZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (lbl_803E4AF0 != len) {
            f32 s = lbl_803E4AD8 / len;
            vx = vx * s;
            vy = vy * s;
            vz = vz * s;
        }
        d = lbl_803E4AF8 * (vz * out.nz + (vx * out.nx + vy * out.ny));
        ((GameObject *)obj)->anim.velocityX = out.nx * d;
        ((GameObject *)obj)->anim.velocityY = out.ny * d;
        ((GameObject *)obj)->anim.velocityZ = out.nz * d;
        ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX - vx;
        ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY - vy;
        ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ - vz;
        ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (e = lbl_803E4AFC * len);
        ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * (lbl_803E4ADC * len);
        ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * e;
    }
    ((GameObject *)obj)->anim.localPosY = -(lbl_803E4B00 * timeDelta - ((GameObject *)obj)->anim.localPosY);
    n = hitDetectFn_80065e50(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ, obj,
                             &list, 0, 0x11);
    ((Dll1DAState *)sub)->unk4 = 0;
    i = 0;
    p = list;
    for (; n > 0; n--) {
        if (((GameObject *)obj)->anim.localPosY < lbl_803E4B04 + **(f32 **)p) {
            ((GameObject *)obj)->anim.localPosY = **(f32 **)(list + i * 4);
            ObjHits_AddContactObject(*(int *)(*(int *)(list + i * 4) + 0x10), obj);
            ((Dll1DAState *)sub)->unk4 = 1;
            break;
        }
        p += 4;
        i += 1;
    }
    if (((GameObject *)obj)->anim.localPosY < *(f32 *)sub) {
        ((GameObject *)obj)->anim.localPosY = *(f32 *)sub;
    }
    saveGame_saveObjectPos(obj);
}

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */
extern int *gBaddieControlInterface;
extern int *gPlayerInterface;
extern u8 lbl_803DDB84;
extern u8 lbl_80325960[];
extern u8 gDIMbossAnimController[];
extern int fn_801BC2D8(int a, int obj);
extern f32 lbl_803E4BB8;

typedef void (*BaddieQueryFn)(int a, int objId, int n, u16 *anim, u16 *pad, u16 *dist);
typedef u8 (*BaddieCheckFn)(int a, int obj, f32 d);
typedef void (*PlayerAnimFn)(int a, int obj, int animId);

typedef struct {
    u8 pad[0x168];
    s16 surprised[6]; /* 0x168 */
    s16 group3[8];    /* 0x174 */
    s16 group2[8];    /* 0x184 */
    s16 group1[8];    /* 0x194 */
} DimAnimTable;

int fn_801B9ECC(int a, int obj)
{
    DimAnimTable *base;
    u16 pad;
    u16 dist;
    u16 anim[2];

    base = (DimAnimTable *)lbl_80325960;
    if (*(s8 *)(obj + 0x346) != 0 || *(s8 *)(obj + 0x27b) != 0) {
        (*(BaddieQueryFn)*(int *)(*gBaddieControlInterface + 0x14))(a, *(int *)(obj + 0x2d0), 0x10,
                                                                    anim, &pad, &dist);
        *(u8 *)(obj + 0x346) = 0;
        if (dist < 0x5a) {
            if (dist > 0x1e &&
                ((u16)(anim[0] - 3) <= 1 || anim[0] == 0xb || anim[0] == 0xc)) {
                (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(a, obj, 2);
            } else {
                (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(a, obj, 9);
            }
        } else if (anim[0] == 0 || anim[0] == 0xf) {
            *(u8 *)(obj + 0x346) = 0;
            if (dist > 0x1a9 &&
                ((*(BaddieCheckFn)*(int *)(*gBaddieControlInterface + 0x18))(a, obj, lbl_803E4BB8) &
                 1) != 0) {
                (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(
                    a, obj, base->surprised[randomGetRange(0, 5)]);
            } else if (dist < 0xfa) {
                (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(a, obj, 3);
            } else {
                if (lbl_803DDB84 > 6) {
                    lbl_803DDB84 = 0;
                }
                switch (*(s8 *)(obj + 0x354)) {
                case 3:
                    (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(
                        a, obj, base->group3[lbl_803DDB84++]);
                    break;
                case 2:
                    (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(
                        a, obj, base->group2[lbl_803DDB84++]);
                    break;
                case 1:
                    (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(
                        a, obj, base->group1[lbl_803DDB84++]);
                    break;
                default:
                    (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(a, obj, 3);
                    break;
                }
            }
        } else {
            (*(PlayerAnimFn)*(int *)(*gPlayerInterface + 0x14))(a, obj, 2);
        }
    }
    if (*(s16 *)(obj + 0x274) == 3 || *(s16 *)(obj + 0x274) == 7) {
        gDIMbossAnimController[0x611] |= 1;
    } else {
        gDIMbossAnimController[0x611] &= ~1;
    }
    fn_801BC2D8(a, obj);
    return 0;
}

void dll_1DF_free(void) {}
void dll_1DF_hitDetect(void) {}
void dll_1DF_release(void) {}
void dll_1DF_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_1DB_getExtraSize(void) { return 0x8; }
int dll_1DB_getObjectTypeId(void) { return 0x0; }
int dim2icefloe_getExtraSize(void) { return 0xbc; }
int dim2icefloe_getObjectTypeId(void) { return 0x0; }
int dim2icicle_getExtraSize(void) { return 0xc; }
int dim2icicle_getObjectTypeId(void) { return 0x0; }
int dim2lavacontrol_getExtraSize(void) { return 0x10; }
int dll_1DF_getExtraSize(void) { return 0x28; }
int dll_1DF_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4B08;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4B30;
extern f32 lbl_803E4B68;
extern f32 lbl_803E4B90;
extern f32 lbl_803E4B98;
void dll_1DB_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4B08); }
void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4B30); }
void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4B68); }
void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4B90); }
void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4B98); }

/* dll_1DA_init: stash obj->f10 into *(obj->p_B8), then bump obj->f10 by a constant step. */
void dll_1DA_init(void* obj)
{
    *(*(f32**)&((GameObject *)obj)->extra) = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + lbl_803E4AD8;
}

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */
extern f32 lbl_803E4BA8;
extern f32 lbl_803E4BAC;
void dll_1DF_init(void* obj, void* p)
{
    u32 flag;
    void* p50;
    void* p64;
    ((GameObject *)obj)->anim.rotZ = (s16)((u32)*(u8*)((char*)p + 0x18) << 8);
    ((GameObject *)obj)->anim.rotY = (s16)((u32)*(u8*)((char*)p + 0x19) << 8);
    ((GameObject *)obj)->anim.rotX = (s16)((u32)*(u8*)((char*)p + 0x1A) << 8);
    flag = *(u8*)((char*)p + 0x1B);
    if (flag != 0) {
        p50 = *(void**)&((GameObject *)obj)->anim.modelInstance;
        ((GameObject *)obj)->anim.rootMotionScale = ((ObjDef *)p50)->rootMotionScaleBase * ((f32)flag / lbl_803E4BA8);
    }
    *(f32*)((char*)*(void**)&((GameObject *)obj)->extra + 0x10) = lbl_803E4BAC;
    p64 = *(void**)&((GameObject *)obj)->anim.modelState;
    if (p64 != 0) {
        ((ObjModelState *)p64)->flags |= 0x810;
    }
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */
void dim2lavacontrol_setScale(void* obj)
{
    void* sub = ((GameObject *)obj)->extra;
    if (((s32)((Dim2lavacontrolState *)sub)->unk2 & 1) == 0) {
        void* p = *(void**)&((GameObject *)obj)->anim.placementData;
        s8 cnt = ((Dim2lavacontrolState *)sub)->unk0;
        if ((s32)cnt > 0) {
            ((Dim2lavacontrolState *)sub)->unk0 = cnt - 1;
            if (((Dim2lavacontrolState *)sub)->unk0 == 0) {
                ((Dim2lavacontrolState *)sub)->unk2 = (s8)(*(u8 *)&((Dim2lavacontrolState *)sub)->unk2 | 1);
                GameBit_Set(((Dim2lavacontrolPlacement *)p)->unk1E, 1);
            }
        }
    }
}

/* dim2lavacontrol_free: stop lava sfx, kill the lava music track, refresh time-of-day. */
extern void fn_8004C1E4(int sfxId, f32 vol);
extern void Music_Trigger(int trackId, int restart);
extern void timeOfDayFn_80055000(void);
void dim2lavacontrol_free(void)
{
    fn_8004C1E4(0xC0, lbl_803E4B90);
    Music_Trigger(0xC4, 0);
    timeOfDayFn_80055000();
}

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */
extern void* objFindTexture(void* obj, int a, int b);
extern void* Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern f32 lbl_803E4B9C, lbl_803E4BA0, lbl_803E4BA4;
void dll_1DF_update(void* obj)
{
    void* sub = ((GameObject *)obj)->extra;
    void* tex;
    void* player;
    f32 dist;
    f32 t;

    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) {
        if (((GameObject *)obj)->anim.seqId == 209) {
            f32 v = lbl_803E4B9C;
            *(u8*)((char*)tex + 0xC) = v;
            *(u8*)((char*)tex + 0xD) = v;
            *(u8*)((char*)tex + 0xE) = v;
        } else {
            f32 v = lbl_803E4B9C;
            *(u8*)((char*)tex + 0xC) = v;
            *(u8*)((char*)tex + 0xD) = v;
            *(u8*)((char*)tex + 0xE) = v;
        }
    }
    player = Obj_GetPlayerObject();
    dist = vec3f_distanceSquared(&((GameObject *)player)->anim.worldPosX, &((GameObject *)obj)->anim.worldPosX);
    if (dist < lbl_803E4BA0) {
        t = ((Dll1DFState *)sub)->unk24 - timeDelta;
        ((Dll1DFState *)sub)->unk24 = t;
        if (t < lbl_803E4B9C) {
            (*gPartfxInterface)->spawnObject(obj, 525, NULL, 2, -1, NULL);
            ((Dll1DFState *)sub)->unk24 = lbl_803E4BA4;
        }
    }
}

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */
void dll_1DB_init(void* obj, void* p)
{
    void* sub = ((GameObject *)obj)->extra;
    s16 t = (s16)((s32)*(s8*)((char*)p + 0x18) << 8);
    ((GameObject *)obj)->anim.rotX = t;
    if (GameBit_Get(*(s16*)((char*)p + 0x1E)) != 0) {
        ((Dll1DBState *)sub)->unk4 = 2;
    } else {
        ((Dll1DBState *)sub)->unk4 = 1;
    }
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

extern int getSaveGameLoadStatus(void);
extern void gameBitFn_800ea2e0(int i);
extern void envFxActFn_800887f8(int a);
extern u8 lbl_803DBF28[8];

void dim2lavacontrol_init(int obj, int param2)
{
    int state;
    int i;
    int g;
    if (getSaveGameLoadStatus() != 0) {
        ((GameObject *)obj)->unkF4 = 2;
    } else {
        ((GameObject *)obj)->unkF4 = 1;
    }
    for (i = 1; (u8)i <= 0x2d; i++) {
        gameBitFn_800ea2e0(i);
    }
    state = *(int *)&((GameObject *)obj)->extra;
    ((Dim2lavacontrolState *)state)->unk0 = (s8)*(s16 *)(param2 + 0x1a);
    *(u8 *)(state + 1) = *(u8 *)&((Dim2lavacontrolState *)state)->unk0;
    if (GameBit_Get(*(s16 *)(param2 + 0x1e)) != 0) {
        g = 1;
    } else {
        g = 0;
    }
    ((Dim2lavacontrolState *)state)->unk2 = (s8)(*(u8 *)&((Dim2lavacontrolState *)state)->unk2 | g);
    *(int *)(state + 0xc) = 0xd7;
    *(u8 *)(state + 4) = 0;
    if ((((Dim2lavacontrolState *)state)->unk2 & 1) != 0) {
        *(u8 *)&((Dim2lavacontrolState *)state)->unk0 = 0;
        *(u8 *)(state + 3) = lbl_803DBF28[0];
        fn_8004C1E4(lbl_803DBF28[0], lbl_803E4B90);
    } else {
        *(u8 *)&((Dim2lavacontrolState *)state)->unk0 = 3;
        *(u8 *)(state + 3) = lbl_803DBF28[3];
        fn_8004C1E4(lbl_803DBF28[3], lbl_803E4B90);
    }
    Music_Trigger(0xdd, 1);
    envFxActFn_800887f8(0);
}

extern void getEnvfxActImmediately(int a, int b, int id, int d);
extern void getEnvfxAct(int a, int b, int id, int d);
extern int fn_802966D4(void *obj, f32 *out);
extern void SCGameBitLatch_Update(void *p, int mask, int a, int b, int e1, int e2);
extern void SCGameBitLatch_UpdateInverted(void *p, int mask, int a, int b, int e1, int e2);

void dim2lavacontrol_update(int obj)
{
    int diff;
    f32 local[3];
    if (((GameObject *)obj)->unkF4 != 0) {
        if (((GameObject *)obj)->unkF4 == 2) {
            getEnvfxActImmediately(0, 0, 0x163, 0);
            getEnvfxActImmediately(0, 0, 0x166, 0);
            getEnvfxActImmediately(0, 0, 0x165, 0);
            getEnvfxActImmediately(0, 0, 0x164, 0);
        } else {
            getEnvfxAct(0, 0, 0x163, 0);
            getEnvfxAct(0, 0, 0x166, 0);
            getEnvfxAct(0, 0, 0x165, 0);
            getEnvfxAct(0, 0, 0x164, 0);
        }
        ((GameObject *)obj)->unkF4 = 0;
    }
    obj = *(int *)&((GameObject *)obj)->extra;
    if (*(s8 *)(obj + 4) == 0) {
        if (GameBit_Get(0xacd) != 0) {
            GameBit_Set(0xcc3, 1);
            *(u8 *)(obj + 4) = 1;
        }
    }
    diff = *(u8 *)(obj + 3) - lbl_803DBF28[((Dim2lavacontrolState *)obj)->unk0];
    if (diff != 0) {
        if (diff > 0) {
            *(u8 *)(obj + 3) = *(u8 *)(obj + 3) - 1;
        } else {
            *(u8 *)(obj + 3) = *(u8 *)(obj + 3) + 1;
        }
        fn_8004C1E4(*(u8 *)(obj + 3), lbl_803E4B90);
    }
    if (fn_802966D4(Obj_GetPlayerObject(), local) != 0) {
        if ((*(int *)&((GameObject *)obj)->anim.rootMotionScale & 2) && *(int *)&((GameObject *)obj)->anim.localPosX != 0xe0) {
            Music_Trigger(*(int *)&((GameObject *)obj)->anim.localPosX, 0);
            *(int *)&((GameObject *)obj)->anim.localPosX = 0xe0;
            Music_Trigger(0xe0, 1);
        }
    } else {
        if ((*(int *)&((GameObject *)obj)->anim.rootMotionScale & 2) && *(int *)&((GameObject *)obj)->anim.localPosX != 0xd7) {
            Music_Trigger(*(int *)&((GameObject *)obj)->anim.localPosX, 0);
            *(int *)&((GameObject *)obj)->anim.localPosX = 0xd7;
            Music_Trigger(0xd7, 1);
        }
    }
    SCGameBitLatch_Update((char *)obj + 8, 1, -1, -1, 0xd99, 0xde);
    SCGameBitLatch_Update((char *)obj + 8, 2, -1, -1, 0xda5, *(int *)&((GameObject *)obj)->anim.localPosX);
    SCGameBitLatch_Update((char *)obj + 8, 8, -1, -1, 0xf04, 0x96);
    SCGameBitLatch_UpdateInverted((char *)obj + 8, 0x10, -1, -1, 0xf04, 0x2c);
    SCGameBitLatch_Update((char *)obj + 8, 4, -1, -1, 0xcbb, 0xc4);
}
