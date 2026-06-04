#include "ghidra_import.h"
#include "main/dll/seqObj11E.h"

#define SFXen_cavedirt22 35
#define SFXsp_literun114 0xe7
#define SFXsp_literun115 232
#define SFXsp_literun116 0xe9
#define SFXar_laser216 0x18d
#define SFXfox_cough1 584
#define SFXspirit_voice2 0x31b

extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068f4();
extern int FUN_80006a10();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHits_RecordObjectHit();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int FUN_80039520();
extern undefined4 FUN_800810f0();
extern undefined4 FUN_80081108();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern byte FUN_8019e768();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern int FUN_80294d20();
extern undefined4 FUN_80294d28();

extern undefined4 DAT_8031fee0;
extern undefined4 DAT_8031fee4;
extern undefined4 DAT_8031fee8;
extern undefined4 DAT_8031fee9;
extern undefined4 DAT_8031feea;
extern undefined4 DAT_8031feeb;
extern undefined4 DAT_803dc908;
extern undefined4 DAT_803dc910;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e34b0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DC918;
extern f32 lbl_803DC91C;
extern f32 lbl_803E3470;
extern f32 lbl_803E3474;
extern f32 lbl_803E3480;
extern f32 lbl_803E3490;
extern f32 lbl_803E3494;
extern f32 lbl_803E3498;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;
extern f32 lbl_803E34A4;
extern f32 lbl_803E34A8;
extern f32 lbl_803E34AC;
extern f32 lbl_803E34B8;
extern f32 lbl_803E34BC;
extern f32 lbl_803E34C0;
extern f32 lbl_803E34C4;
extern f32 lbl_803E34C8;
extern f32 lbl_803E34CC;
extern f32 lbl_803E34D0;
extern f32 lbl_803E34D4;
extern f32 lbl_803E34D8;
extern f32 lbl_803E34DC;
extern f32 lbl_803E34E0;
extern f32 lbl_803E34E4;
extern undefined2 uRam803dc90a;
extern undefined4 uRam803dc90c;

/*
 * --INFO--
 *
 * Function: FUN_80152040
 * EN v1.0 Address: 0x80152040
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801520FC
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152040(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_80017a98();
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x1be);
  if (iVar2 == 0) {
    FUN_8011e800(2);
    *(undefined2 *)(param_2 + 0x338) = DAT_803dc908;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  else if ((iVar1 == 0) || (iVar2 = FUN_80294d20(iVar1), iVar2 < 0x19)) {
    FUN_8011e800(2);
    *(undefined2 *)(param_2 + 0x338) = uRam803dc90a;
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
  }
  else {
    FUN_80294d28(iVar1,-0x19);
    GameBit_Set((int)*(short *)(iVar3 + 0x1c),1);
    *(undefined2 *)(param_2 + 0x338) = uRam803dc90c;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8011e800(2);
    (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80152194
 * EN v1.0 Address: 0x80152194
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x8015224C
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152194(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  iVar3 = FUN_80017a98();
  iVar4 = *(int *)(param_1 + 0x4c);
  fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10);
  if (fVar1 < lbl_803E3470) {
    fVar1 = -fVar1;
  }
  if (fVar1 <= lbl_803E3474) {
    dVar5 = (double)FUN_80293f90();
    dVar8 = -(double)(float)((double)lbl_803E3474 * dVar5 - (double)*(float *)(iVar4 + 8));
    dVar5 = (double)FUN_80294964();
    dVar7 = -(double)(float)((double)lbl_803E3474 * dVar5 - (double)*(float *)(iVar4 + 0x10));
    fVar1 = (float)((double)*(float *)(iVar3 + 0x18) - dVar8);
    fVar2 = (float)((double)*(float *)(iVar3 + 0x20) - dVar7);
    dVar5 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar5 < (double)*(float *)(param_2 + 0x2ac)) {
      dVar5 = (double)FUN_80293f90();
      dVar6 = (double)FUN_80294964();
      fVar1 = -(float)(dVar5 * (double)(float)(dVar8 - dVar5) +
                      (double)(float)(dVar6 * (double)(float)(dVar7 - dVar6)));
      dVar7 = (double)(fVar1 + (float)(dVar5 * (double)*(float *)(iVar3 + 0x8c) +
                                      (double)(float)(dVar6 * (double)*(float *)(iVar3 + 0x94))));
      if ((lbl_803E3470 <
           fVar1 + (float)(dVar5 * (double)*(float *)(iVar3 + 0x18) +
                          (double)(float)(dVar6 * (double)*(float *)(iVar3 + 0x20)))) &&
         ((double)lbl_803E3480 <= dVar7)) {
        *(float *)(iVar3 + 0x18) = -(float)(dVar5 * dVar7 - (double)*(float *)(iVar3 + 0x18));
        *(float *)(iVar3 + 0x20) = -(float)(dVar6 * dVar7 - (double)*(float *)(iVar3 + 0x20));
        FUN_800068f4((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                     (double)*(float *)(iVar3 + 0x20),(float *)(iVar3 + 0xc),(float *)(iVar3 + 0x10)
                     ,(float *)(iVar3 + 0x14),*(int *)(iVar3 + 0x30));
      }
    }
  }
  return;
}

#pragma scheduling off
#pragma peephole off
void fn_80152440(int obj, int p, int p3, int msg)
{
  extern void Sfx_PlayFromObject(int obj, int sfx);
  extern void fn_8014D08C(int obj, int p, int type, f32 t, int a, int b);
  extern f32 lbl_803E2810;
  extern f32 lbl_803E2814;
  int sub;
  f32 fz;

  sub = *(int *)(obj + 0x4c);
  if (msg == 16 || msg == 17) {
    return;
  }
  Sfx_PlayFromObject(obj, SFXen_cavedirt22);
  Sfx_PlayFromObject(obj, SFXspirit_voice2);
  *(u32 *)(p + 0x2e8) |= 0x8;
  *(f32 *)(p + 0x32c) = (f32)(u32)(u16)*(s16 *)(sub + 0x2c);
  fn_8014D08C(obj, p, 1, lbl_803E2810, 0, 0);
  *(u32 *)(p + 0x2e4) &= 0xffffffdf;
  fz = lbl_803E2814;
  *(f32 *)(obj + 0x2c) = lbl_803E2814;
  *(f32 *)(obj + 0x28) = fz;
  *(f32 *)(obj + 0x24) = fz;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80152514  size: 1408b  main update: child-zap timer, curve
 * follow, heading steps, landing sfx, light-pulse fx, child spark spawn. */

extern int fn_80152370(int obj, int p2);
extern void Obj_FreeObject(int *obj);
extern void Sfx_StopObjectChannel(int *obj, int channel);
extern int curveFn_80010320(u8 *curve, f32 t);
extern int *gRomCurveInterface;
extern u8 lbl_803DBCA8;
extern int Sfx_IsPlayingFromObject(int *obj, int sfxId);
extern int fn_801A0174(int *obj);
extern int *Obj_GetPlayerObject(void);
extern int *objFindTexture(int *obj, int a, int b);
extern void fn_8014CF7C(void *p1, void *p2, f32 f1, f32 f2, int p5, int p6);
extern void fn_8014D08C(void *p1, void *p2, int p3, f32 f1, int p5, int p6);
extern void Sfx_PlayFromObject(int *obj, int sfxId);
extern void objfx_spawnLightPulse(int *obj, f32 scale, int a, int b, int c, f32 v, void *params);
extern void objfx_spawnMaskedHitEffect(int *obj, f32 scale, int a, int b, int c, void *params);
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803DBCB0;
extern f32 lbl_803DBCB4;
extern f32 lbl_803E2814;
extern f32 lbl_803E2820;
extern f32 lbl_803E2824;
extern f32 lbl_803E2828;
extern f32 lbl_803E282C;
extern f32 lbl_803E2830;
extern f32 lbl_803E2834;
extern f32 lbl_803E2838;
extern f32 lbl_803E283C;
extern f32 lbl_803E2840;
extern f32 lbl_803E2844;
extern f32 lbl_803E2848;
extern f32 lbl_803E284C;

typedef struct {
    u8 pad[8];
    f32 a;
    f32 b;
    f32 c;
    f32 d;
} SeqFxParams;

#pragma scheduling off
#pragma peephole off
void fn_80152514(int *obj, u8 *state)
{
    int *def;
    u8 *path;
    int attached;
    s16 spd;
    SeqFxParams fx;

    def = *(int **)((char *)obj + 0x4c);
    path = *(u8 **)state;
    if (*(f32 *)(state + 0x32c) > lbl_803E2814) {
        int *child = *(int **)((char *)obj + 0xc8);
        if (child != 0) {
            Obj_FreeObject(child);
            ObjLink_DetachChild(obj, *(int **)((char *)obj + 0xc8));
            *(int *)((char *)obj + 0xc8) = 0;
        }
        *(f32 *)(state + 0x32c) = *(f32 *)(state + 0x32c) - timeDelta;
        if (*(f32 *)(state + 0x32c) <= lbl_803E2814) {
            *(f32 *)(state + 0x32c) = lbl_803E2814;
            *(u32 *)(state + 0x2e4) |= 0x20;
            Sfx_StopObjectChannel(obj, 4);
            fn_8014D08C(obj, state, 0, lbl_803E2820, 0, 0);
        } else if (!(*(u32 *)(state + 0x2e4) & 0x20)) {
            return;
        }
    }
    if (*(u32 *)(state + 0x2dc) & 0x2000) {
        int step;

        if (curveFn_80010320(path, *(f32 *)(state + 0x2fc)) != 0 || *(int *)(path + 0x10) != 0) {
            if ((*(u8 (**)(u8 *))(*(int *)gRomCurveInterface + 0x90))(path) != 0) {
                if ((*(u8 (**)(u8 *, int *, f32, u8 *, int))(*(int *)gRomCurveInterface + 0x8c))(
                        *(u8 **)state, obj, lbl_803E2824, &lbl_803DBCA8, -1) != 0) {
                    *(u32 *)(state + 0x2dc) &= ~0x2000;
                }
            }
        }
        *(f32 *)((char *)obj + 0x24) =
            (*(f32 *)(path + 0x68) - *(f32 *)((char *)obj + 0xc)) / timeDelta;
        *(f32 *)((char *)obj + 0x2c) =
            (*(f32 *)(path + 0x70) - *(f32 *)((char *)obj + 0x14)) / timeDelta;
        step = (s8)*((u8 *)def + 0x2a);
        if (step == 0) {
            fn_8014CF7C(obj, state, *(f32 *)(path + 0x68), *(f32 *)(path + 0x70), 0xf, 0);
        } else if (*(u32 *)(state + 0x2dc) & 0x2000) {
            spd = step << 8;
            if ((int)(lbl_803E2828 * *(f32 *)(path + 0x78)) >= 0) {
                step = spd;
            } else {
                step = -spd;
            }
            *(s16 *)obj = *(s16 *)obj - step;
            fn_8014CF7C(obj, state, *(f32 *)(path + 0x68), *(f32 *)(path + 0x70), 0xf, 0);
            if ((int)(lbl_803E2828 * *(f32 *)(path + 0x78)) >= 0) {
                step = spd;
            } else {
                step = -spd;
            }
            *(s16 *)obj += step;
        } else {
            step = ((int)(lbl_803E2828 * *(f32 *)(path + 0x78)) >= 0) ? step : -step;
            *(s16 *)obj += step;
        }
        if (*(f32 *)((char *)obj + 0x10) - *(f32 *)(path + 0x6c) < lbl_803E282C) {
            if (Sfx_IsPlayingFromObject(obj, SFXar_laser216) == 0) {
                Sfx_PlayFromObject(obj, SFXar_laser216);
            }
            state[0x33a] = 1;
        } else {
            state[0x33a] = 0;
        }
    } else {
        if (*(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)def + 0xc) < lbl_803E2830) {
            if (Sfx_IsPlayingFromObject(obj, SFXar_laser216) == 0) {
                Sfx_PlayFromObject(obj, SFXar_laser216);
            }
            state[0x33a] = 1;
        } else {
            state[0x33a] = 0;
        }
        *(s16 *)obj += *(s8 *)((char *)def + 0x2a);
    }
    if (state[0x33a] != 0) {
        *(f32 *)((char *)obj + 0x28) += lbl_803DBCB0 * timeDelta;
    }
    if (*(u16 *)((char *)obj + 0xb0) & 0x800) {
        f32 z = lbl_803E2814;
        fx.b = z;
        fx.c = z;
        fx.d = z;
        fx.a = lbl_803E2820;
        objfx_spawnLightPulse(obj, lbl_803E2834, 2, 0, 6, lbl_803E2838, &fx);
        fx.c = lbl_803E283C;
        objfx_spawnMaskedHitEffect(obj, lbl_803E2840, 1, 6, 0x20, &fx);
        fx.b = lbl_803E2814;
        z = lbl_803E2844;
        fx.c = z;
        fx.d = z;
    }
    if (*(f32 *)((char *)obj + 0x28) < lbl_803E2848) {
        *(f32 *)((char *)obj + 0x28) = lbl_803E2848;
    } else if (*(f32 *)((char *)obj + 0x28) > lbl_803E2834) {
        *(f32 *)((char *)obj + 0x28) = lbl_803E2834;
    }
    if (lbl_803E2814 == *(f32 *)(state + 0x32c)) {
        int *child2;

        if (*(s8 *)((char *)def + 0x2e) != -1 &&
            (child2 = *(int **)((char *)obj + 0xc8)) != 0 && fn_801A0174(child2) != 0) {
            ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x16, 2, 0);
            fn_80152370((int)obj, 0x3b2);
            Sfx_PlayFromObject(obj, SFXsp_literun116);
            *(f32 *)(state + 0x32c) = lbl_803DBCB4;
        }
        if ((int)randomGetRange(0, (int)(lbl_803E284C * oneOverTimeDelta)) == 0) {
            Sfx_PlayFromObject(obj, SFXsp_literun114);
        }
        child2 = *(int **)((char *)obj + 0xc8);
        if (child2 != 0) {
            int *tex = objFindTexture(child2, 0, 0);
            int v;
            if (tex != 0) {
                v = *(s16 *)((char *)tex + 8) - 0x3c;
                if (v < 0) {
                    v += 0x2710;
                }
                *(s16 *)((char *)tex + 8) = v;
            }
        } else {
            int *newObj;
            int flag;

            if (*(s8 *)((char *)def + 0x2a) != 0) {
                attached = 1;
            } else {
                attached = 0;
            }
            newObj = (int *)fn_80152370((int)obj, 0x639);
            flag = 0;
            if (*(s8 *)((char *)def + 0x2a) != 0 && !(*(u32 *)(state + 0x2dc) & 0x2000)) {
                flag = 1;
            }
            *(int *)((char *)newObj + 0xf4) = flag;
            ObjLink_AttachChild(obj, newObj, attached);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80152B90  size: 816b  firefly hover update: circle drift, bob
 * between heights, periodically drop a spawned object, ambient sfx timers. */

extern void fn_80293018(int idx, f32 *outA, f32 *outB);
extern u8 Obj_IsLoadingLocked(void);
extern u8 *Obj_AllocObjectSetup(int size, int type);
extern int *loadObjectAtObject(int *obj, u8 *setup);
extern void fn_8014CD1C(int *obj, u8 *state, int p3, f32 a, f32 b, int p6);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E2868;
extern f32 lbl_803E286C;
extern f32 lbl_803E2878;
extern f32 lbl_803E287C;
extern f32 lbl_803E2880;
extern f32 lbl_803E2884;
extern f32 lbl_803E2888;
extern f32 lbl_803E288C;
extern f32 lbl_803E2890;
extern f32 lbl_803E2894;

#pragma scheduling off
#pragma peephole off
void fn_80152B90(int *obj, u8 *state)
{
    f32 y;
    f32 sinOut;
    f32 cosOut;

    *(u16 *)(state + 0x338) = lbl_803E287C * timeDelta + (f32)(u32)*(u16 *)(state + 0x338);
    fn_80293018(*(u16 *)(state + 0x338), &sinOut, &cosOut);
    sinOut = sinOut * *(f32 *)(state + 0x2a8) + *(f32 *)(state + 0x324);
    cosOut = cosOut * *(f32 *)(state + 0x2a8) + *(f32 *)(state + 0x32c);
    if (state[0x33a] == 0) {
        f32 dx;
        f32 dz;

        y = *(f32 *)((char *)obj + 0x10);
        dx = *(f32 *)(state + 0x324) - *(f32 *)(*(int *)(state + 0x29c) + 0xc);
        dz = *(f32 *)(state + 0x32c) - *(f32 *)(*(int *)(state + 0x29c) + 0x14);
        if (sqrtf(dx * dx + dz * dz) <= lbl_803E2880 * *(f32 *)(state + 0x2a8)) {
            state[0x33a] = 1;
            state[0x33b] = 0;
        }
    } else if (state[0x33a] == 1) {
        y = *(f32 *)((char *)obj + 0x10) - lbl_803E2884 * timeDelta;
        if (y <= *(f32 *)(state + 0x328) - lbl_803E2888) {
            state[0x33a] = 2;
        } else {
            state[0x33b] = (f32)(u32)state[0x33b] + timeDelta;
            if (state[0x33b] > 0x64) {
                state[0x33b] = 0;
                if (Obj_IsLoadingLocked() != 0) {
                    u8 *setup;
                    int *spawned;

                    setup = Obj_AllocObjectSetup(0x24, 0x6b5);
                    *(f32 *)(setup + 8) = *(f32 *)((char *)obj + 0xc);
                    *(f32 *)(setup + 0xc) = lbl_803E2878 + *(f32 *)((char *)obj + 0x10);
                    *(f32 *)(setup + 0x10) = *(f32 *)((char *)obj + 0x14);
                    *(u8 *)(setup + 4) = 1;
                    *(u8 *)(setup + 5) = 1;
                    *(u8 *)(setup + 6) = 0xff;
                    *(u8 *)(setup + 7) = 0xff;
                    spawned = loadObjectAtObject(obj, setup);
                    if (spawned != 0) {
                        *(int **)((char *)spawned + 0xc4) = obj;
                        Sfx_PlayFromObject(obj, 0x249);
                    }
                }
            }
        }
    } else {
        y = lbl_803E288C * timeDelta + *(f32 *)((char *)obj + 0x10);
        if (y >= *(f32 *)(state + 0x328)) {
            state[0x33a] = 0;
        }
    }
    *(f32 *)((char *)obj + 0x24) = oneOverTimeDelta * (sinOut - *(f32 *)((char *)obj + 0xc));
    *(f32 *)((char *)obj + 0x28) = oneOverTimeDelta * (y - *(f32 *)((char *)obj + 0x10));
    *(f32 *)((char *)obj + 0x2c) = oneOverTimeDelta * (cosOut - *(f32 *)((char *)obj + 0x14));
    fn_8014CD1C(obj, state, 0xf, lbl_803E2890, lbl_803E2894, 0);
    *(f32 *)(state + 0x334) = *(f32 *)(state + 0x334) - timeDelta;
    if (*(f32 *)(state + 0x334) <= lbl_803E2868) {
        *(f32 *)(state + 0x334) = (f32)(int)randomGetRange(0x3c, 0x78);
        Sfx_PlayFromObject(obj, 0x31);
    }
    *(f32 *)(state + 0x330) = *(f32 *)(state + 0x330) - timeDelta;
    if (*(f32 *)(state + 0x330) <= lbl_803E2868) {
        *(f32 *)(state + 0x330) = lbl_803E286C;
        Sfx_PlayFromObject(obj, 0x24a);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80152370(int obj, int p2)
{
  extern void *Obj_GetPlayerObject(void);
  extern u8 Obj_IsLoadingLocked(void);
  extern u8 *Obj_AllocObjectSetup(int size, int type);
  extern u8 *Obj_SetupObject(u8 *obj, int a, int b, int c, int d);
  int sub;
  u8 *no;

  sub = *(int *)(obj + 0x4c);
  Obj_GetPlayerObject();
  if (Obj_IsLoadingLocked() == 0) return 0;
  no = Obj_AllocObjectSetup(36, p2);
  *(s16 *)(no + 0) = (s16)p2;
  *(u8 *)(no + 4) = *(u8 *)(sub + 4);
  *(u8 *)(no + 6) = *(u8 *)(sub + 6);
  *(u8 *)(no + 5) = 1;
  *(u8 *)(no + 7) = *(u8 *)(sub + 7);
  *(f32 *)(no + 8) = *(f32 *)(obj + 0xc);
  *(f32 *)(no + 0xc) = *(f32 *)(obj + 0x10);
  *(f32 *)(no + 0x10) = *(f32 *)(obj + 0x14);
  *(u8 *)(no + 0x19) = 0;
  *(s16 *)(no + 0x20) = 149;
  return (int)Obj_SetupObject(no, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801523bc
 * EN v1.0 Address: 0x801523BC
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80152498
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801523bc(uint param_1,int param_2)
{
  FUN_80006824(param_1,SFXen_cavedirt22);
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801523f8
 * EN v1.0 Address: 0x801523F8
 * EN v1.0 Size: 1452b
 * EN v1.1 Address: 0x801524D4
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801523f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  ushort uVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if ((*(char *)(param_10 + 0x33a) == '\x02') &&
     (uVar2 = GameBit_Get((int)*(short *)(iVar3 + 0x1c)), uVar2 == 0)) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
      FUN_8011e868(7);
    }
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_80152040(param_9,param_10);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) &&
     (*(int *)(&DAT_8031fee4 + (uint)*(byte *)(param_10 + 0x33a) * 0xc) != 0)) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    uVar2 = (uint)*(byte *)(param_10 + 0x33a);
    if (uVar2 == 0) {
      if ((*(uint *)(param_10 + 0x2dc) & 0x20000000) != 0) {
        uVar2 = GameBit_Get((int)*(short *)(iVar3 + 0x1c));
        if (uVar2 == 0) {
          *(undefined *)(param_10 + 0x33a) =
               (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
        }
        else {
          *(undefined *)(param_10 + 0x33a) =
               (&DAT_8031feea)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
        }
      }
    }
    else if (uVar2 == 2) {
      uVar2 = GameBit_Get((int)*(short *)(iVar3 + 0x1c));
      if ((uVar2 != 0) || ((*(uint *)(param_10 + 0x2dc) & 0x20000000) == 0)) {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
    }
    else if (uVar2 == 3) {
      uVar2 = GameBit_Get((int)*(short *)(iVar3 + 0x1c));
      if (uVar2 == 0) {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
      else {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031feea)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
    }
    else {
      *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[uVar2 * 0xc];
    }
    uVar1 = (ushort)(byte)(&DAT_8031fee8)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
    if (*(ushort *)(param_9 + 0xa0) != uVar1) {
      if ((uVar1 != 0) && (uVar1 != 4)) {
        FUN_80006824(param_9,0x4a8);
      }
      iVar3 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      FUN_8014d4c8((double)*(float *)(&DAT_8031fee0 + iVar3),param_2,param_3,param_4,param_5,param_6
                   ,param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_8031fee8)[iVar3],0,0xf,in_r8,
                   in_r9,in_r10);
    }
  }
  if ((&DAT_8031feeb)[(uint)*(byte *)(param_10 + 0x33a) * 0xc] != '\0') {
    FUN_80152194(param_9,param_10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801529a4
 * EN v1.0 Address: 0x801529A4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x8015278C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801529a4(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  *(float *)(param_2 + 0x2ac) = lbl_803E3490;
  *(float *)(param_2 + 0x2a8) = lbl_803E3494;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc80;
  *(float *)(param_2 + 0x308) = lbl_803E3498;
  *(float *)(param_2 + 0x300) = lbl_803E349C;
  *(float *)(param_2 + 0x304) = lbl_803E34A0;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E34A4;
  *(float *)(param_2 + 0x314) = lbl_803E34A4;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  if (*(char *)(iVar2 + 0x2e) != -1) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80152a30
 * EN v1.0 Address: 0x80152A30
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8015281C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80152a30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined2 param_10
            )
{
  uint uVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  FUN_80017a98();
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) == 0) {
    uVar2 = 0;
  }
  else {
    puVar3 = FUN_80017aa4(0x24,param_10);
    *puVar3 = param_10;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar4 + 7);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)((int)puVar3 + 0x19) = 0;
    puVar3[0x10] = 0x95;
    uVar2 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
  }
  return uVar2;
}

#pragma scheduling off
#pragma peephole off
void fn_80152A94(int obj, int p)
{
  extern void Sfx_AddLoopedObjectSound(int obj, int sfx);
  extern f32 lbl_803E2814;
  extern f32 lbl_803E2820;
  extern f32 lbl_803E2850;
  extern f32 lbl_803E2854;
  extern f32 lbl_803E2858;
  extern f32 lbl_803E285C;
  extern f32 lbl_803E2860;
  f32 fz;

  *(f32 *)(p + 0x2ac) = lbl_803E2850;
  *(u32 *)(p + 0x2e4) = 41;
  *(u32 *)(p + 0x2e4) |= 0x7000;
  *(u32 *)(p + 0x2e4) |= 0x20000;
  *(f32 *)(p + 0x308) = lbl_803E2854;
  *(f32 *)(p + 0x300) = lbl_803E2858;
  *(f32 *)(p + 0x304) = lbl_803E285C;
  *(u8 *)(p + 0x320) = 0;
  fz = lbl_803E2820;
  *(f32 *)(p + 0x314) = fz;
  *(u8 *)(p + 0x321) = 0;
  *(f32 *)(p + 0x318) = fz;
  *(u8 *)(p + 0x322) = 0;
  *(f32 *)(p + 0x31c) = fz;
  *(f32 *)(p + 0x32c) = lbl_803E2814;
  *(f32 *)(obj + 0xa8) = lbl_803E2860;
  Sfx_AddLoopedObjectSound(obj, SFXsp_literun115);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80152B2C(int obj, int p, int param3, int msg)
{
  extern void Sfx_PlayFromObject(int obj, int sfx);

  if (msg == 16 || msg == 17) {
    return;
  }
  Sfx_PlayFromObject(obj, SFXfox_cough1);
  *(s16 *)(p + 0x2b0) = 0;
  *(u32 *)(p + 0x2e4) |= 0x20;
  *(u32 *)(p + 0x2e8) |= 0x8;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80152b8c
 * EN v1.0 Address: 0x80152B8C
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801528EC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152b8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x4c);
  if ((param_12 != 0x10) && (param_12 != 0x11)) {
    FUN_80006824(param_9,SFXen_cavedirt22);
    FUN_80006824(param_9,SFXspirit_voice2);
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
    *(float *)(param_10 + 0x32c) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x2c)) - DOUBLE_803e34b0);
    FUN_8014d4c8((double)lbl_803E34A8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,param_14,param_15,param_16);
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xffffffdf;
    fVar1 = lbl_803E34AC;
    *(float *)(param_9 + 0x2c) = lbl_803E34AC;
    *(float *)(param_9 + 0x28) = fVar1;
    *(float *)(param_9 + 0x24) = fVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80152cf0
 * EN v1.0 Address: 0x80152CF0
 * EN v1.0 Size: 2108b
 * EN v1.1 Address: 0x801529C0
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152cf0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short *psVar1;
  int iVar2;
  char cVar7;
  short sVar5;
  short sVar6;
  bool bVar8;
  byte bVar9;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar10;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar11;
  int iVar12;
  double dVar13;
  undefined8 uVar14;
  undefined auStack_48 [8];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  uVar14 = FUN_80286840();
  psVar1 = (short *)((ulonglong)uVar14 >> 0x20);
  puVar10 = (undefined4 *)uVar14;
  iVar12 = *(int *)(psVar1 + 0x26);
  pfVar11 = (float *)*puVar10;
  if ((double)lbl_803E34AC < (double)(float)puVar10[0xcb]) {
    if (*(int *)(psVar1 + 100) != 0) {
      FUN_80017ac8((double)(float)puVar10[0xcb],param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,*(int *)(psVar1 + 100));
      ObjLink_DetachChild((int)psVar1,*(int *)(psVar1 + 100));
      psVar1[100] = 0;
      psVar1[0x65] = 0;
    }
    puVar10[0xcb] = (float)puVar10[0xcb] - lbl_803DC074;
    if (lbl_803E34AC < (float)puVar10[0xcb]) {
      if ((puVar10[0xb9] & 0x20) == 0) goto LAB_80152f28;
    }
    else {
      puVar10[0xcb] = lbl_803E34AC;
      puVar10[0xb9] = puVar10[0xb9] | 0x20;
      FUN_8000680c((int)psVar1,4);
      FUN_8014d4c8((double)lbl_803E34B8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)psVar1,(int)puVar10,0,0,0,in_r8,in_r9,in_r10);
    }
  }
  if ((puVar10[0xb7] & 0x2000) == 0) {
    if (lbl_803E34C8 <= *(float *)(psVar1 + 8) - *(float *)(iVar12 + 0xc)) {
      *(undefined *)((int)puVar10 + 0x33a) = 0;
    }
    else {
      bVar8 = FUN_800067f8((int)psVar1,0x18d);
      if (!bVar8) {
        FUN_80006824((uint)psVar1,SFXar_laser216);
      }
      *(undefined *)((int)puVar10 + 0x33a) = 1;
    }
    *psVar1 = *psVar1 + (short)*(char *)(iVar12 + 0x2a);
  }
  else {
    iVar2 = FUN_80006a10((double)(float)puVar10[0xbf],pfVar11);
    if ((((iVar2 != 0) || (pfVar11[4] != 0.0)) &&
        (cVar7 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar11), cVar7 != '\0')) &&
       (cVar7 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)lbl_803E34BC,*puVar10,psVar1,&DAT_803dc910,0xffffffff),
       cVar7 != '\0')) {
      puVar10[0xb7] = puVar10[0xb7] & 0xffffdfff;
    }
    *(float *)(psVar1 + 0x12) = (pfVar11[0x1a] - *(float *)(psVar1 + 6)) / lbl_803DC074;
    *(float *)(psVar1 + 0x16) = (pfVar11[0x1c] - *(float *)(psVar1 + 10)) / lbl_803DC074;
    iVar2 = (int)*(char *)(iVar12 + 0x2a);
    if (iVar2 == 0) {
      param_2 = (double)pfVar11[0x1c];
      FUN_8014d3d0(psVar1,puVar10,0xf,0);
    }
    else if ((puVar10[0xb7] & 0x2000) == 0) {
      local_28 = (longlong)(int)(lbl_803E34C0 * pfVar11[0x1e]);
      if ((int)(lbl_803E34C0 * pfVar11[0x1e]) < 0) {
        iVar2 = -iVar2;
      }
      *psVar1 = *psVar1 + (short)iVar2;
    }
    else {
      sVar6 = (short)(iVar2 << 8);
      local_30 = (longlong)(int)(lbl_803E34C0 * pfVar11[0x1e]);
      sVar5 = sVar6;
      if ((int)(lbl_803E34C0 * pfVar11[0x1e]) < 0) {
        sVar5 = -sVar6;
      }
      *psVar1 = *psVar1 - sVar5;
      param_2 = (double)pfVar11[0x1c];
      FUN_8014d3d0(psVar1,puVar10,0xf,0);
      local_28 = (longlong)(int)(lbl_803E34C0 * pfVar11[0x1e]);
      if ((int)(lbl_803E34C0 * pfVar11[0x1e]) < 0) {
        sVar6 = -sVar6;
      }
      *psVar1 = *psVar1 + sVar6;
    }
    if (lbl_803E34C4 <= *(float *)(psVar1 + 8) - pfVar11[0x1b]) {
      *(undefined *)((int)puVar10 + 0x33a) = 0;
    }
    else {
      bVar8 = FUN_800067f8((int)psVar1,0x18d);
      if (!bVar8) {
        FUN_80006824((uint)psVar1,SFXar_laser216);
      }
      *(undefined *)((int)puVar10 + 0x33a) = 1;
    }
  }
  if (*(char *)((int)puVar10 + 0x33a) != '\0') {
    param_2 = (double)lbl_803DC918;
    *(float *)(psVar1 + 0x14) =
         (float)(param_2 * (double)lbl_803DC074 + (double)*(float *)(psVar1 + 0x14));
  }
  if ((psVar1[0x58] & 0x800U) != 0) {
    local_3c = lbl_803E34AC;
    local_38 = lbl_803E34AC;
    local_34 = lbl_803E34AC;
    local_40 = lbl_803E34B8;
    param_2 = (double)lbl_803E34D0;
    FUN_80081108((double)lbl_803E34CC,param_2);
    local_38 = lbl_803E34D4;
    FUN_800810f0((double)lbl_803E34D8,psVar1,1,6,0x20,(int)auStack_48);
    local_3c = lbl_803E34AC;
    local_38 = lbl_803E34DC;
    local_34 = lbl_803E34DC;
  }
  if (lbl_803E34E0 <= *(float *)(psVar1 + 0x14)) {
    if (lbl_803E34CC < *(float *)(psVar1 + 0x14)) {
      *(float *)(psVar1 + 0x14) = lbl_803E34CC;
    }
  }
  else {
    *(float *)(psVar1 + 0x14) = lbl_803E34E0;
  }
  dVar13 = (double)lbl_803E34AC;
  if (dVar13 == (double)(float)puVar10[0xcb]) {
    if (((*(char *)(iVar12 + 0x2e) != -1) && (*(int *)(psVar1 + 100) != 0)) &&
       (bVar9 = FUN_8019e768(*(int *)(psVar1 + 100)), bVar9 != 0)) {
      iVar2 = FUN_80017a98();
      ObjHits_RecordObjectHit(iVar2,(int)psVar1,'\x16',2,0);
      FUN_80152a30(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)psVar1,0x3b2)
      ;
      FUN_80006824((uint)psVar1,SFXsp_literun116);
      puVar10[0xcb] = lbl_803DC91C;
    }
    dVar13 = (double)lbl_803E34E4;
    local_28 = (longlong)(int)(dVar13 * (double)lbl_803DC078);
    uVar3 = randomGetRange(0,(int)(dVar13 * (double)lbl_803DC078));
    if (uVar3 == 0) {
      dVar13 = (double)FUN_80006824((uint)psVar1,SFXsp_literun114);
    }
    if (*(int *)(psVar1 + 100) == 0) {
      cVar7 = *(char *)(iVar12 + 0x2a);
      iVar2 = FUN_80152a30(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)psVar1,0x639);
      uVar4 = 0;
      if ((*(char *)(iVar12 + 0x2a) != '\0') && ((puVar10[0xb7] & 0x2000) == 0)) {
        uVar4 = 1;
      }
      *(undefined4 *)(iVar2 + 0xf4) = uVar4;
      ObjLink_AttachChild((int)psVar1,iVar2,(ushort)(cVar7 != '\0'));
    }
    else {
      iVar12 = FUN_80039520(*(int *)(psVar1 + 100),0);
      if (iVar12 != 0) {
        iVar2 = *(short *)(iVar12 + 8) + -0x3c;
        if (iVar2 < 0) {
          iVar2 = *(short *)(iVar12 + 8) + 0x26d4;
        }
        *(short *)(iVar12 + 8) = (short)iVar2;
      }
    }
  }
LAB_80152f28:
  FUN_8028688c();
  return;
}

extern f32 lbl_803E27F8;
extern f32 lbl_803E27FC;
extern f32 lbl_803E2800;
extern f32 lbl_803E2804;
extern f32 lbl_803E2808;
extern f32 lbl_803E280C;

#pragma scheduling off
#pragma peephole off
void fn_801522E0(int* obj, u8* state) {
    int* sub = *(int**)((char*)obj + 0x4c);
    f32 fz;
    *(f32*)((char*)state + 684) = lbl_803E27F8;
    *(f32*)((char*)state + 680) = lbl_803E27FC;
    *(int*)((char*)state + 740) = 1;
    *(int*)((char*)state + 740) |= 0xC80;
    *(f32*)((char*)state + 776) = lbl_803E2800;
    *(f32*)((char*)state + 768) = lbl_803E2804;
    *(f32*)((char*)state + 772) = lbl_803E2808;
    state[800] = 0;
    fz = lbl_803E280C;
    *(f32*)((char*)state + 788) = fz;
    state[801] = 0;
    *(f32*)((char*)state + 792) = fz;
    state[802] = 0;
    *(f32*)((char*)state + 796) = fz;
    if ((s8)*((s8*)sub + 46) != -1) {
        *(int*)((char*)state + 732) |= 1;
    }
    *(u8*)((char*)obj + 175) |= 8;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80152040  size: 672b  state-table driver: walks the 12-byte
 * lbl_8031F290 state rows, advancing on GameBit + sequence flags and kicking
 * the matching anim. */

typedef struct {
    f32 animSpeed; /* 0x0 */
    u32 unk4;      /* 0x4 */
    u8 anim;       /* 0x8 */
    u8 next;       /* 0x9 */
    u8 alt;        /* 0xa */
    u8 flagB;      /* 0xb */
} Seq11ERow;

extern Seq11ERow lbl_8031F290[];
extern void fn_80151C68(int *obj, u8 *state);
extern void fn_80151DB8(int *obj, u8 *state);

#pragma scheduling off
#pragma peephole off
void fn_80152040(int *obj, u8 *state)
{
    int *def = *(int **)((char *)obj + 0x4c);
    u32 flags;

    if (state[0x33a] == 2 && GameBit_Get(*(s16 *)((char *)def + 0x1c)) == 0) {
        *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) & ~8);
        if (*(u8 *)((char *)obj + 0xaf) & 1) {
            fn_80151C68(obj, state);
        }
    } else {
        *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
    }
    flags = *(u32 *)(state + 0x2dc);
    if (flags & 0x80000000) {
        if (lbl_8031F290[state[0x33a]].unk4 != 0) {
            u32 triggered = 0x40000000;
            *(u32 *)(state + 0x2dc) = flags | triggered;
        }
    }
    flags = *(u32 *)(state + 0x2dc);
    if (flags & 0x40000000) {
        int anim;
        u8 *animTbl;

        if (state[0x33a] == 0) {
            if (flags & 0x20000000) {
                if (GameBit_Get(*(s16 *)((char *)def + 0x1c)) != 0) {
                    state[0x33a] = lbl_8031F290[state[0x33a]].alt;
                } else {
                    state[0x33a] = lbl_8031F290[state[0x33a]].next;
                }
            }
        } else if (state[0x33a] == 2) {
            if (GameBit_Get(*(s16 *)((char *)def + 0x1c)) != 0 ||
                !(*(u32 *)(state + 0x2dc) & 0x20000000)) {
                state[0x33a] = lbl_8031F290[state[0x33a]].next;
            }
        } else if (state[0x33a] == 3) {
            if (GameBit_Get(*(s16 *)((char *)def + 0x1c)) != 0) {
                state[0x33a] = lbl_8031F290[state[0x33a]].alt;
            } else {
                state[0x33a] = lbl_8031F290[state[0x33a]].next;
            }
        } else {
            state[0x33a] = lbl_8031F290[state[0x33a]].next;
        }
        anim = *(s16 *)((char *)obj + 0xa0);
        animTbl = (u8 *)lbl_8031F290 + 8;
        if (anim != animTbl[state[0x33a] * 12]) {
            if (animTbl[state[0x33a] * 12] != 0 && animTbl[state[0x33a] * 12] != 4) {
                Sfx_PlayFromObject(obj, 0x4a8);
            }
            fn_8014D08C(obj, state, animTbl[state[0x33a] * 12],
                        *(f32 *)((u8 *)lbl_8031F290 + state[0x33a] * 12), 0, 0xf);
        }
    }
    if (lbl_8031F290[state[0x33a]].flagB != 0) {
        fn_80151DB8(obj, state);
    }
}
#pragma peephole reset
#pragma scheduling reset


