#include "ghidra_import.h"
#include "main/dll/grenade.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_80006ba8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern int FUN_80017730();
extern undefined4 FUN_80017a6c();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int randomGetRange(int min,int max);
extern undefined4 ObjHits_SyncObjectPosition();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_80039580();
extern int Sfx_IsPlayingFromObjectChannel(int obj,int channel);
extern undefined4 objAudioFn_800393f8(int obj,void *audio,int soundId,int volume,int param5,int param6);
extern int FUN_800da5f0();
extern undefined4 FUN_800da700();
extern uint FUN_800db47c();
extern undefined4 FUN_8011e824();
extern int FUN_8012efc4();
extern undefined4 FUN_80139910();
extern int FUN_80139a48();
extern undefined4 FUN_80139a4c();
extern int trickyFn_8013b368();
extern undefined4 objAnimFn_8013a3f0(int param_1, int param_2, f32 param_3, int param_4);
extern void trickyFn_8013d8f0(u8 *arg1, u8 *arg2);
extern undefined4 FUN_80144e40();
extern undefined4 FUN_80145120();
extern undefined4 FUN_80146fa0();
extern undefined4 FUN_801778d0();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_802c295c;
extern undefined4 DAT_802c2960;
extern undefined4 DAT_802c2964;
extern undefined4 DAT_802c2968;
extern undefined4 DAT_802c296c;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e305c;
extern undefined4 DAT_803e3060;
extern f64 DOUBLE_803e30f0;
extern f64 DOUBLE_803e31b8;
extern f32 lbl_803DC074;
extern f32 timeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23EC;
extern f32 lbl_803E2408;
extern f32 lbl_803E2438;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f64 lbl_803E2460;
extern f32 lbl_803E2478;
extern f32 lbl_803E2518;
extern f32 lbl_803E251C;
extern f32 lbl_803E2524;
extern f32 lbl_803E306C;
extern f32 lbl_803E3074;
extern f32 lbl_803E307C;
extern f32 lbl_803E3080;
extern f32 lbl_803E3088;
extern f32 lbl_803E3098;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30B4;
extern f32 lbl_803E30C8;
extern f32 lbl_803E30CC;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E3108;
extern f32 lbl_803E3114;
extern f32 lbl_803E3118;
extern f32 lbl_803E312C;
extern f32 lbl_803E313C;
extern f32 lbl_803E3158;
extern f32 lbl_803E3188;
extern f32 lbl_803E31A0;
extern f32 lbl_803E31A4;
extern f32 lbl_803E31A8;
extern f32 lbl_803E31AC;
extern f32 lbl_803E31B0;
extern f32 lbl_803E31B4;
extern f32 lbl_803E31C0;
extern void* PTR_FUN_8031dfa4;

/*
 * --INFO--
 *
 * Function: trickyDigTunnel
 * EN v1.0 Address: 0x80141880
 * EN v1.0 Size: 1900b
 * EN v1.1 Address: 0x80141C08
 * EN v1.1 Size: 1900b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void trickyDigTunnel(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     ushort *param_9,undefined4 *param_10,int param_11,undefined4 param_12,
                     byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float fVar2;
  ushort uVar3;
  bool bVar8;
  char cVar9;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar10;
  int iVar11;
  double dVar12;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  local_28[0] = DAT_803e3060;
  switch(*(undefined *)((int)param_10 + 10)) {
  case 0:
    param_11 = 2;
    iVar6 = FUN_800da5f0((float *)param_10[10],0xffffffff,2);
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar6 + 0x1c));
    param_10[0x1c2] = uVar5;
    param_10[0x1c0] = iVar6;
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar6 + 0x20));
    param_10[0x1c1] = uVar5;
    if (*(char *)(param_10[0x1c1] + 3) != '\0') {
      param_10[0x1c1] = param_10[0x1c1] ^ param_10[0x1c2];
      param_10[0x1c2] = param_10[0x1c2] ^ param_10[0x1c1];
      param_10[0x1c1] = param_10[0x1c1] ^ param_10[0x1c2];
    }
    if (param_10[10] != param_10[0x1c2] + 8) {
      param_10[10] = param_10[0x1c2] + 8;
      param_10[0x15] = param_10[0x15] & 0xfffffbff;
      *(undefined2 *)((int)param_10 + 0xd2) = 0;
    }
    *(undefined *)((int)param_10 + 10) = 1;
  case 1:
    FUN_80146fa0();
    trickyFn_8013b368((double)lbl_803E3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar4 = FUN_800db47c((float *)(param_9 + 0xc),(undefined *)0x0);
    if (*(byte *)(param_10[0x1c2] + 3) == uVar4) {
      *(undefined *)((int)param_10 + 9) = 1;
      *(undefined *)((int)param_10 + 10) = 2;
    }
    break;
  case 2:
    FUN_80146fa0();
    trickyFn_8013d8f0((u8 *)param_9, (u8 *)param_10);
    iVar6 = FUN_80139a48();
    if (iVar6 == 0) {
      param_10[0x15] = param_10[0x15] | 0x2010;
      *(undefined *)((int)param_10 + 10) = 3;
    }
    else {
      iVar6 = FUN_800db47c((float *)(param_9 + 0xc),(undefined *)0x0);
      if (iVar6 == 0) {
        param_10[0x15] = param_10[0x15] | 0x2010;
      }
    }
    break;
  case 3:
    objAnimFn_8013a3f0((int)param_9,0xe,lbl_803E31A0,0x4000000);
    param_10[0xb] = *(float *)(param_10[0x1c1] + 8) - *(float *)(param_10[0x1c0] + 8);
    param_10[0xc] = *(float *)(param_10[0x1c1] + 0x10) - *(float *)(param_10[0x1c0] + 0x10);
    FUN_800068d0((uint)param_9,0x13d);
    uStack_1c = randomGetRange(0x14,0xb4);
    param_10[0x1c3] = (f32)(s32)uStack_1c;
    *(undefined *)((int)param_10 + 10) = 4;
  case 4:
    FUN_80146fa0();
    param_10[0x1c3] = (float)param_10[0x1c3] - lbl_803DC074;
    if ((float)param_10[0x1c3] <= lbl_803E306C) {
      uStack_1c = randomGetRange(0x14,0xb4);
      param_10[0x1c3] = (f32)(s32)uStack_1c;
      param_10[0x1c3] = (float)param_10[0x1c3] * lbl_803E30B4;
      iVar6 = *(int *)(param_9 + 0x5c);
      if (((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)) &&
          (bVar8 = Sfx_IsPlayingFromObjectChannel((int)param_9,0x10), !bVar8)))) {
        objAudioFn_800393f8((int)param_9,(void *)(iVar6 + 0x3a8),0x360,0x500,0xffffffff,0);
      }
    }
    dVar12 = (double)(**(code **)(**(int **)(param_10[9] + 0x68) + 0x20))(param_10[9],param_9);
    *(float *)(param_9 + 6) =
         (float)((double)(float)param_10[0xb] * dVar12 + (double)*(float *)(param_10[0x1c0] + 8));
    *(float *)(param_9 + 10) =
         (float)((double)(float)param_10[0xc] * dVar12 + (double)*(float *)(param_10[0x1c0] + 0x10))
    ;
    fVar1 = *(float *)(*(int *)(param_9 + 0x5c) + 0x2c);
    fVar2 = *(float *)(*(int *)(param_9 + 0x5c) + 0x30);
    if (lbl_803E307C < fVar1 * fVar1 + fVar2 * fVar2) {
      iVar6 = FUN_80017730();
      FUN_80139910(param_9,(ushort)iVar6);
    }
    cVar9 = (**(code **)(**(int **)(param_10[9] + 0x68) + 0x24))();
    if (cVar9 != '\0') {
      iVar7 = 0;
      iVar6 = 0;
      iVar11 = 4;
      do {
        iVar10 = *(int *)(param_10[0x1c1] + iVar6 + 0x1c);
        if ((-1 < iVar10) && (iVar10 != *(int *)(param_10[0x1c0] + 0x14))) {
          param_10[0x1c0] = param_10[0x1c1];
          uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))
                            (*(undefined4 *)(param_10[0x1c1] + iVar7 * 4 + 0x1c));
          param_10[0x1c1] = uVar5;
          break;
        }
        iVar6 = iVar6 + 4;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      *(char *)*param_10 = *(char *)*param_10 + -4;
      FUN_800068cc();
      *(undefined *)((int)param_10 + 10) = 5;
      uVar4 = randomGetRange(0,1);
      uVar3 = *(ushort *)((int)local_28 + uVar4 * 2);
      iVar6 = *(int *)(param_9 + 0x5c);
      if ((((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)))) &&
         (bVar8 = Sfx_IsPlayingFromObjectChannel((int)param_9,0x10), !bVar8)) {
        objAudioFn_800393f8((int)param_9,(void *)(iVar6 + 0x3a8),uVar3,0x500,0xffffffff,0);
      }
    }
    break;
  case 5:
    FUN_80017710((float *)(param_9 + 0xc),(float *)(param_10[0x1c1] + 8));
    FUN_80146fa0();
    trickyFn_8013d8f0((u8 *)param_9, (u8 *)param_10);
    iVar6 = FUN_80139a48();
    if (iVar6 == 0) {
      iVar7 = 0;
      iVar6 = 0;
      iVar11 = 4;
      do {
        iVar10 = *(int *)(param_10[0x1c1] + iVar6 + 0x1c);
        if ((-1 < iVar10) && (iVar10 != *(int *)(param_10[0x1c0] + 0x14))) {
          param_10[0x1c0] = param_10[0x1c1];
          uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))
                            (*(undefined4 *)(param_10[0x1c1] + iVar7 * 4 + 0x1c));
          param_10[0x1c1] = uVar5;
          break;
        }
        iVar6 = iVar6 + 4;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      *(undefined *)((int)param_10 + 10) = 6;
    }
    break;
  case 6:
    FUN_80146fa0();
    trickyFn_8013d8f0((u8 *)param_9, (u8 *)param_10);
    iVar6 = FUN_80139a48();
    if (iVar6 == 0) {
      if (lbl_803E306C == (float)param_10[0xab]) {
        bVar8 = false;
      }
      else if (lbl_803E30A0 == (float)param_10[0xac]) {
        bVar8 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= lbl_803E30A4) {
        bVar8 = false;
      }
      else {
        bVar8 = true;
      }
      if (bVar8) {
        objAnimFn_8013a3f0((int)param_9,8,lbl_803E30CC,0);
        param_10[0x1e7] = lbl_803E30D0;
        param_10[0x20e] = lbl_803E306C;
        FUN_80146fa0();
      }
      else {
        objAnimFn_8013a3f0((int)param_9,0,lbl_803E30D4,0);
        FUN_80146fa0();
      }
      param_10[0x15] = param_10[0x15] & 0xffffdfef;
      *(undefined *)((int)param_10 + 10) = 7;
    }
    break;
  case 7:
    FUN_80146fa0();
    iVar6 = FUN_800db47c((float *)(param_10[1] + 0x18),(undefined *)0x0);
    iVar7 = FUN_800db47c((float *)(param_9 + 0xc),(undefined *)0x0);
    if (iVar7 == iVar6) {
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar1 = lbl_803E306C;
      param_10[0x1c7] = lbl_803E306C;
      param_10[0x1c8] = fVar1;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: trickyFn_80141fec
 * EN v1.0 Address: 0x80142100
 * EN v1.0 Size: 1948b
 * EN v1.1 Address: 0x80142374
 * EN v1.1 Size: 1336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *Objfsa_FindNearestEnabledCurveType24(void *pos, int a, int b);
extern float getXZDistance(float *a, float *b);
extern void Sfx_AddLoopedObjectSound(u8 *obj, int soundId);
extern void Sfx_RemoveLoopedObjectSound(u8 *obj, int soundId);
extern float sqrtf(float x);
extern u32 lbl_803E23CC;
extern f32 lbl_803E2418;
extern f32 lbl_803E23DC;
extern f32 lbl_803E2488;
extern f32 lbl_803E2510;
extern f32 lbl_803E2514;
extern f32 lbl_803E2424;
extern f32 lbl_803E24F8;

void trickyFn_80141fec(u8 *obj, u8 *state)
{
    u32 sfxTable;
    u8 *ptr;
    u8 *pc;
    int ret;
    f32 spd;
    f32 d;
    f32 z;
    u16 id;

    sfxTable = lbl_803E23CC;
    pc = *(u8 **)(state + 0x24);
    switch (state[0xa]) {
    case 0:
        *(u8 **)(state + 0x70c) = Objfsa_FindNearestEnabledCurveType24(*(u8 **)(state + 0x24) + 0x18, -1, 2);
        if (*(u8 **)(state + 0x70c) != NULL
            && getXZDistance((float *)(*(u8 **)(state + 0x24) + 0x18), (float *)(*(u8 **)(state + 0x70c) + 8)) > lbl_803E2514) {
            *(u8 **)(state + 0x70c) = NULL;
        }
        state[0xa] = 1;
    case 1:
        ret = trickyFn_8013b368((int)obj, lbl_803E2488, (int)state);
        if (ret == 0) {
            if (*(u8 **)(state + 0x70c) != NULL) {
                state[0xa] = 2;
                if (*(u8 **)(state + 0x28) != *(u8 **)(state + 0x70c) + 8) {
                    *(u8 **)(state + 0x28) = *(u8 **)(state + 0x70c) + 8;
                    *(u32 *)(state + 0x54) &= ~0x400;
                    *(u16 *)(state + 0xd2) = 0;
                }
            } else {
                *(u32 *)(state + 0x54) |= 0x10;
                state[0xa] = 3;
                *(f32 *)(state + 0x700) = lbl_803E23DC;
                *(f32 *)(state + 0x710) = (f32)(int)randomGetRange(0x28, 0x50);
                Sfx_AddLoopedObjectSound(obj, 0x13d);
                objAnimFn_8013a3f0((int)obj, 0xe, lbl_803E2510, 0x4000000);
            }
        } else if (ret == 2) {
            state[0x8] = 1;
            state[0xa] = 0;
            z = lbl_803E23DC;
            *(f32 *)(state + 0x71c) = z;
            *(f32 *)(state + 0x720) = z;
            *(u32 *)(state + 0x54) &= ~0x10;
            *(u32 *)(state + 0x54) &= ~0x10000;
            *(u32 *)(state + 0x54) &= ~0x20000;
            *(u32 *)(state + 0x54) &= ~0x40000;
            *(s8 *)(state + 0xd) = -1;
        }
        break;
    case 2:
        if (trickyFn_8013b368((int)obj, lbl_803E2418, (int)state) == 0) {
            *(u32 *)(state + 0x54) |= 0x10;
            state[0xa] = 3;
            *(f32 *)(state + 0x700) = lbl_803E23DC;
            Sfx_AddLoopedObjectSound(obj, 0x13d);
            objAnimFn_8013a3f0((int)obj, 0xe, lbl_803E2510, 0x4000000);
        }
        break;
    case 3:
        *(f32 *)(state + 0x700) += timeDelta;
        *(f32 *)(state + 0x710) -= timeDelta;
        if (*(f32 *)(state + 0x700) >= lbl_803E24F8) {
            state[0xa] = 4;
            *(f32 *)(state + 0x704) = *(f32 *)(obj + 0x18);
            *(f32 *)(state + 0x708) = *(f32 *)(obj + 0x20);
            ptr = *(u8 **)(state + 0x70c);
            if (ptr != NULL) {
                *(f32 *)(state + 0x2c) = *(f32 *)(ptr + 8) - *(f32 *)(*(u8 **)(state + 0x24) + 0x18);
                *(f32 *)(state + 0x30) = *(f32 *)(ptr + 0x10) - *(f32 *)(*(u8 **)(state + 0x24) + 0x20);
                d = sqrtf(*(f32 *)(state + 0x2c) * *(f32 *)(state + 0x2c) + *(f32 *)(state + 0x30) * *(f32 *)(state + 0x30));
                if (lbl_803E23DC != d) {
                    *(f32 *)(state + 0x2c) = *(f32 *)(state + 0x2c) / d;
                    *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) / d;
                }
            }
        }
        break;
    case 4:
        *(f32 *)(state + 0x710) -= timeDelta;
        if (*(f32 *)(state + 0x710) <= lbl_803E23DC) {
            *(f32 *)(state + 0x710) = (f32)(int)randomGetRange(0x28, 0x50);
            *(f32 *)(state + 0x710) *= lbl_803E2424;
            ptr = *(u8 **)(obj + 0xb8);
            if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x360, 0x500, -1, 0);
            }
        }
        spd = ((f32 (**)(u8 *, u8 *))(**(u8 ***)(pc + 0x68)))[8](pc, obj);
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x704) - *(f32 *)(state + 0x2c) * spd;
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x708) - *(f32 *)(state + 0x30) * spd;
        if (((u8 (**)(u8 *))(**(u8 ***)(pc + 0x68)))[9](pc) != 0) {
            Sfx_RemoveLoopedObjectSound(obj, 0x13d);
            **(u8 **)state -= 4;
            state[0x8] = 1;
            state[0xa] = 0;
            z = lbl_803E23DC;
            *(f32 *)(state + 0x71c) = z;
            *(f32 *)(state + 0x720) = z;
            *(u32 *)(state + 0x54) &= ~0x10;
            *(u32 *)(state + 0x54) &= ~0x10000;
            *(u32 *)(state + 0x54) &= ~0x20000;
            *(u32 *)(state + 0x54) &= ~0x40000;
            *(s8 *)(state + 0xd) = -1;
            id = *(u16 *)((char *)&sfxTable + randomGetRange(0, 1) * 2);
            ptr = *(u8 **)(obj + 0xb8);
            if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, id, 0x500, -1, 0);
            }
        }
        break;
    }
}

/*
 * --INFO--
 *
 * Function: trickyFn_80142524
 * EN v1.0 Address: 0x8014289C
 * EN v1.0 Size: 1752b
 * EN v1.1 Address: 0x801428AC
 * EN v1.1 Size: 1264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void trickyDebugPrint(const char *fmt, ...);
extern void *Tricky_findNearestGroup4BObject(void);
extern void fn_80144B50(u8 *obj, u8 *state);
extern u8 lbl_8031D2E8[];
typedef struct GrenadeIfc { void *vtable; } GrenadeIfc;
typedef struct TrickyFnRow { u8 pad[0x6c]; int (*fn)(u8 *, u8 *); } TrickyFnRow;
extern GrenadeIfc *gPathControlInterface;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2518;

void trickyFn_80142524(u8 *obj, u8 *state)
{
    u8 *base;
    u8 *found;
    u8 *other;
    u8 *target;
    u8 *ptr;
    int inWater;
    f32 z;

    base = lbl_8031D2E8;
    found = NULL;
    if ((*(u32 *)(state + 0x54) & 0x10) == 0) {
        if (state[0x7d0] != 0) {
            if ((int)state[0x7d0] == 1) {
                target = *(u8 **)(state + 0x7d4);
                other = *(u8 **)(obj + 0xb8);
                if ((*(u16 *)(obj + 0xb0) & 0x1000) == 0) {
                    if ((*(u32 *)(other + 0x54) & 0x10) == 0) {
                        *(u8 **)(other + 0x24) = target;
                        if (*(u8 **)(other + 0x28) != target + 0x18) {
                            *(u8 **)(other + 0x28) = target + 0x18;
                            *(u32 *)(other + 0x54) &= ~0x400;
                            *(u16 *)(other + 0xd2) = 0;
                        }
                        other[0xa] = 0;
                        other[0x8] = 10;
                    } else {
                        other[0x7d0] = 1;
                        *(u8 **)(other + 0x7d4) = target;
                        *(u32 *)(other + 0x54) |= 0x10000;
                    }
                }
                if (trickyFoodFn_8014460c((int)obj, (int *)state) == 0
                    && trickyFn_8013b368((int)obj, lbl_803E2488, (int)state) == 0) {
                    *(f32 *)(state + 0x740) -= timeDelta;
                    if (*(f32 *)(state + 0x740) <= lbl_803E23DC) {
                        *(f32 *)(state + 0x740) = (f32)(int)randomGetRange(500, 0x2ee);
                        ptr = *(u8 **)(obj + 0xb8);
                        if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                            && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x360, 0x500, -1, 0);
                        }
                    }
                    if (lbl_803E23DC == *(f32 *)(state + 0x2ac)) {
                        inWater = 0;
                    } else if (lbl_803E2410 == *(f32 *)(state + 0x2b0)) {
                        inWater = 1;
                    } else if (*(f32 *)(state + 0x2b4) - *(f32 *)(state + 0x2b0) > lbl_803E2414) {
                        inWater = 1;
                    } else {
                        inWater = 0;
                    }
                    if (inWater != 0) {
                        objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                        *(f32 *)(state + 0x79c) = lbl_803E2440;
                        *(f32 *)(state + 0x838) = lbl_803E23DC;
                        trickyDebugPrint((char *)(base + 0x184));
                    } else {
                        switch (*(s16 *)(obj + 0xa0)) {
                        case 0xd:
                            if (*(u32 *)(state + 0x54) & 0x8000000) {
                                objAnimFn_8013a3f0((int)obj, 0x31, lbl_803E243C, 0);
                            }
                            break;
                        default:
                            objAnimFn_8013a3f0((int)obj, 0xd, lbl_803E2444, 0);
                        case 0x31:
                            break;
                        }
                        trickyDebugPrint((char *)(base + 0x190));
                    }
                }
            }
            state[0x7d0] = 0;
            return;
        }
        found = Tricky_findNearestGroup4BObject();
    }
    if (found != NULL) {
        state[0x374] = 2;
        ((void (**)(u8 *, u8 *))gPathControlInterface->vtable)[8](obj, state + 0xf8);
        state[8] = 1;
        state[0xa] = 0;
        z = lbl_803E23DC;
        *(f32 *)(state + 0x71c) = z;
        *(f32 *)(state + 0x720) = z;
        *(u32 *)(state + 0x54) &= ~0x10;
        *(u32 *)(state + 0x54) &= ~0x10000;
        *(u32 *)(state + 0x54) &= ~0x20000;
        *(u32 *)(state + 0x54) &= ~0x40000;
        *(s8 *)(state + 0xd) = -1;
        *(f32 *)(obj + 0xc) = *(f32 *)(found + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(found + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(found + 0x14);
        *(f32 *)(obj + 0x18) = *(f32 *)(found + 0x18);
        *(f32 *)(obj + 0x1c) = *(f32 *)(found + 0x1c);
        *(f32 *)(obj + 0x20) = *(f32 *)(found + 0x20);
        ObjHits_SyncObjectPosition((int)obj);
        *(s16 *)obj = *(s16 *)found;
        state[9] = 0;
        z = lbl_803E23DC;
        *(f32 *)(state + 0x10) = z;
        *(f32 *)(state + 0x14) = z;
        *(f32 *)(state + 0xe0) = *(f32 *)(found + 0x18);
        *(f32 *)(state + 0xe4) = *(f32 *)(found + 0x1c);
        *(f32 *)(state + 0xe8) = *(f32 *)(found + 0x20);
        *(u32 *)(state + 0x54) |= 0x80000;
        *(u32 *)(state + 0x54) &= ~0x2000;
    } else {
        *(f32 *)(state + 0x71c) -= timeDelta;
        if (*(f32 *)(state + 0x71c) < lbl_803E23DC) {
            *(f32 *)(state + 0x71c) = lbl_803E23DC;
        }
        fn_80144B50(obj, state);
        if (((TrickyFnRow *)(base + state[0xa] * 4))->fn(obj, state) == 0) {
            if (lbl_803E23DC == *(f32 *)(state + 0x2ac)) {
                inWater = 0;
            } else if (lbl_803E2410 == *(f32 *)(state + 0x2b0)) {
                inWater = 1;
            } else if (*(f32 *)(state + 0x2b4) - *(f32 *)(state + 0x2b0) > lbl_803E2414) {
                inWater = 1;
            } else {
                inWater = 0;
            }
            if (inWater != 0) {
                objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                *(f32 *)(state + 0x79c) = lbl_803E2440;
                *(f32 *)(state + 0x838) = lbl_803E23DC;
            } else {
                objAnimFn_8013a3f0((int)obj, 0x25, lbl_803E2518, 0);
            }
        }
    }
}

/*
 * --INFO--
 *
 * Function: trickyFn_80142a14
 * EN v1.0 Address: 0x80142F74
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x80142D9C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void objPosFn_80039510(int obj, int flags, float *out);
extern float getXZDistance(float *a, float *b);
extern void tricky_startRandomIdleMove(int obj, int state);
extern f32 lbl_803E2424;
extern f32 lbl_803E24C8;

#pragma scheduling off
#pragma peephole off
int trickyFn_80142a14(int obj, int state)
{
  int tex;
  short sVar;
  u16 sfxId;
  float pos[3];

  objPosFn_80039510(*(int *)(state + 0x24), 0, pos);
  if (getXZDistance(pos, (float *)(state + 0x72c)) > lbl_803E2424) {
    *(float *)(state + 0x72c) = pos[0];
    *(float *)(state + 0x730) = pos[1];
    *(float *)(state + 0x734) = pos[2];
  }
  if (((*(u8 *)(state + 0x728) >> 5) & 1) != 0) {
    if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) {
      return 0;
    }
    tricky_startRandomIdleMove(obj, state);
    return 1;
  }
  if ((u8)trickyFn_8013b368(lbl_803E24C8, obj, state) == 1) {
    return 1;
  }
  *(u8 *)(state + 0x728) = *(u8 *)(state + 0x728) | 0x20;
  sfxId = randomGetRange(862, 863);
  tex = *(int *)(obj + 0xb8);
  if (((*(u8 *)(tex + 0x58) >> 6) & 1) == 0) {
    sVar = *(short *)(obj + 0xa0);
    if (sVar >= 48 || sVar < 41) {
      if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
        objAudioFn_800393f8(obj, (void *)(tex + 0x3a8), sfxId, 1280, -1, 0);
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFlameFn_80142b6c
 * EN v1.0 Address: 0x80143160
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x80142EF4
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 Obj_IsLoadingLocked(void);
extern u8 *Obj_AllocObjectSetup(int size, int id);
extern u8 *Obj_SetupObject(u8 *e, int a, int b, int c, void *d);
extern void objSetAnimSpeedTo1(u8 *e);
extern f32 lbl_803E24AC;
extern f32 lbl_803E23E4;

int trickyFlameFn_80142b6c(u8 *obj, u8 *state)
{
    int i;
    u8 *p;
    u8 *ptr;
    u8 *e;

    switch (*(s16 *)(obj + 0xa0)) {
    case 0x1a:
        if (*(f32 *)(obj + 0x98) > lbl_803E24AC && (*(u32 *)(state + 0x54) & 0x800) == 0) {
            if (Obj_IsLoadingLocked() != 0) {
                *(u32 *)(state + 0x54) |= 0x800;
                p = state;
                for (i = 0; i < 7; i++) {
                    e = Obj_AllocObjectSetup(0x24, 0x4f0);
                    e[4] = 2;
                    e[5] = 1;
                    *(s16 *)(e + 0x1a) = i;
                    *(u8 **)(p + 0x700) = Obj_SetupObject(e, 5, *(s8 *)(obj + 0xac), -1, *(void **)(obj + 0x30));
                    p += 4;
                }
                Sfx_PlayFromObject((int)obj, 0x3db);
                Sfx_AddLoopedObjectSound(obj, 0x3dc);
            }
        } else {
            if (*(u32 *)(state + 0x54) & 0x8000000) {
                *(u32 *)(state + 0x54) &= ~0x800;
                *(u32 *)(state + 0x54) |= 0x1000;
                p = state;
                for (i = 0; i < 7; i++) {
                    objSetAnimSpeedTo1(*(u8 **)(p + 0x700));
                    p += 4;
                }
                Sfx_RemoveLoopedObjectSound(obj, 0x3dc);
                ptr = *(u8 **)(obj + 0xb8);
                if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                    && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                    && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                    objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x29d, 0, -1, 0);
                }
                state[0xa] = 10;
            }
        }
        break;
    default:
        objAnimFn_8013a3f0((int)obj, 0x1a, lbl_803E23E4, 0);
    }
    return 1;
}

/*
 * --INFO--
 *
 * Function: trickyFoodFn_80142d2c
 * EN v1.0 Address: 0x801433C8
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x801430B4
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int *gGameUIInterface;
extern u32 lbl_802C21DC[];

#pragma scheduling off
#pragma peephole off
int trickyFoodFn_80142d2c(int obj, int state)
{
  int tex;
  int iface;
  int result;
  short sVar;
  u32 buf[5];

  buf[0] = lbl_802C21DC[0];
  buf[1] = lbl_802C21DC[1];
  buf[2] = lbl_802C21DC[2];
  buf[3] = lbl_802C21DC[3];
  buf[4] = lbl_802C21DC[4];
  if (trickyFoodFn_8014460c(obj, (int *)state) != 0) {
    *(float *)(state + 0x720) = lbl_803E23DC;
    *(int *)(state + 0x54) = *(int *)(state + 0x54) & ~0x10;
    *(u8 *)(state + 0xa) = 0;
    return 1;
  }
  iface = *gGameUIInterface;
  result = (**(code **)(iface + 0x24))(buf, 5);
  if (result != 2) {
    if (result < 2) {
      if (result < 0) goto skip;
    } else if (result > 5) {
      goto skip;
    }
    tex = *(int *)(obj + 0xb8);
    if (((*(u8 *)(tex + 0x58) >> 6) & 1) == 0) {
      sVar = *(short *)(obj + 0xa0);
      if (sVar >= 48 || sVar < 41) {
        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
          objAudioFn_800393f8(obj, (void *)(tex + 0x3a8), 861, 1280, -1, 0);
        }
      }
    }
  }
skip:
  if (lbl_803E23DC == *(float *)(state + 0x720)) {
    *(int *)(state + 0x54) = *(int *)(state + 0x54) & ~0x10;
    *(u8 *)(state + 0xa) = 0;
  }
  return (u8)trickyFn_8013b368(lbl_803E2408, obj, state) == 1;
}

/*
 * --INFO--
 *
 * Function: trickyFn_80142eb0
 * EN v1.0 Address: 0x801435F4
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80143238
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E23F0;
extern f32 lbl_803E243C;
extern f32 lbl_803E249C;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern int *gPartfxInterface;
extern char sInWaterMessage[];
extern char lbl_8031D478[];

#pragma scheduling off
#pragma peephole off
int trickyFn_80142eb0(int obj, int state)
{
  short sVar;
  int b;
  u8 auStack_28[8];
  float local_20;
  int local_1c;
  int local_18;
  int local_14;

  if (trickyFoodFn_8014460c(obj, (int *)state) != 0) {
    return 1;
  }
  *(u8 *)(obj + 0xaf) = *(u8 *)(obj + 0xaf) | 0x10;
  sVar = *(short *)(obj + 0xa0);
  if (sVar == 46) {
    if (((*(int *)(state + 0x54) & 0x8000000) != 0) &&
        (((*(int *)(state + 0x54) & 0x10000) != 0 || randomGetRange(0, 2) == 0) ||
         *(float *)(state + 0x720) > lbl_803E23DC)) {
      objAnimFn_8013a3f0(obj, 47, lbl_803E23EC, 0);
    }
    local_1c = *(int *)(obj + 0x18);
    local_18 = *(int *)(obj + 0x1c);
    local_14 = *(int *)(obj + 0x20);
    local_20 = lbl_803E23F0;
    (**(code **)(*gPartfxInterface + 8))(obj, 2022, auStack_28, 0x200001, -1, 0);
  } else if (sVar < 46) {
    if (43 < sVar && (*(int *)(state + 0x54) & 0x8000000) != 0) {
      objAnimFn_8013a3f0(obj, 46, lbl_803E249C, 0);
    }
  } else if (sVar < 48 && (*(int *)(state + 0x54) & 0x8000000) != 0) {
    if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
      b = 0;
    } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
      b = 1;
    } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
      b = 1;
    } else {
      b = 0;
    }
    if (b != 0) {
      objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
      *(float *)(state + 0x79c) = lbl_803E2440;
      *(float *)(state + 0x838) = lbl_803E23DC;
      trickyDebugPrint(sInWaterMessage);
    } else {
      objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
      trickyDebugPrint(lbl_8031D478);
    }
    *(int *)(state + 0x54) = *(int *)(state + 0x54) & 0xffffffef;
    *(u8 *)(state + 0xa) = 0;
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: trickyFn_801430e0
 * EN v1.0 Address: 0x80143854
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80143468
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E251C;

int trickyFn_801430e0(u8 *obj, u8 *state)
{
    u8 *ptr;
    int ret;

    if (trickyFoodFn_8014460c((int)obj, (int *)state) != 0) {
        return 1;
    }
    if ((u8)trickyFn_8013b368((int)obj, lbl_803E2418, (int)state) != 1) {
        if (*(u8 **)(state + 0x7b0) != NULL) {
            ptr = *(u8 **)(obj + 0xb8);
            if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x357, 0, -1, 0);
            }
            objAnimFn_8013a3f0((int)obj, 0x26, lbl_803E251C, 0);
            state[0xa] = 5;
        } else {
            ret = randomGetRange(0, 6);
            if (ret < 5 && ret >= 0) {
                tricky_startRandomIdleMove((int)obj, (int)state);
            } else {
                objAnimFn_801441c0((int)obj, (int)state);
            }
        }
    }
    return 1;
}

/*
 * --INFO--
 *
 * Function: trickyFn_80143210
 * EN v1.0 Address: 0x80143A14
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80143598
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 trickyFn_80143210(int param_1,int *param_2)
{
  short sVar1;
  int iVar2;
  
  iVar2 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar2 != 0) {
    return 1;
  }
  sVar1 = *(short *)(param_1 + 0xa0);
  switch (sVar1) {
  case 0x23:
    if ((param_2[0x15] & 0x8000000U) != 0) {
      objAnimFn_8013a3f0(param_1,0x24,lbl_803E2478,0);
    }
    break;
  case 0x24:
    if (((param_2[0x15] & 0x8000000U) != 0) && ((int)randomGetRange(0,3) == 0)) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
    break;
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFn_801432cc
 * EN v1.0 Address: 0x80143ABC
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80143654
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 trickyFn_801432cc(int param_1,int *param_2)
{
  short sVar1;
  int iVar2;
  
  iVar2 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar2 != 0) {
    return 1;
  }
  sVar1 = *(short *)(param_1 + 0xa0);
  switch (sVar1) {
  case 0x21:
    if ((param_2[0x15] & 0x8000000U) != 0) {
      objAnimFn_8013a3f0(param_1,0x22,lbl_803E2478,0);
    }
    break;
  case 0x22:
    if (((param_2[0x15] & 0x8000000U) != 0) && ((int)randomGetRange(0,3) == 0)) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
    break;
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFn_80143388
 * EN v1.0 Address: 0x80143B64
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80143710
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 trickyFn_80143388(int param_1,int *param_2)
{
  int iVar1;
  int iVar3;

  iVar1 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar1 != 0) {
    return 1;
  }
  for (iVar1 = 0; iVar1 < *(char *)((int)param_2 + 0x827); iVar1 = iVar1 + 1) {
    iVar3 = iVar1 + 0x81f;
    if (*(char *)((int)param_2 + iVar3) != '\0') continue;
    iVar3 = *(int *)(param_1 + 0xb8);
    if (((u32)(*(byte *)(iVar3 + 0x58) >> 6 & 1)) != 0U) continue;
    if (*(short *)(param_1 + 0xa0) >= 0x30 || *(short *)(param_1 + 0xa0) < 0x29) {
      if (Sfx_IsPlayingFromObjectChannel(param_1,0x10) == 0) {
        objAudioFn_800393f8(param_1,(void *)(iVar3 + 0x3a8),0x357,0,0xffffffff,0);
      }
    }
  }
  iVar1 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar1 != 0) {
    return 1;
  }
  if ((param_2[0x15] & 0x8000000U) != 0) {
    if (param_2[8] == (int)*(short *)(param_1 + 0xa0)) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFn_801434b0
 * EN v1.0 Address: 0x80143C64
 * EN v1.0 Size: 972b
 * EN v1.1 Address: 0x80143838
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E2520;
extern f32 lbl_803E251C;
extern f32 lbl_803E23F8;
extern f32 lbl_803E24C8;
extern int *gSHthorntailAnimationInterface;

#pragma scheduling off
#pragma peephole off
int trickyFn_801434b0(int param_1, int *param_2)
{
  char cVar1;
  short sVar2;
  float fVar3;
  int b;
  int iVar5;
  u8 auStack_28[12];
  int local_1c;
  float local_18;
  int local_14;

  if (trickyFoodFn_8014460c(param_1, param_2) != 0) {
    return 1;
  }
  *(u8 *)(param_1 + 0xaf) = *(u8 *)(param_1 + 0xaf) | 0x10;
  sVar2 = *(short *)(param_1 + 0xa0);
  if (sVar2 == 0x2a) {
    *(float *)(param_2 + 0x1cf) = *(float *)(param_2 + 0x1cf) - timeDelta;
    if (*(float *)(param_2 + 0x1cf) <= lbl_803E23DC) {
      if (((param_2[0x15] & 0x10000) != 0) || (lbl_803E23DC < *(float *)(param_2 + 0x1c8))) {
        objAnimFn_8013a3f0(param_1, 0x2b, lbl_803E23EC, 0);
      } else {
        iVar5 = (**(code **)(*gSHthorntailAnimationInterface + 0x24))(0);
        if (iVar5 == 0) {
          objAnimFn_8013a3f0(param_1, 0x2c, lbl_803E251C, 0);
          *(u8 *)((int)param_2 + 10) = 9;
        }
      }
    }
    for (iVar5 = 0; iVar5 < *(char *)((int)param_2 + 0x827); iVar5 = iVar5 + 1) {
      cVar1 = *(char *)((int)param_2 + iVar5 + 0x81f);
      if (cVar1 == '\0') {
        objAudioFn_800393f8(param_1, (void *)(param_2 + 0xea), 0x390, 0x500, -1, 0);
      } else if (cVar1 == '\a') {
        objAudioFn_800393f8(param_1, (void *)(param_2 + 0xea), 0x391, 0x100, -1, 0);
      }
    }
    fVar3 = *(float *)(param_2 + 0x1d1) - timeDelta;
    *(float *)(param_2 + 0x1d1) = fVar3;
    if (fVar3 <= lbl_803E23DC) {
      if ((*(u16 *)(param_1 + 0xb0) & 0x800) != 0) {
        local_1c = param_2[0x102];
        local_18 = lbl_803E23F8 + *(float *)(param_2 + 0x103);
        local_14 = param_2[0x104];
        (**(code **)(*gPartfxInterface + 8))(param_1, 0x7f0, auStack_28, 0x200001, -1, 0);
      }
      *(float *)(param_2 + 0x1d1) = lbl_803E24C8;
    }
  } else if (sVar2 < 0x2a) {
    if ((0x28 < sVar2) && ((param_2[0x15] & 0x8000000) != 0)) {
      objAnimFn_8013a3f0(param_1, 0x2a, lbl_803E2520, 0);
    }
  } else if ((sVar2 < 0x2c) && ((param_2[0x15] & 0x8000000) != 0)) {
    if (lbl_803E23DC == *(float *)(param_2 + 0xab)) {
      b = 0;
    } else if (lbl_803E2410 == *(float *)(param_2 + 0xac)) {
      b = 1;
    } else if (*(float *)(param_2 + 0xad) - *(float *)(param_2 + 0xac) > lbl_803E2414) {
      b = 1;
    } else {
      b = 0;
    }
    if (b != 0) {
      objAnimFn_8013a3f0(param_1, 8, lbl_803E243C, 0);
      *(float *)(param_2 + 0x1e7) = lbl_803E2440;
      *(float *)(param_2 + 0x20e) = lbl_803E23DC;
      trickyDebugPrint(sInWaterMessage);
    } else {
      objAnimFn_8013a3f0(param_1, 0, lbl_803E2444, 0);
      trickyDebugPrint(lbl_8031D478);
    }
    param_2[0x15] = param_2[0x15] & 0xffffffef;
    *(u8 *)((int)param_2 + 10) = 0;
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFoodFn_801437d4
 * EN v1.0 Address: 0x80144030
 * EN v1.0 Size: 1136b
 * EN v1.1 Address: 0x80143B5C
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
trickyFoodFn_801437d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int *param_10)
{
  float fVar1;
  int iVar2;
  bool bVar5;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  char local_28 [28];
  
  iVar2 = trickyFoodFn_8014460c(param_9,param_10);
  if (iVar2 == 0) {
    iVar2 = FUN_8012efc4();
    if (iVar2 == 0xc1) {
      *(undefined *)((int)param_10 + 10) = 0;
    }
    else {
      param_10[0x1ce] = (int)((float)param_10[0x1ce] - lbl_803DC074);
      dVar6 = (double)(float)param_10[0x1ce];
      if (dVar6 < (double)lbl_803E306C) {
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar5 = Sfx_IsPlayingFromObjectChannel(param_9,0x10), !bVar5)))) {
          in_r8 = 0;
          dVar6 = (double)objAudioFn_800393f8(param_9,(void *)(iVar2 + 0x3a8),0x29a,0x100,0xffffffff,0);
        }
        param_10[0x1ce] = (int)lbl_803E30D0;
      }
      if ((param_10[0x1ee] == 0) && (uVar3 = FUN_80017ae8(), (uVar3 & 0xff) != 0)) {
        puVar4 = FUN_80017aa4(0x20,0x17b);
        local_28[0] = -1;
        local_28[1] = -1;
        local_28[2] = -1;
        if (param_10[0x1ea] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 6] = '\x01';
        }
        if (param_10[0x1ec] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 4 & 3] = '\x01';
        }
        if (param_10[0x1ee] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 2 & 3] = '\x01';
        }
        if (local_28[0] == -1) {
          uVar3 = 0;
        }
        else if (local_28[1] == -1) {
          uVar3 = 1;
        }
        else if (local_28[2] == -1) {
          uVar3 = 2;
        }
        else if (local_28[3] == -1) {
          uVar3 = 3;
        }
        else {
          uVar3 = 0xffffffff;
        }
        *(byte *)(param_10 + 0x1ef) =
             (byte)((uVar3 & 0xff) << 2) & 0xc | *(byte *)(param_10 + 0x1ef) & 0xf3;
        iVar2 = FUN_80017ae4(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                             0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
        param_10[0x1ee] = iVar2;
        ObjLink_AttachChild(param_9,param_10[0x1ee],*(byte *)(param_10 + 0x1ef) >> 2 & 3);
        fVar1 = lbl_803E306C;
        param_10[0x1f0] = (int)lbl_803E306C;
        param_10[0x1f1] = (int)fVar1;
        param_10[0x1f2] = (int)fVar1;
      }
      iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (((iVar2 != 0) && ((float)param_10[0x1c7] <= lbl_803E306C)) &&
         (uVar3 = FUN_80017690(0xdd), uVar3 != 0)) {
        objAnimFn_8013a3f0(param_9,0x29,lbl_803E30D4,0);
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar5 = Sfx_IsPlayingFromObjectChannel(param_9,0x10), !bVar5)))) {
          objAudioFn_800393f8(param_9,(void *)(iVar2 + 0x3a8),0x354,0x1000,0xffffffff,0);
        }
        param_10[0x15] = param_10[0x15] | 0x10;
        *(undefined *)((int)param_10 + 10) = 4;
        uVar3 = randomGetRange(0x78,0xf0);
        param_10[0x1cf] =
             (int)(f32)(s32)(uVar3);
      }
    }
  }
  else {
    *(undefined *)((int)param_10 + 10) = 0;
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: trickyFn_80143b04
 * EN v1.0 Address: 0x801444A0
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80143E8C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 trickyFn_80143b04(int param_1,int *param_2)
{
  int iVar1;

  iVar1 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar1 != 0) {
    return 1;
  }
  if ((param_2[0x15] & 0x8000000U) != 0) {
    if (param_2[8] == (int)*(short *)(param_1 + 0xa0)) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFn_80143b78
 * EN v1.0 Address: 0x80144508
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80143F00
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
undefined4 trickyFn_80143b78(int param_1,int *param_2)
{
  int iVar1;

  iVar1 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar1 != 0) {
    return 1;
  }
  iVar1 = trickyFn_8013b368(param_1,lbl_803E2408,param_2);
  if (iVar1 == 1) {
    if (lbl_803E23DC == *(f32*)((int)param_2 + 0x71c)) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
    return 1;
  }
  *(undefined *)((int)param_2 + 10) = 0;
  return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: trickyFn_80143c04
 * EN v1.0 Address: 0x80144660
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x80143F8C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
#pragma scheduling off
#pragma peephole off
int trickyFn_80143c04(int obj, int state)
{
  int tex;
  short sVar;
  int result;
  int iVar4;
  float fVar;

  *(int *)(state + 0x24) = *(int *)(state + 4);
  if (*(int *)(state + 0x28) != *(int *)(state + 0x24) + 0x18) {
    *(int *)(state + 0x28) = *(int *)(state + 0x24) + 0x18;
    *(int *)(state + 0x54) = *(int *)(state + 0x54) & 0xfffffbff;
    *(short *)(state + 0xd2) = 0;
  }
  if (lbl_803E23DC == *(float *)(state + 0x71c)) {
    *(s8 *)(state + 0xd) = -1;
    fVar = lbl_803E24C8;
  } else {
    fVar = lbl_803E2408;
    if ((*(int *)(state + 0x54) & 0x20000) != 0) {
      *(s8 *)(state + 0xd) = 0;
      *(int *)(state + 0x54) = *(int *)(state + 0x54) & 0xfffdffff;
    }
  }
  result = (u8)trickyFn_8013b368(fVar, obj, state);
  if (result == 1) {
    *(u8 *)(state + 0x728) = *(u8 *)(state + 0x728) | 0x80;
    return 1;
  }
  if (result == 2) {
    if ((*(int *)(state + 0x54) & 2) != 0) {
      tex = *(int *)(obj + 0xb8);
      if (((*(u8 *)(tex + 0x58) >> 6) & 1) == 0) {
        sVar = *(short *)(obj + 0xa0);
        if (sVar >= 48 || sVar < 41) {
          if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
            objAudioFn_800393f8(obj, (void *)(tex + 0x3a8), 861, 1280, -1, 0);
          }
        }
      }
    }
  }
  if (lbl_803E23DC == *(float *)(state + 0x2ac)) {
    iVar4 = 0;
  } else if (lbl_803E2410 == *(float *)(state + 0x2b0)) {
    iVar4 = 1;
  } else if (*(float *)(state + 0x2b4) - *(float *)(state + 0x2b0) > lbl_803E2414) {
    iVar4 = 1;
  } else {
    iVar4 = 0;
  }
  if (iVar4 != 0) {
    return 0;
  }
  return fn_80143DD4(obj, (int *)state);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80143DD4
 * EN v1.0 Address: 0x80144904
 * EN v1.0 Size: 1212b
 * EN v1.1 Address: 0x8014415C
 * EN v1.1 Size: 1004b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct { u8 bf7:1; u8 bf6:1; u8 rest:6; } FlagByte728;
#pragma scheduling off
#pragma peephole off
undefined4 fn_80143DD4(int param_1,int *param_2)
{
  int iVar1;
  uint uVar3;

  iVar1 = trickyFoodFn_8014460c(param_1,param_2);
  if (iVar1 != 0) {
    return 1;
  }
  if (*(f32*)((int)param_2 + 0x79c) > lbl_803E23DC) {
    objAnimFn_8013a3f0(param_1,0x1b,lbl_803E23EC,0);
    *(undefined *)((int)param_2 + 10) = 2;
    *(f32*)((int)param_2 + 0x79c) = lbl_803E23DC;
    return 1;
  }
  if ((*(byte *)(param_2 + 0x1ca) >> 7 & 1) != 0U) {
    *(f32*)((int)param_2 + 0x724) = lbl_803E2524;
    ((FlagByte728*)((int)param_2 + 0x728))->bf7 = 0;
    ((FlagByte728*)((int)param_2 + 0x728))->bf6 = 1;
  }
  if ((*(byte *)(param_2 + 0x1ca) >> 6 & 1) != 0U) {
    *(f32*)((int)param_2 + 0x724) = *(f32*)((int)param_2 + 0x724) - timeDelta;
    if (*(f32*)((int)param_2 + 0x724) <= lbl_803E23DC) {
      *(f32*)((int)param_2 + 0x71c) = lbl_803E2438;
      uVar3 = randomGetRange(200,500);
      *(f32*)((int)param_2 + 0x724) =
           (f32)(s32)(uVar3);
      ((FlagByte728*)((int)param_2 + 0x728))->bf6 = 0;
      *(undefined *)((int)param_2 + 10) = 1;
    }
    return 0;
  }
  if (Sfx_IsPlayingFromObjectChannel(param_1,0x10)) {
    return 1;
  }
  iVar1 = ((int (*)(int))(*(int *)(*DAT_803dd6d8 + 0x24)))(0);
  if (iVar1 == 0) {
    param_2[0x15] = param_2[0x15] & 0xdfffffff;
  }
  iVar1 = ((int (*)(int))(*(int *)(*DAT_803dd6d8 + 0x24)))(0);
  if ((iVar1 != 0) && ((param_2[0x15] & 0x20000000U) == 0)) {
    param_2[0x15] = param_2[0x15] | 0x20000000;
    iVar1 = *(int *)(param_1 + 0xb8);
    if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0U) &&
       ((*(short *)(param_1 + 0xa0) >= 0x30 || (*(short *)(param_1 + 0xa0) < 0x29)) &&
         !Sfx_IsPlayingFromObjectChannel(param_1,0x10))) {
      objAudioFn_800393f8(param_1,(void *)(iVar1 + 0x3a8),0x353,0x500,0xffffffff,0);
    }
    return 0;
  }
  if (*(byte *)*param_2 <= 3) {
    objAnimFn_8013a3f0(param_1,0x14,lbl_803E2444,0);
    *(undefined *)((int)param_2 + 10) = 3;
    *(f32*)((int)param_2 + 0x738) = lbl_803E2440;
    return 1;
  }
  *(f32*)((int)param_2 + 0x724) = *(f32*)((int)param_2 + 0x724) - timeDelta;
  if (*(f32*)((int)param_2 + 0x724) > lbl_803E23DC) {
    return 0;
  }
  uVar3 = randomGetRange(200,500);
  *(f32*)((int)param_2 + 0x724) =
       (f32)(s32)(uVar3);
  if (*(byte *)*param_2 <= 7) {
    objAnimFn_8013a3f0(param_1,0x14,lbl_803E2444,0);
    *(undefined *)((int)param_2 + 10) = 3;
    *(f32*)((int)param_2 + 0x738) = lbl_803E2440;
    return 1;
  }
  if (*(f32*)((int)param_2 + 0x71c) <= lbl_803E23DC) {
    if (param_2[0x1ec] == 0) {
      uVar3 = randomGetRange(0,6);
      if (((int)uVar3 < 5) && (-1 < (int)uVar3)) {
        tricky_startRandomIdleMove(param_1,(int)param_2);
      }
      else {
        objAnimFn_801441c0(param_1,(int)param_2);
      }
    }
    else {
      iVar1 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0U) &&
          (*(short *)(param_1 + 0xa0) >= 0x30 || (*(short *)(param_1 + 0xa0) < 0x29)
           ) && !Sfx_IsPlayingFromObjectChannel(param_1,0x10))) {
        objAudioFn_800393f8(param_1,(void *)(iVar1 + 0x3a8),0x357,0,0xffffffff,0);
      }
      objAnimFn_8013a3f0(param_1,0x26,lbl_803E251C,0);
      *(undefined *)((int)param_2 + 10) = 5;
    }
  }
  else {
    tricky_startRandomIdleMove(param_1,(int)param_2);
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: objAnimFn_801441c0
 * EN v1.0 Address: 0x80144DC0
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x80144548
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void objAnimFn_801441c0(int param_1,int param_2)
{
  short *psVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  double dVar9;
  float local_38 [2];
  undefined4 local_30;
  uint uStack_2c;

  psVar1 = (short *)param_1;
  iVar6 = param_2;
  uVar8 = 1;
  uVar7 = 3;
  local_38[0] = lbl_803E31B4;
  iVar2 = ObjGroup_FindNearestObject(0x4d,psVar1,local_38);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0)) {
    uVar8 = 0;
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if ((iVar3 == 0) || (uVar4 = FUN_80017690(0xdd), uVar4 == 0)) {
    uVar7 = 2;
  }
  uVar7 = randomGetRange(uVar8,uVar7);
  if (uVar7 == 2) {
    objAnimFn_8013a3f0((int)psVar1,0x2d,lbl_803E31C0,0);
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    *(undefined *)(iVar6 + 10) = 9;
  }
  else if ((int)uVar7 < 2) {
    if (uVar7 == 0) {
      *(int *)(iVar6 + 0x24) = iVar2;
      FUN_80039580(iVar2,0,(float *)(iVar6 + 0x72c));
      if (*(int *)(iVar6 + 0x28) != iVar6 + 0x72c) {
        *(int *)(iVar6 + 0x28) = iVar6 + 0x72c;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      *(byte *)(iVar6 + 0x728) = *(byte *)(iVar6 + 0x728) & 0xdf;
      *(undefined *)(iVar6 + 10) = 0xc;
    }
    else if (-1 < (int)uVar7) {
      uVar7 = randomGetRange(0x20,0xff);
      uStack_2c = (int)(short)((*psVar1 + (short)uVar7) * 0x100) ^ 0x80000000;
      local_30 = 0x43300000;
      dVar9 = (double)FUN_80293f90();
      *(float *)(iVar6 + 0x72c) = (float)(DOUBLE_803e31b8 * -dVar9 + (double)*(float *)(psVar1 + 6))
      ;
      *(undefined4 *)(iVar6 + 0x730) = *(undefined4 *)(psVar1 + 8);
      dVar9 = (double)FUN_80294964();
      *(float *)(iVar6 + 0x734) =
           (float)((double)lbl_803E3114 * -dVar9 + (double)*(float *)(psVar1 + 10));
      if (*(int *)(iVar6 + 0x28) != iVar6 + 0x72c) {
        *(int *)(iVar6 + 0x28) = iVar6 + 0x72c;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      *(undefined *)(iVar6 + 10) = 8;
    }
  }
  else if ((int)uVar7 < 4) {
    objAnimFn_8013a3f0((int)psVar1,0x29,lbl_803E30D4,0);
    iVar2 = *(int *)(psVar1 + 0x5c);
    if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < psVar1[0x50] || (psVar1[0x50] < 0x29)) &&
        (bVar5 = Sfx_IsPlayingFromObjectChannel((int)psVar1,0x10), !bVar5)))) {
      objAudioFn_800393f8((int)psVar1,(void *)(iVar2 + 0x3a8),0x354,0x1000,0xffffffff,0);
    }
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    *(undefined *)(iVar6 + 10) = 4;
    uStack_2c = randomGetRange(0x78,0xf0);
    *(float *)(iVar6 + 0x73c) = (f32)(s32)uStack_2c;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: tricky_startRandomIdleMove
 * EN v1.0 Address: 0x80145074
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8014482C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void tricky_startRandomIdleMove(int param_1,int param_2)
{
  int iVar1;
  int iVar3;

  iVar1 = randomGetRange(0,4);
  switch (iVar1) {
  case 0:
    objAnimFn_8013a3f0(param_1,0,lbl_803E2444,0);
    *(undefined *)(param_2 + 10) = 2;
    break;
  case 1:
    iVar3 = *(int *)(param_1 + 0xb8);
    if (((u32)(*(byte *)(iVar3 + 0x58) >> 6 & 1)) == 0U) {
      if (*(short *)(param_1 + 0xa0) >= 0x30 || *(short *)(param_1 + 0xa0) < 0x29) {
        if (Sfx_IsPlayingFromObjectChannel(param_1,0x10) == 0) {
          objAudioFn_800393f8(param_1,(void *)(iVar3 + 0x3a8),0x357,0,0xffffffff,0);
        }
      }
    }
    objAnimFn_8013a3f0(param_1,0x26,lbl_803E251C,0);
    *(undefined *)(param_2 + 10) = 5;
    break;
  case 2:
    objAnimFn_8013a3f0(param_1,0x21,lbl_803E2478,0);
    *(undefined *)(param_2 + 10) = 6;
    break;
  case 3:
    objAnimFn_8013a3f0(param_1,0x23,lbl_803E2478,0);
    *(undefined *)(param_2 + 10) = 7;
    break;
  case 4:
    objAnimFn_8013a3f0(param_1,0x25,lbl_803E2518,0);
    *(undefined *)(param_2 + 10) = 2;
    break;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: trickyFoodFn_8014460c
 * EN v1.0 Address: 0x801451DC
 * EN v1.0 Size: 1244b
 * EN v1.1 Address: 0x80144994
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int trickyFoodFn_8014460c(int param_1,int *param_2)
{
  bool bVar1;
  char cVar2;
  char cVar3;
  byte bVar5;
  uint uVar4;
  uint uVar6;
  int iVar7;
  short local_18 [4];
  
  bVar1 = false;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  uVar6 = FUN_80017690(0xc1);
  uVar6 = uVar6 & 0xff;
  if (uVar6 != 0) {
    FUN_8011e824(local_18);
    bVar1 = local_18[0] == 0xc1;
    iVar7 = FUN_8012efc4();
    if (iVar7 == 0xc1) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80017a6c(param_1,0,0,0,'\0','\x04');
    }
    else {
      iVar7 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc1);
      if (iVar7 != 0) {
        cVar2 = *(char *)*param_2;
        cVar3 = ((char *)*param_2)[1];
        if (cVar2 == cVar3) {
          iVar7 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 1;
          if (lbl_803E306C == *(float *)(iVar7 + 0x2ac)) {
            bVar1 = false;
          }
          else if (lbl_803E30A0 == *(float *)(iVar7 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= lbl_803E30A4) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            objAnimFn_8013a3f0(param_1,8,lbl_803E30CC,0);
            *(float *)(iVar7 + 0x79c) = lbl_803E30D0;
            *(float *)(iVar7 + 0x838) = lbl_803E306C;
            FUN_80146fa0();
          }
          else {
            objAnimFn_8013a3f0(param_1,0,lbl_803E30D4,0);
            FUN_80146fa0();
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_1,0xffffffff);
          *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
        }
        else {
          bVar5 = cVar3 - cVar2;
          uVar4 = (uint)(bVar5 >> 2);
          if ((bVar5 & 3) != 0) {
            uVar4 = uVar4 + 1;
          }
          if (uVar6 < uVar4) {
            *(char *)((int)param_2 + 0x82d) = cVar2 + (char)(uVar6 << 2);
            FUN_80017698(0xc1,0);
          }
          else {
            *(char *)((int)param_2 + 0x82d) = cVar2 + (char)(uVar4 << 2);
            FUN_80017698(0xc1,uVar6 - uVar4);
          }
          if (*(byte *)(*param_2 + 1) < *(byte *)((int)param_2 + 0x82d)) {
            *(byte *)((int)param_2 + 0x82d) = *(byte *)(*param_2 + 1);
          }
          iVar7 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
          if (lbl_803E306C == *(float *)(iVar7 + 0x2ac)) {
            bVar1 = false;
          }
          else if (lbl_803E30A0 == *(float *)(iVar7 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= lbl_803E30A4) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            objAnimFn_8013a3f0(param_1,8,lbl_803E30CC,0);
            *(float *)(iVar7 + 0x79c) = lbl_803E30D0;
            *(float *)(iVar7 + 0x838) = lbl_803E306C;
            FUN_80146fa0();
          }
          else {
            objAnimFn_8013a3f0(param_1,0,lbl_803E30D4,0);
            FUN_80146fa0();
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
          *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
          param_2[0x15] = param_2[0x15] | 0x40000000;
        }
        FUN_80006ba8(0,0x100);
        return 1;
      }
    }
  }
  else {
    uVar6 = FUN_80017690(0x4e3);
    uVar6 = uVar6 & 0xff;
    if ((uVar6 != 0xff) && (iVar7 = FUN_8012efc4(), iVar7 == -1)) {
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        FUN_80017698(0x4e3,0xff);
        iVar7 = *(int *)(param_1 + 0xb8);
        *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
        if (uVar6 != 2) {
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 1;
        }
        if (lbl_803E306C == *(float *)(iVar7 + 0x2ac)) {
          bVar1 = false;
        }
        else if (lbl_803E30A0 == *(float *)(iVar7 + 0x2b0)) {
          bVar1 = true;
        }
        else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= lbl_803E30A4) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
        if (bVar1) {
          objAnimFn_8013a3f0(param_1,8,lbl_803E30CC,0);
          *(float *)(iVar7 + 0x79c) = lbl_803E30D0;
          *(float *)(iVar7 + 0x838) = lbl_803E306C;
          FUN_80146fa0();
        }
        else {
          objAnimFn_8013a3f0(param_1,0,lbl_803E30D4,0);
          FUN_80146fa0();
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar6,param_1,0xffffffff);
        *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
        FUN_80006ba8(0,0x100);
        return 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80017a6c(param_1,0,0,0,'\0','\x02');
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80144B50
 * EN v1.0 Address: 0x80144B50
 * EN v1.0 Size: 752b
 */
extern int ObjHits_GetPriorityHit(int obj, int *out, int a, int b);
extern uint GameBit_Get(int bit);
extern f32 lbl_803E2534;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24EC;

void fn_80144B50(u8 *obj, u8 *state)
{
    int hit[3];
    u8 *ptr;
    f32 fv;
    int inWater;

    *(f32 *)(state + 0x720) -= timeDelta;
    if (*(f32 *)(state + 0x720) < lbl_803E23DC) {
        *(f32 *)(state + 0x720) = lbl_803E23DC;
    }
    if (ObjHits_GetPriorityHit((int)obj, hit, 0, 0) != 0
        && *(u8 **)(hit[0] + 0xc4) != NULL
        && *(s16 *)(*(u8 **)(hit[0] + 0xc4) + 0x44) == 1) {
        fv = *(f32 *)(state + 0x720);
        if (fv <= lbl_803E23DC) {
            *(f32 *)(state + 0x720) = fv + lbl_803E24EC;
            ptr = *(u8 **)(obj + 0xb8);
            if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x34f, 0x500, -1, 0);
            }
        } else {
            *(f32 *)(state + 0x720) = fv + lbl_803E2440;
            if (state[0xa] != 0xb) {
                if (*(u32 *)(state + 0x54) & 0x10) {
                    if (*(f32 *)(state + 0x720) > lbl_803E2534) {
                        *(f32 *)(state + 0x720) *= lbl_803E24A8;
                        if (GameBit_Get(0x245) != 0) {
                            if (lbl_803E23DC == *(f32 *)(state + 0x2ac)) {
                                inWater = 0;
                            } else if (lbl_803E2410 == *(f32 *)(state + 0x2b0)) {
                                inWater = 1;
                            } else if (*(f32 *)(state + 0x2b4) - *(f32 *)(state + 0x2b0) > lbl_803E2414) {
                                inWater = 1;
                            } else {
                                inWater = 0;
                            }
                            if (inWater == 0) {
                                state[0xa] = 0xb;
                                return;
                            }
                        }
                        ptr = *(u8 **)(obj + 0xb8);
                        if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                            && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x350, 0x500, -1, 0);
                        }
                    } else {
                        ptr = *(u8 **)(obj + 0xb8);
                        if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                            && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x350, 0x500, -1, 0);
                        }
                    }
                } else {
                    ptr = *(u8 **)(obj + 0xb8);
                    if (((u32)*(u8 *)(ptr + 0x58) >> 6 & 1) == 0
                        && (*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29)
                        && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0) {
                        objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x350, 0x500, -1, 0);
                    }
                    state[0xa] = 10;
                    *(u32 *)(state + 0x54) |= 0x10;
                }
            }
        }
    }
}
