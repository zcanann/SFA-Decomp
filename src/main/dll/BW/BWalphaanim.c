#include "ghidra_import.h"
#include "main/dll/BW/BWalphaanim.h"

extern undefined4 FUN_8000680c();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a10();
extern undefined4 FUN_80017a80();
extern int FUN_80053c14();
extern undefined4 FUN_80053c20();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801ea854();
extern uint FUN_801eb0c0();
extern undefined4 FUN_801eb42c();
extern undefined4 FUN_801eb708();
extern undefined4 FUN_801eba80();
extern undefined4 FUN_801ec1ac();
extern undefined4 FUN_801ec7a0();
extern undefined4 FUN_801ecd30();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80293130();

extern f64 DOUBLE_803e6798;
extern f64 DOUBLE_803e68b8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E6838;
extern f32 lbl_803E68B0;

/*
 * --INFO--
 *
 * Function: FUN_801ed428
 * EN v1.0 Address: 0x801ED428
 * EN v1.0 Size: 1732b
 * EN v1.1 Address: 0x801EDA60
 * EN v1.1 Size: 1700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed428(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  double dVar7;
  float fStack_108;
  float fStack_104;
  float local_100;
  float local_fc;
  float fStack_f8;
  float local_f4;
  float local_f0;
  float fStack_ec;
  short local_e8;
  short local_e6;
  short local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  short local_d0;
  short local_ce;
  short local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float afStack_b8 [16];
  float afStack_78 [16];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_9 + 0x56) == -1) {
    uVar3 = GameBit_Get(0x1fa);
    if (uVar3 != 0) {
      *(undefined *)(iVar6 + 0x420) = 0;
    }
    uVar3 = GameBit_Get(0x1fb);
    if (uVar3 != 0) {
      param_1 = FUN_80017a10((int)param_9,0x13);
    }
  }
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  param_9[1] = *(short *)(iVar6 + 0x41c);
  param_9[2] = *(short *)(iVar6 + 0x41e);
  if (((*(byte *)(iVar6 + 0x428) >> 2 & 1) == 0) &&
     (uVar3 = GameBit_Get((int)*(short *)(iVar6 + 0x44a)), uVar3 == 0)) {
    cVar5 = *(char *)(iVar6 + 0x421);
    if (cVar5 != '\x01') {
      if (cVar5 < '\x01') {
        if (-1 < cVar5) {
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          if ((*(byte *)((int)param_9 + 0xaf) & 4) == 0) {
            *(undefined *)(iVar6 + 0x420) = 0;
          }
          else {
            *(undefined *)(iVar6 + 0x420) = 1;
          }
          FUN_8000680c((int)param_9,0x57);
        }
      }
      else if (cVar5 < '\x03') {
        FUN_801eb42c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6);
        if ((*(byte *)(iVar6 + 0x428) >> 1 & 1) == 0) {
          FUN_8011e868(0x10);
          FUN_8011e844(0x11);
          cVar5 = FUN_80006bd0(0);
          uStack_34 = (int)cVar5 ^ 0x80000000;
          local_38 = 0x43300000;
          *(float *)(iVar6 + 0x45c) =
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e6798);
          cVar5 = FUN_80006bc8(0);
          uStack_2c = (int)cVar5 ^ 0x80000000;
          local_30 = 0x43300000;
          iVar4 = (int)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e6798);
          local_28 = (longlong)iVar4;
          *(char *)(iVar6 + 0x460) = (char)iVar4;
          uVar3 = FUN_80006c10(0);
          *(uint *)(iVar6 + 0x458) = uVar3;
          uVar3 = FUN_80006c00(0);
          *(uint *)(iVar6 + 0x450) = uVar3;
          uVar3 = FUN_80006bf8(0);
          *(uint *)(iVar6 + 0x454) = uVar3;
          uStack_1c = -(int)*(char *)(iVar6 + 0x460) ^ 0x80000000;
          local_20 = 0x43300000;
          uStack_14 = FUN_80017730();
          uStack_14 = uStack_14 & 0xffff;
          local_18 = 0x43300000;
          iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e68b8) /
                       lbl_803E68B0);
          local_10 = (longlong)iVar4;
          *(short *)(iVar6 + 0x44c) = (short)iVar4;
          *(float *)(iVar6 + 0x45c) = *(float *)(iVar6 + 0x45c) / lbl_803E6804;
          fVar1 = *(float *)(iVar6 + 0x45c);
          fVar2 = lbl_803E6808;
          if ((lbl_803E6808 <= fVar1) && (fVar2 = fVar1, lbl_803E6784 < fVar1)) {
            fVar2 = lbl_803E6784;
          }
          *(float *)(iVar6 + 0x45c) = fVar2;
          FUN_801ec1ac((int)param_9,iVar6);
          FUN_801ecd30(param_9,iVar6);
          if (*(float *)(iVar6 + 0x3e4) == lbl_803E6780) {
            *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
            *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
            *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
          }
          else {
            FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x464),
                         (float *)(iVar6 + 0x47c));
            FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x494),
                         (float *)(iVar6 + 0x494));
            *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - lbl_803DC074;
            if (*(float *)(iVar6 + 0x3e4) <= lbl_803E6780) {
              iVar4 = FUN_80053c14();
              if (iVar4 != 0) {
                FUN_80053c20((double)lbl_803E6780,0);
              }
              *(float *)(iVar6 + 0x3e4) = lbl_803E6780;
            }
          }
          local_dc = lbl_803E6780;
          local_d8 = lbl_803E6780;
          local_d4 = lbl_803E6780;
          local_e0 = lbl_803E6784;
          local_e8 = -*(short *)(iVar6 + 0x40e);
          local_e6 = -param_9[1];
          local_e4 = -param_9[2];
          FUN_8001774c(afStack_b8,(int)&local_e8);
          FUN_80017778((double)lbl_803E6780,
                       (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                       (double)lbl_803E6780,afStack_b8,&local_100,&fStack_108,&fStack_f8);
          local_100 = local_100 * *(float *)(iVar6 + 0x540);
          local_fc = lbl_803E6780;
          FUN_80247edc((double)lbl_803DC074,&local_100,&local_100);
          FUN_80247e94((float *)(iVar6 + 0x494),&local_100,(float *)(iVar6 + 0x494));
          *(float *)(iVar6 + 0x498) =
               *(float *)(iVar6 + 0x4b0) * lbl_803DC074 + *(float *)(iVar6 + 0x498);
          dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x548),(double)lbl_803DC074);
          *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
          dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x54c),(double)lbl_803DC074);
          *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
          FUN_801ec7a0((uint)param_9,iVar6);
          FUN_80017778((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                       (double)*(float *)(iVar6 + 0x49c),(float *)(iVar6 + 0xec),
                       (float *)(param_9 + 0x12),(float *)(param_9 + 0x14),(float *)(param_9 + 0x16)
                      );
          FUN_80017a80((int)param_9);
        }
        else {
          uVar3 = FUN_801eb0c0(param_9,iVar6);
          if (uVar3 != 0) {
            FUN_801ec1ac((int)param_9,iVar6);
            FUN_801ecd30(param_9,iVar6);
            if (*(float *)(iVar6 + 0x3e4) == lbl_803E6780) {
              *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
              *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
              *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
            }
            else {
              FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x464),
                           (float *)(iVar6 + 0x47c));
              FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x494),
                           (float *)(iVar6 + 0x494));
              *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - lbl_803DC074;
              if (*(float *)(iVar6 + 0x3e4) <= lbl_803E6780) {
                iVar4 = FUN_80053c14();
                if (iVar4 != 0) {
                  FUN_80053c20((double)lbl_803E6780,0);
                }
                *(float *)(iVar6 + 0x3e4) = lbl_803E6780;
              }
            }
            local_c4 = lbl_803E6780;
            local_c0 = lbl_803E6780;
            local_bc = lbl_803E6780;
            local_c8 = lbl_803E6784;
            local_d0 = -*(short *)(iVar6 + 0x40e);
            local_ce = -param_9[1];
            local_cc = -param_9[2];
            FUN_8001774c(afStack_78,(int)&local_d0);
            FUN_80017778((double)lbl_803E6780,
                         (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                         (double)lbl_803E6780,afStack_78,&local_f4,&fStack_104,&fStack_ec);
            local_f4 = local_f4 * *(float *)(iVar6 + 0x540);
            local_f0 = lbl_803E6780;
            FUN_80247edc((double)lbl_803DC074,&local_f4,&local_f4);
            FUN_80247e94((float *)(iVar6 + 0x494),&local_f4,(float *)(iVar6 + 0x494));
            *(float *)(iVar6 + 0x498) =
                 *(float *)(iVar6 + 0x4b0) * lbl_803DC074 + *(float *)(iVar6 + 0x498);
            dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x548),(double)lbl_803DC074);
            *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
            dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x54c),(double)lbl_803DC074);
            *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
            FUN_801ec7a0((uint)param_9,iVar6);
            FUN_80017778((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                         (double)*(float *)(iVar6 + 0x49c),(float *)(iVar6 + 0xec),
                         (float *)(param_9 + 0x12),(float *)(param_9 + 0x14),
                         (float *)(param_9 + 0x16));
            FUN_80017a80((int)param_9);
          }
        }
        FUN_801eb708((uint)param_9,iVar6);
        uVar3 = (uint)(lbl_803E6838 * -*(float *)(iVar6 + 0x430));
        local_10 = (longlong)(int)uVar3;
        FUN_801ea854((double)*(float *)(iVar6 + 0x49c),(uint)param_9,iVar6,uVar3,iVar6 + 0x461,7);
        FUN_801eba80((int)param_9,iVar6);
        *param_9 = *(short *)(iVar6 + 0x40e);
      }
    }
  }
  else {
    *(byte *)(iVar6 + 0x428) = *(byte *)(iVar6 + 0x428) & 0xfb | 4;
  }
  return;
}

extern void textureFree(u32);
extern u32 textureLoadAsset(int);
extern u32 lbl_803DDC60;

#pragma scheduling off
#pragma peephole off
void SnowBike_release(void) {
    if (lbl_803DDC60 != 0) {
        textureFree(lbl_803DDC60);
        lbl_803DDC60 = 0;
    }
}
void SnowBike_initialise(void) {
    if (lbl_803DDC60 == 0) {
        lbl_803DDC60 = textureLoadAsset(0x186);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void fn_801EE088(int *obj) {
    int *p = (int*)obj[0xb8/4];
    *(f32*)((char*)p + 0x4c) = *(f32*)((char*)obj + 0xc);
    *(f32*)((char*)p + 0x50) = *(f32*)((char*)obj + 0x10);
    *(f32*)((char*)p + 0x54) = *(f32*)((char*)obj + 0x14);
    {
        s32 v = *(s16*)obj - 0x4000;
        *(s16*)((char*)p + 0x2c) = (s16)v;
    }
    *(s16*)((char*)p + 0x2e) = *(s16*)((char*)obj + 4);
}
#pragma peephole reset
