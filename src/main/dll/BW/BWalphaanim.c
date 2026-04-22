#include "ghidra_import.h"
#include "main/dll/BW/BWalphaanim.h"

extern undefined4 FUN_8000b7dc();
extern char FUN_80014c98();
extern char FUN_80014cec();
extern uint FUN_80014e40();
extern uint FUN_80014e9c();
extern uint FUN_80014f14();
extern uint FUN_80020078();
extern uint FUN_80021884();
extern undefined4 FUN_80021c64();
extern undefined4 FUN_80022790();
extern undefined4 FUN_8002a8d4();
extern undefined4 FUN_8002b9c8();
extern int FUN_80055238();
extern undefined4 FUN_80055240();
extern undefined4 FUN_8011f6ac();
extern undefined4 FUN_8011f6d0();
extern undefined4 FUN_801ea878();
extern uint FUN_801eb0f8();
extern undefined4 FUN_801eb484();
extern undefined4 FUN_801eb70c();
extern undefined4 FUN_801ebc6c();
extern undefined4 FUN_801ec398();
extern undefined4 FUN_801ec7e4();
extern undefined4 FUN_801ecdd8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_802932a4();

extern f64 DOUBLE_803e6798;
extern f64 DOUBLE_803e68b8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6780;
extern f32 FLOAT_803e6784;
extern f32 FLOAT_803e6804;
extern f32 FLOAT_803e6808;
extern f32 FLOAT_803e6838;
extern f32 FLOAT_803e68b0;

/*
 * --INFO--
 *
 * Function: FUN_801eda60
 * EN v1.0 Address: 0x801EDA60
 * EN v1.0 Size: 1700b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eda60(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
    uVar3 = FUN_80020078(0x1fa);
    if (uVar3 != 0) {
      *(undefined *)(iVar6 + 0x420) = 0;
    }
    uVar3 = FUN_80020078(0x1fb);
    if (uVar3 != 0) {
      param_1 = FUN_8002a8d4((int)param_9,0x13);
    }
  }
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  param_9[1] = *(short *)(iVar6 + 0x41c);
  param_9[2] = *(short *)(iVar6 + 0x41e);
  if (((*(byte *)(iVar6 + 0x428) >> 2 & 1) == 0) &&
     (uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x44a)), uVar3 == 0)) {
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
          FUN_8000b7dc((int)param_9,0x57);
        }
      }
      else if (cVar5 < '\x03') {
        FUN_801eb484(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6);
        if ((*(byte *)(iVar6 + 0x428) >> 1 & 1) == 0) {
          FUN_8011f6d0(0x10);
          FUN_8011f6ac(0x11);
          cVar5 = FUN_80014cec(0);
          uStack_34 = (int)cVar5 ^ 0x80000000;
          local_38 = 0x43300000;
          *(float *)(iVar6 + 0x45c) =
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e6798);
          cVar5 = FUN_80014c98(0);
          uStack_2c = (int)cVar5 ^ 0x80000000;
          local_30 = 0x43300000;
          iVar4 = (int)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e6798);
          local_28 = (longlong)iVar4;
          *(char *)(iVar6 + 0x460) = (char)iVar4;
          uVar3 = FUN_80014f14(0);
          *(uint *)(iVar6 + 0x458) = uVar3;
          uVar3 = FUN_80014e9c(0);
          *(uint *)(iVar6 + 0x450) = uVar3;
          uVar3 = FUN_80014e40(0);
          *(uint *)(iVar6 + 0x454) = uVar3;
          uStack_1c = -(int)*(char *)(iVar6 + 0x460) ^ 0x80000000;
          local_20 = 0x43300000;
          uStack_14 = FUN_80021884();
          uStack_14 = uStack_14 & 0xffff;
          local_18 = 0x43300000;
          iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e68b8) /
                       FLOAT_803e68b0);
          local_10 = (longlong)iVar4;
          *(short *)(iVar6 + 0x44c) = (short)iVar4;
          *(float *)(iVar6 + 0x45c) = *(float *)(iVar6 + 0x45c) / FLOAT_803e6804;
          fVar1 = *(float *)(iVar6 + 0x45c);
          fVar2 = FLOAT_803e6808;
          if ((FLOAT_803e6808 <= fVar1) && (fVar2 = fVar1, FLOAT_803e6784 < fVar1)) {
            fVar2 = FLOAT_803e6784;
          }
          *(float *)(iVar6 + 0x45c) = fVar2;
          FUN_801ec398((int)param_9,iVar6);
          FUN_801ecdd8(param_9,iVar6);
          if (*(float *)(iVar6 + 0x3e4) == FLOAT_803e6780) {
            *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
            *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
            *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
          }
          else {
            FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x464),
                         (float *)(iVar6 + 0x47c));
            FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x494),
                         (float *)(iVar6 + 0x494));
            *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - FLOAT_803dc074;
            if (*(float *)(iVar6 + 0x3e4) <= FLOAT_803e6780) {
              iVar4 = FUN_80055238();
              if (iVar4 != 0) {
                FUN_80055240((double)FLOAT_803e6780,0);
              }
              *(float *)(iVar6 + 0x3e4) = FLOAT_803e6780;
            }
          }
          local_dc = FLOAT_803e6780;
          local_d8 = FLOAT_803e6780;
          local_d4 = FLOAT_803e6780;
          local_e0 = FLOAT_803e6784;
          local_e8 = -*(short *)(iVar6 + 0x40e);
          local_e6 = -param_9[1];
          local_e4 = -param_9[2];
          FUN_80021c64(afStack_b8,(int)&local_e8);
          FUN_80022790((double)FLOAT_803e6780,
                       (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                       (double)FLOAT_803e6780,afStack_b8,&local_100,&fStack_108,&fStack_f8);
          local_100 = local_100 * *(float *)(iVar6 + 0x540);
          local_fc = FLOAT_803e6780;
          FUN_80247edc((double)FLOAT_803dc074,&local_100,&local_100);
          FUN_80247e94((float *)(iVar6 + 0x494),&local_100,(float *)(iVar6 + 0x494));
          *(float *)(iVar6 + 0x498) =
               *(float *)(iVar6 + 0x4b0) * FLOAT_803dc074 + *(float *)(iVar6 + 0x498);
          dVar7 = (double)FUN_802932a4((double)*(float *)(iVar6 + 0x548),(double)FLOAT_803dc074);
          *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
          dVar7 = (double)FUN_802932a4((double)*(float *)(iVar6 + 0x54c),(double)FLOAT_803dc074);
          *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
          FUN_801ec7e4((uint)param_9,iVar6);
          FUN_80022790((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                       (double)*(float *)(iVar6 + 0x49c),(float *)(iVar6 + 0xec),
                       (float *)(param_9 + 0x12),(float *)(param_9 + 0x14),(float *)(param_9 + 0x16)
                      );
          FUN_8002b9c8((int)param_9);
        }
        else {
          uVar3 = FUN_801eb0f8(param_9,iVar6);
          if (uVar3 != 0) {
            FUN_801ec398((int)param_9,iVar6);
            FUN_801ecdd8(param_9,iVar6);
            if (*(float *)(iVar6 + 0x3e4) == FLOAT_803e6780) {
              *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
              *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
              *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
            }
            else {
              FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x464),
                           (float *)(iVar6 + 0x47c));
              FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x494),
                           (float *)(iVar6 + 0x494));
              *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - FLOAT_803dc074;
              if (*(float *)(iVar6 + 0x3e4) <= FLOAT_803e6780) {
                iVar4 = FUN_80055238();
                if (iVar4 != 0) {
                  FUN_80055240((double)FLOAT_803e6780,0);
                }
                *(float *)(iVar6 + 0x3e4) = FLOAT_803e6780;
              }
            }
            local_c4 = FLOAT_803e6780;
            local_c0 = FLOAT_803e6780;
            local_bc = FLOAT_803e6780;
            local_c8 = FLOAT_803e6784;
            local_d0 = -*(short *)(iVar6 + 0x40e);
            local_ce = -param_9[1];
            local_cc = -param_9[2];
            FUN_80021c64(afStack_78,(int)&local_d0);
            FUN_80022790((double)FLOAT_803e6780,
                         (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                         (double)FLOAT_803e6780,afStack_78,&local_f4,&fStack_104,&fStack_ec);
            local_f4 = local_f4 * *(float *)(iVar6 + 0x540);
            local_f0 = FLOAT_803e6780;
            FUN_80247edc((double)FLOAT_803dc074,&local_f4,&local_f4);
            FUN_80247e94((float *)(iVar6 + 0x494),&local_f4,(float *)(iVar6 + 0x494));
            *(float *)(iVar6 + 0x498) =
                 *(float *)(iVar6 + 0x4b0) * FLOAT_803dc074 + *(float *)(iVar6 + 0x498);
            dVar7 = (double)FUN_802932a4((double)*(float *)(iVar6 + 0x548),(double)FLOAT_803dc074);
            *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
            dVar7 = (double)FUN_802932a4((double)*(float *)(iVar6 + 0x54c),(double)FLOAT_803dc074);
            *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
            FUN_801ec7e4((uint)param_9,iVar6);
            FUN_80022790((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                         (double)*(float *)(iVar6 + 0x49c),(float *)(iVar6 + 0xec),
                         (float *)(param_9 + 0x12),(float *)(param_9 + 0x14),
                         (float *)(param_9 + 0x16));
            FUN_8002b9c8((int)param_9);
          }
        }
        FUN_801eb70c((uint)param_9,iVar6);
        uVar3 = (uint)(FLOAT_803e6838 * -*(float *)(iVar6 + 0x430));
        local_10 = (longlong)(int)uVar3;
        FUN_801ea878((double)*(float *)(iVar6 + 0x49c),(uint)param_9,iVar6,uVar3,iVar6 + 0x461,7);
        FUN_801ebc6c((int)param_9,iVar6);
        *param_9 = *(short *)(iVar6 + 0x40e);
      }
    }
  }
  else {
    *(byte *)(iVar6 + 0x428) = *(byte *)(iVar6 + 0x428) & 0xfb | 4;
  }
  return;
}
