// Function: FUN_802acf3c
// Entry: 802acf3c
// Size: 2600 bytes

/* WARNING: Removing unreachable block (ram,0x802ad93c) */
/* WARNING: Removing unreachable block (ram,0x802ad934) */
/* WARNING: Removing unreachable block (ram,0x802ad92c) */
/* WARNING: Removing unreachable block (ram,0x802acf5c) */
/* WARNING: Removing unreachable block (ram,0x802acf54) */
/* WARNING: Removing unreachable block (ram,0x802acf4c) */

int FUN_802acf3c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,int param_11,float *param_12,undefined4 *param_13,
                undefined4 param_14,undefined4 param_15,int param_16)

{
  short sVar1;
  float fVar2;
  byte bVar3;
  int iVar4;
  ushort uVar5;
  bool bVar6;
  double dVar7;
  double dVar8;
  float fStack_d8;
  undefined4 local_d4;
  undefined4 local_d0;
  ushort local_cc [4];
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float afStack_b4 [16];
  undefined auStack_74 [52];
  
  local_d4 = DAT_803e8b08;
  local_d0 = DAT_803e8b0c;
  if ((((((*(char *)(param_11 + 0x8c8) == 'H') || (*(char *)(param_11 + 0x8c8) == 'G')) ||
        (bVar3 = *(byte *)(param_11 + 0x3f0), (bVar3 >> 2 & 1) != 0)) ||
       (((bVar3 >> 3 & 1) != 0 || (*(int *)(param_11 + 0x7f8) != 0)))) ||
      (((bVar3 >> 1 & 1) != 0 ||
       ((*(int *)(param_11 + 0x2d0) != 0 || ((*(byte *)(param_11 + 0x3f6) >> 6 & 1) != 0)))))) ||
     (*(short *)(param_11 + 0x274) == 0x26)) {
    bVar6 = false;
  }
  else {
    bVar6 = true;
  }
  if (((bVar6) && ((*(ushort *)(param_11 + 0x6e0) & 0x40) != 0)) &&
     (iVar4 = FUN_80080490(), iVar4 == 0)) {
    if (((*(byte *)(param_11 + 0x3f1) >> 5 & 1) == 0) &&
       ((*(byte *)(param_11 + 0x3f0) >> 4 & 1) == 0)) {
      dVar7 = (double)*(float *)(param_10 + 0x284);
      dVar8 = (double)*(float *)(param_10 + 0x280);
      local_cc[0] = *(ushort *)(param_11 + 0x484);
      local_cc[1] = 0;
      local_cc[2] = 0;
      local_c4 = FLOAT_803e8b78;
      local_c0 = FLOAT_803e8b3c;
      local_bc = FLOAT_803e8b3c;
      local_b8 = FLOAT_803e8b3c;
      FUN_80021fac(afStack_b4,local_cc);
      param_2 = (double)FLOAT_803e8b3c;
      param_3 = -dVar8;
      param_12 = (float *)(param_11 + 0x4cc);
      FUN_80022790(dVar7,param_2,param_3,afStack_b4,(float *)(param_11 + 0x4c8),&fStack_d8,param_12)
      ;
      *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0x7f;
      *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xbf;
      *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xef;
      *(byte *)(param_11 + 0x3f1) = *(byte *)(param_11 + 0x3f1) & 0xf7 | 8;
      *(short *)(param_11 + 0x484) = *(short *)(param_11 + 0x478);
      *param_9 = *(short *)(param_11 + 0x478);
      *(byte *)(param_11 + 0x3f1) = *(byte *)(param_11 + 0x3f1) & 0xdf | 0x20;
      fVar2 = FLOAT_803e8b3c;
      *(float *)(param_11 + 0x7bc) = FLOAT_803e8b3c;
      *(float *)(param_11 + 0x7b8) = fVar2;
    }
    if ((*(byte *)(param_11 + 0x3f1) >> 4 & 1) == 0) {
      FUN_80101c10(2);
      param_12 = (float *)0x8;
      param_13 = &local_d4;
      param_14 = 0x1e;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x52,1,0);
      if ((uint)(2 < DAT_803df12c - DAT_803df124) +
          (DAT_803df128 - ((uint)(DAT_803df12c < DAT_803df124) + DAT_803df120)) != 0) {
        FUN_8000bb38((uint)param_9,0x3e4);
      }
      DAT_803df124 = DAT_803df12c;
      DAT_803df120 = DAT_803df128;
      *(byte *)(param_11 + 0x3f1) = *(byte *)(param_11 + 0x3f1) & 0xef | 0x10;
    }
  }
  else {
    if ((*(byte *)(param_11 + 0x3f1) >> 5 & 1) != 0) {
      sVar1 = *param_9;
      *(short *)(param_11 + 0x484) = sVar1;
      *(short *)(param_11 + 0x478) = sVar1;
      *(int *)(param_11 + 0x494) = (int)sVar1;
      *(float *)(param_11 + 0x284) = FLOAT_803e8b3c;
    }
    *(byte *)(param_11 + 0x3f1) = *(byte *)(param_11 + 0x3f1) & 0xdf;
    if ((((*(byte *)(param_11 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(param_11 + 0x8c8) != 'H')) &&
       ((*(char *)(param_11 + 0x8c8) != 'G' && (iVar4 = FUN_80080490(), iVar4 == 0)))) {
      param_12 = (float *)0x0;
      param_13 = (undefined4 *)0x0;
      param_14 = 0x1e;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x42,0,1);
      *(byte *)(param_11 + 0x3f1) = *(byte *)(param_11 + 0x3f1) & 0xef;
    }
  }
  bVar6 = 0xfffffffe < DAT_803df12c;
  DAT_803df12c = DAT_803df12c + 1;
  DAT_803df128 = DAT_803df128 + (uint)bVar6;
  bVar3 = *(byte *)(param_11 + 0x3f0) >> 5 & 1;
  if (((bVar3 != 0) || (*(float *)(param_11 + 0x838) <= FLOAT_803e8c38)) ||
     (FLOAT_803e8d94 <= *(float *)(param_10 + 0x1b0))) {
    if (((bVar3 == 0) && ((*(byte *)(param_11 + 0x3f0) >> 3 & 1) == 0)) &&
       ((*(byte *)(param_11 + 0x3f0) >> 2 & 1) == 0)) {
      if (((*(byte *)(param_11 + 0x3f1) & 1) != 0) ||
         (*(float *)(param_10 + 0x1b0) < FLOAT_803e8bf0)) {
        *(undefined *)(param_11 + 0x40d) = 0;
      }
      else {
        *(char *)(param_11 + 0x40d) = *(char *)(param_11 + 0x40d) + '\x01';
      }
      bVar3 = *(byte *)(param_11 + 0x40d);
      if (10 < bVar3) {
        bVar3 = 10;
      }
      *(byte *)(param_11 + 0x40d) = bVar3;
      if (2 < *(byte *)(param_11 + 0x40d)) {
        *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0x7f;
        *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xef;
        *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xf7;
        FUN_8017082c();
        *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xfd;
        *(uint *)(param_11 + 0x360) = *(uint *)(param_11 + 0x360) | 0x800000;
        FUN_80035f9c((int)param_9);
        *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xbf;
        *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xfb | 4;
        *(byte *)(param_11 + 0x3f4) = *(byte *)(param_11 + 0x3f4) & 0xef;
        *(undefined *)(param_11 + 0x800) = 0;
        iVar4 = *(int *)(param_11 + 0x7f8);
        if (iVar4 != 0) {
          if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
            FUN_80182a5c(iVar4);
          }
          else {
            FUN_800ea9f8(iVar4);
          }
          *(ushort *)(*(int *)(param_11 + 0x7f8) + 6) =
               *(ushort *)(*(int *)(param_11 + 0x7f8) + 6) & 0xbfff;
          *(undefined4 *)(*(int *)(param_11 + 0x7f8) + 0xf8) = 0;
          *(undefined4 *)(param_11 + 0x7f8) = 0;
        }
        *(code **)(param_10 + 0x308) = FUN_802a58ac;
        return 3;
      }
    }
    bVar3 = *(byte *)(param_11 + 0x3f0) >> 5 & 1;
    if ((bVar3 == 0) && (FLOAT_803e8b3c != *(float *)(param_11 + 0x784))) {
      *(undefined4 *)(param_10 + 0x308) = 0;
      iVar4 = 0x42;
    }
    else {
      if ((bVar3 == 0) &&
         (((((*(byte *)(param_11 + 0x3f0) >> 3 & 1) == 0 &&
            ((*(byte *)(param_11 + 0x3f0) >> 2 & 1) == 0)) && (*(int *)(param_11 + 0x2d0) == 0)) &&
          (((*(byte *)(param_11 + 0x3f6) >> 6 & 1) == 0 && (*(short *)(param_11 + 0x274) != 0x26))))
         )) {
        bVar6 = true;
      }
      else {
        bVar6 = false;
      }
      if (((bVar6) && (*(int *)(param_11 + 0x7f8) != 0)) && (*(char *)(param_11 + 0x800) == '\0')) {
        if ((*(uint *)(param_10 + 0x310) & 0x4000) == 0) {
          *(undefined **)(param_10 + 0x308) = &LAB_802a5108;
          iVar4 = 8;
        }
        else {
          *(undefined **)(param_10 + 0x308) = &LAB_802a5108;
          iVar4 = 7;
        }
      }
      else {
        if (((((bVar3 == 0) && (bVar3 = *(byte *)(param_11 + 0x3f0), (bVar3 >> 3 & 1) == 0)) &&
             ((bVar3 >> 2 & 1) == 0)) &&
            (((bVar3 >> 1 & 1) == 0 && (*(int *)(param_11 + 0x2d0) == 0)))) &&
           (((*(byte *)(param_11 + 0x3f6) >> 6 & 1) == 0 && (*(short *)(param_11 + 0x274) != 0x26)))
           ) {
          bVar6 = true;
        }
        else {
          bVar6 = false;
        }
        if ((!bVar6) ||
           (iVar4 = FUN_802a48ec(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8),
           iVar4 == 0)) {
          if (((*(int *)(param_10 + 0x2d0) == 0) ||
              (((sVar1 = *(short *)(param_10 + 0x274), sVar1 == 0x24 || (sVar1 == 0x25)) ||
               (sVar1 == 0x26)))) ||
             (((*(byte *)(param_11 + 0x3f6) >> 5 & 1) != 0 ||
              (*(char *)(param_10 + 0x349) != '\x01')))) {
            uVar5 = FUN_80014e04(0);
            if ((uVar5 & 0x20) != 0) {
              if (((((*(byte *)(param_11 + 0x3f4) >> 6 & 1) == 0) ||
                   (bVar3 = *(byte *)(param_11 + 0x3f0), (bVar3 >> 5 & 1) != 0)) ||
                  (((bVar3 >> 3 & 1) != 0 ||
                   ((((((bVar3 >> 2 & 1) != 0 || (*(char *)(param_11 + 0x8c8) == 'D')) ||
                      (*(int *)(param_11 + 0x7f8) != 0)) ||
                     ((*(int *)(param_11 + 0x2d0) != 0 ||
                      ((*(byte *)(param_11 + 0x3f6) >> 6 & 1) != 0)))) ||
                    (*(short *)(param_11 + 0x274) == 0x26)))))) ||
                 (((param_9[0x58] & 0x1000U) != 0 ||
                  (*(float *)(param_11 + 0x880) != FLOAT_803e8b3c)))) {
                bVar6 = false;
              }
              else {
                bVar6 = true;
              }
              if ((bVar6) && ((*(byte *)(param_11 + 0x3f0) >> 1 & 1) == 0)) {
                FUN_8017082c();
                FUN_8003042c((double)*(float *)(param_9 + 0x4c),param_2,param_3,param_4,param_5,
                             param_6,param_7,param_8,param_9,0x4f,0,param_12,param_13,param_14,
                             param_15,param_16);
                FUN_8002f66c((int)param_9,8);
                if ((DAT_803df0cc != 0) && ((*(byte *)(param_11 + 0x3f4) >> 6 & 1) != 0)) {
                  *(undefined *)(param_11 + 0x8b4) = 4;
                  *(byte *)(param_11 + 0x3f4) = *(byte *)(param_11 + 0x3f4) & 0xf7 | 8;
                }
                *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xef;
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xbf;
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0x7f;
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xf7;
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xfb;
                *(undefined *)(param_11 + 0x40d) = 0;
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xfd | 2;
                *(undefined *)(param_11 + 0x800) = 0;
                iVar4 = *(int *)(param_11 + 0x7f8);
                if (iVar4 != 0) {
                  if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
                    FUN_80182a5c(iVar4);
                  }
                  else {
                    FUN_800ea9f8(iVar4);
                  }
                  *(ushort *)(*(int *)(param_11 + 0x7f8) + 6) =
                       *(ushort *)(*(int *)(param_11 + 0x7f8) + 6) & 0xbfff;
                  *(undefined4 *)(*(int *)(param_11 + 0x7f8) + 0xf8) = 0;
                  *(undefined4 *)(param_11 + 0x7f8) = 0;
                }
                FUN_80035f84((int)param_9);
                *(code **)(param_10 + 0x308) = FUN_802a58ac;
                return 3;
              }
            }
            if (((*(byte *)(param_11 + 0x3f0) >> 3 & 1) != 0) ||
               ((*(byte *)(param_11 + 0x3f0) >> 2 & 1) != 0)) {
              iVar4 = FUN_802a7c04(param_9,param_11,param_10,auStack_74,0x14);
              if (iVar4 == 0xc) {
                *(undefined4 *)(param_10 + 0x308) = 0;
                return 10;
              }
              if (iVar4 == 9) {
                if ((FLOAT_803e8bc8 + *(float *)(param_11 + 0x550) <=
                     FLOAT_803e8d98 + *(float *)(param_9 + 8)) &&
                   (FLOAT_803e8d98 + *(float *)(param_9 + 8) <=
                    *(float *)(param_11 + 0x54c) - FLOAT_803e8ba8)) {
                  FUN_80014acc((double)FLOAT_803e8b70);
                  *(code **)(param_10 + 0x308) = FUN_802a0730;
                  return 0x12;
                }
              }
            }
            if ((*(byte *)(param_11 + 0x3f0) >> 5 & 1) != 0) {
              iVar4 = FUN_802a7c04(param_9,param_11,param_10,auStack_74,0x100);
              if (iVar4 == 5) {
                DAT_803dd308 = 0xffff;
                *(undefined4 *)(param_10 + 0x308) = 0;
                return 0xc;
              }
              if ((*(float *)(param_11 + 0x838) < FLOAT_803e8c58) &&
                 ((*(byte *)(param_11 + 0x3f1) & 1) != 0)) {
                *(byte *)(param_11 + 0x3f0) = *(byte *)(param_11 + 0x3f0) & 0xdf;
              }
            }
            iVar4 = 0;
          }
          else {
            *(code **)(param_10 + 0x308) = FUN_8029d028;
            iVar4 = 0x25;
          }
        }
      }
    }
  }
  else {
    FUN_802aef9c((uint)param_9,param_11);
    iVar4 = 0;
  }
  return iVar4;
}

