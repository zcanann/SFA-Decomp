// Function: FUN_802ac7dc
// Entry: 802ac7dc
// Size: 2600 bytes

/* WARNING: Removing unreachable block (ram,0x802ad1d4) */
/* WARNING: Removing unreachable block (ram,0x802ad1cc) */
/* WARNING: Removing unreachable block (ram,0x802ad1dc) */

int FUN_802ac7dc(undefined8 param_1,short *param_2,int param_3,int param_4)

{
  short sVar1;
  float fVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  bool bVar6;
  undefined4 uVar7;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack216 [4];
  undefined4 local_d4;
  undefined4 local_d0;
  undefined2 local_cc;
  undefined2 local_ca;
  undefined2 local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  undefined auStack180 [64];
  undefined auStack116 [52];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  local_d4 = DAT_803e7e70;
  local_d0 = DAT_803e7e74;
  if ((((((*(char *)(param_4 + 0x8c8) == 'H') || (*(char *)(param_4 + 0x8c8) == 'G')) ||
        (bVar3 = *(byte *)(param_4 + 0x3f0), (bVar3 >> 2 & 1) != 0)) ||
       (((bVar3 >> 3 & 1) != 0 || (*(int *)(param_4 + 0x7f8) != 0)))) ||
      (((bVar3 >> 1 & 1) != 0 ||
       ((*(int *)(param_4 + 0x2d0) != 0 || ((*(byte *)(param_4 + 0x3f6) >> 6 & 1) != 0)))))) ||
     (*(short *)(param_4 + 0x274) == 0x26)) {
    bVar6 = false;
  }
  else {
    bVar6 = true;
  }
  if (((bVar6) && ((*(ushort *)(param_4 + 0x6e0) & 0x40) != 0)) &&
     (iVar4 = FUN_80080204(), iVar4 == 0)) {
    if (((*(byte *)(param_4 + 0x3f1) >> 5 & 1) == 0) && ((*(byte *)(param_4 + 0x3f0) >> 4 & 1) == 0)
       ) {
      dVar8 = (double)*(float *)(param_3 + 0x284);
      dVar9 = (double)*(float *)(param_3 + 0x280);
      local_cc = *(undefined2 *)(param_4 + 0x484);
      local_ca = 0;
      local_c8 = 0;
      local_c4 = FLOAT_803e7ee0;
      local_c0 = FLOAT_803e7ea4;
      local_bc = FLOAT_803e7ea4;
      local_b8 = FLOAT_803e7ea4;
      FUN_80021ee8(auStack180,&local_cc);
      FUN_800226cc(dVar8,(double)FLOAT_803e7ea4,-dVar9,auStack180,param_4 + 0x4c8,auStack216,
                   param_4 + 0x4cc);
      *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0x7f;
      *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xbf;
      *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xef;
      *(byte *)(param_4 + 0x3f1) = *(byte *)(param_4 + 0x3f1) & 0xf7 | 8;
      *(short *)(param_4 + 0x484) = *(short *)(param_4 + 0x478);
      *param_2 = *(short *)(param_4 + 0x478);
      *(byte *)(param_4 + 0x3f1) = *(byte *)(param_4 + 0x3f1) & 0xdf | 0x20;
      fVar2 = FLOAT_803e7ea4;
      *(float *)(param_4 + 0x7bc) = FLOAT_803e7ea4;
      *(float *)(param_4 + 0x7b8) = fVar2;
    }
    if ((*(byte *)(param_4 + 0x3f1) >> 4 & 1) == 0) {
      FUN_80101974(2);
      (**(code **)(*DAT_803dca50 + 0x1c))(0x52,1,0,8,&local_d4,0x1e,0xff);
      if ((uint)(2 < DAT_803de4ac - DAT_803de4a4) +
          (DAT_803de4a8 - ((uint)(DAT_803de4ac < DAT_803de4a4) + DAT_803de4a0)) != 0) {
        FUN_8000bb18(param_2,0x3e4);
      }
      DAT_803de4a4 = DAT_803de4ac;
      DAT_803de4a0 = DAT_803de4a8;
      *(byte *)(param_4 + 0x3f1) = *(byte *)(param_4 + 0x3f1) & 0xef | 0x10;
    }
  }
  else {
    if ((*(byte *)(param_4 + 0x3f1) >> 5 & 1) != 0) {
      sVar1 = *param_2;
      *(short *)(param_4 + 0x484) = sVar1;
      *(short *)(param_4 + 0x478) = sVar1;
      *(int *)(param_4 + 0x494) = (int)sVar1;
      *(float *)(param_4 + 0x284) = FLOAT_803e7ea4;
    }
    *(byte *)(param_4 + 0x3f1) = *(byte *)(param_4 + 0x3f1) & 0xdf;
    if ((((*(byte *)(param_4 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(param_4 + 0x8c8) != 'H')) &&
       ((*(char *)(param_4 + 0x8c8) != 'G' && (iVar4 = FUN_80080204(), iVar4 == 0)))) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
      *(byte *)(param_4 + 0x3f1) = *(byte *)(param_4 + 0x3f1) & 0xef;
    }
  }
  bVar6 = 0xfffffffe < DAT_803de4ac;
  DAT_803de4ac = DAT_803de4ac + 1;
  DAT_803de4a8 = DAT_803de4a8 + (uint)bVar6;
  bVar3 = *(byte *)(param_4 + 0x3f0) >> 5 & 1;
  if (((bVar3 != 0) || (*(float *)(param_4 + 0x838) <= FLOAT_803e7fa0)) ||
     (FLOAT_803e80fc <= *(float *)(param_3 + 0x1b0))) {
    if (((bVar3 == 0) && ((*(byte *)(param_4 + 0x3f0) >> 3 & 1) == 0)) &&
       ((*(byte *)(param_4 + 0x3f0) >> 2 & 1) == 0)) {
      if (((*(byte *)(param_4 + 0x3f1) & 1) != 0) || (*(float *)(param_3 + 0x1b0) < FLOAT_803e7f58))
      {
        *(undefined *)(param_4 + 0x40d) = 0;
      }
      else {
        *(char *)(param_4 + 0x40d) = *(char *)(param_4 + 0x40d) + '\x01';
      }
      bVar3 = *(byte *)(param_4 + 0x40d);
      if (10 < bVar3) {
        bVar3 = 10;
      }
      *(byte *)(param_4 + 0x40d) = bVar3;
      if (2 < *(byte *)(param_4 + 0x40d)) {
        *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0x7f;
        *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xef;
        *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xf7;
        FUN_80170380(DAT_803de450,2);
        *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xfd;
        *(uint *)(param_4 + 0x360) = *(uint *)(param_4 + 0x360) | 0x800000;
        FUN_80035ea4(param_2);
        *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xbf;
        *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xfb | 4;
        *(byte *)(param_4 + 0x3f4) = *(byte *)(param_4 + 0x3f4) & 0xef;
        *(undefined *)(param_4 + 0x800) = 0;
        if (*(int *)(param_4 + 0x7f8) != 0) {
          sVar1 = *(short *)(*(int *)(param_4 + 0x7f8) + 0x46);
          if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
            FUN_80182504();
          }
          else {
            FUN_800ea774();
          }
          *(ushort *)(*(int *)(param_4 + 0x7f8) + 6) =
               *(ushort *)(*(int *)(param_4 + 0x7f8) + 6) & 0xbfff;
          *(undefined4 *)(*(int *)(param_4 + 0x7f8) + 0xf8) = 0;
          *(undefined4 *)(param_4 + 0x7f8) = 0;
        }
        *(code **)(param_3 + 0x308) = FUN_802a514c;
        iVar4 = 3;
        goto LAB_802ad1cc;
      }
    }
    bVar3 = *(byte *)(param_4 + 0x3f0) >> 5 & 1;
    if ((bVar3 == 0) && (FLOAT_803e7ea4 != *(float *)(param_4 + 0x784))) {
      *(undefined4 *)(param_3 + 0x308) = 0;
      iVar4 = 0x42;
    }
    else {
      if ((bVar3 == 0) &&
         (((((*(byte *)(param_4 + 0x3f0) >> 3 & 1) == 0 &&
            ((*(byte *)(param_4 + 0x3f0) >> 2 & 1) == 0)) && (*(int *)(param_4 + 0x2d0) == 0)) &&
          (((*(byte *)(param_4 + 0x3f6) >> 6 & 1) == 0 && (*(short *)(param_4 + 0x274) != 0x26))))))
      {
        bVar6 = true;
      }
      else {
        bVar6 = false;
      }
      if (((bVar6) && (*(int *)(param_4 + 0x7f8) != 0)) && (*(char *)(param_4 + 0x800) == '\0')) {
        if ((*(uint *)(param_3 + 0x310) & 0x4000) == 0) {
          *(undefined **)(param_3 + 0x308) = &LAB_802a49a8;
          iVar4 = 8;
        }
        else {
          *(undefined **)(param_3 + 0x308) = &LAB_802a49a8;
          iVar4 = 7;
        }
      }
      else {
        if (((((bVar3 == 0) && (bVar3 = *(byte *)(param_4 + 0x3f0), (bVar3 >> 3 & 1) == 0)) &&
             ((bVar3 >> 2 & 1) == 0)) &&
            (((bVar3 >> 1 & 1) == 0 && (*(int *)(param_4 + 0x2d0) == 0)))) &&
           (((*(byte *)(param_4 + 0x3f6) >> 6 & 1) == 0 && (*(short *)(param_4 + 0x274) != 0x26))))
        {
          bVar6 = true;
        }
        else {
          bVar6 = false;
        }
        if ((!bVar6) || (iVar4 = FUN_802a418c(param_1,param_2,param_3), iVar4 == 0)) {
          if (((*(int *)(param_3 + 0x2d0) == 0) ||
              (((sVar1 = *(short *)(param_3 + 0x274), sVar1 == 0x24 || (sVar1 == 0x25)) ||
               (sVar1 == 0x26)))) ||
             (((*(byte *)(param_4 + 0x3f6) >> 5 & 1) != 0 || (*(char *)(param_3 + 0x349) != '\x01'))
             )) {
            uVar5 = FUN_80014dd8(0);
            if ((uVar5 & 0x20) != 0) {
              if (((((*(byte *)(param_4 + 0x3f4) >> 6 & 1) == 0) ||
                   (bVar3 = *(byte *)(param_4 + 0x3f0), (bVar3 >> 5 & 1) != 0)) ||
                  (((bVar3 >> 3 & 1) != 0 ||
                   ((((((bVar3 >> 2 & 1) != 0 || (*(char *)(param_4 + 0x8c8) == 'D')) ||
                      (*(int *)(param_4 + 0x7f8) != 0)) ||
                     ((*(int *)(param_4 + 0x2d0) != 0 ||
                      ((*(byte *)(param_4 + 0x3f6) >> 6 & 1) != 0)))) ||
                    (*(short *)(param_4 + 0x274) == 0x26)))))) ||
                 (((param_2[0x58] & 0x1000U) != 0 || (*(float *)(param_4 + 0x880) != FLOAT_803e7ea4)
                  ))) {
                bVar6 = false;
              }
              else {
                bVar6 = true;
              }
              if ((bVar6) && ((*(byte *)(param_4 + 0x3f0) >> 1 & 1) == 0)) {
                FUN_80170380(DAT_803de450,1);
                FUN_80030334((double)*(float *)(param_2 + 0x4c),param_2,0x4f,0);
                FUN_8002f574(param_2,8);
                if ((DAT_803de44c != 0) && ((*(byte *)(param_4 + 0x3f4) >> 6 & 1) != 0)) {
                  *(undefined *)(param_4 + 0x8b4) = 4;
                  *(byte *)(param_4 + 0x3f4) = *(byte *)(param_4 + 0x3f4) & 0xf7 | 8;
                }
                *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xef;
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xbf;
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0x7f;
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xf7;
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xfb;
                *(undefined *)(param_4 + 0x40d) = 0;
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xfd | 2;
                *(undefined *)(param_4 + 0x800) = 0;
                if (*(int *)(param_4 + 0x7f8) != 0) {
                  sVar1 = *(short *)(*(int *)(param_4 + 0x7f8) + 0x46);
                  if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
                    FUN_80182504();
                  }
                  else {
                    FUN_800ea774();
                  }
                  *(ushort *)(*(int *)(param_4 + 0x7f8) + 6) =
                       *(ushort *)(*(int *)(param_4 + 0x7f8) + 6) & 0xbfff;
                  *(undefined4 *)(*(int *)(param_4 + 0x7f8) + 0xf8) = 0;
                  *(undefined4 *)(param_4 + 0x7f8) = 0;
                }
                FUN_80035e8c(param_2);
                *(code **)(param_3 + 0x308) = FUN_802a514c;
                iVar4 = 3;
                goto LAB_802ad1cc;
              }
            }
            if (((*(byte *)(param_4 + 0x3f0) >> 3 & 1) != 0) ||
               ((*(byte *)(param_4 + 0x3f0) >> 2 & 1) != 0)) {
              iVar4 = FUN_802a74a4(param_1,param_2,param_4,param_3,auStack116,0x14);
              if (iVar4 == 0xc) {
                *(undefined4 *)(param_3 + 0x308) = 0;
                iVar4 = 10;
                goto LAB_802ad1cc;
              }
              if (iVar4 == 9) {
                if ((FLOAT_803e7f30 + *(float *)(param_4 + 0x550) <=
                     FLOAT_803e8100 + *(float *)(param_2 + 8)) &&
                   (FLOAT_803e8100 + *(float *)(param_2 + 8) <=
                    *(float *)(param_4 + 0x54c) - FLOAT_803e7f10)) {
                  FUN_80014aa0((double)FLOAT_803e7ed8);
                  *(code **)(param_3 + 0x308) = FUN_8029ffd0;
                  iVar4 = 0x12;
                  goto LAB_802ad1cc;
                }
              }
            }
            if ((*(byte *)(param_4 + 0x3f0) >> 5 & 1) != 0) {
              iVar4 = FUN_802a74a4((double)FLOAT_803e7ee0,param_2,param_4,param_3,auStack116,0x100);
              if (iVar4 == 5) {
                DAT_803dc6a0 = 0xffff;
                *(undefined4 *)(param_3 + 0x308) = 0;
                iVar4 = 0xc;
                goto LAB_802ad1cc;
              }
              if ((*(float *)(param_4 + 0x838) < FLOAT_803e7fc0) &&
                 ((*(byte *)(param_4 + 0x3f1) & 1) != 0)) {
                *(byte *)(param_4 + 0x3f0) = *(byte *)(param_4 + 0x3f0) & 0xdf;
              }
            }
            iVar4 = 0;
          }
          else {
            *(code **)(param_3 + 0x308) = FUN_8029c8c8;
            iVar4 = 0x25;
          }
        }
      }
    }
  }
  else {
    FUN_802ae83c(param_2,param_4,param_3);
    iVar4 = 0;
  }
LAB_802ad1cc:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  return iVar4;
}

