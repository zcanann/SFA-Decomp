// Function: FUN_801ecf94
// Entry: 801ecf94
// Size: 1172 bytes

/* WARNING: Removing unreachable block (ram,0x801ed3fc) */
/* WARNING: Removing unreachable block (ram,0x801ed404) */

void FUN_801ecf94(int param_1)

{
  int iVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  float fVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  undefined auStack104 [8];
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar8 = *(int *)(param_1 + 0xb8);
  iVar6 = **(int **)(param_1 + 0x54);
  if (*(int *)(param_1 + 0xc0) == 0) {
    if (*(char *)(iVar8 + 0x421) == '\x02') {
      FUN_801eb940(param_1,iVar8);
      *(undefined2 *)(iVar8 + 0x41c) = *(undefined2 *)(param_1 + 2);
      *(undefined2 *)(iVar8 + 0x41e) = *(undefined2 *)(param_1 + 4);
      dVar10 = DOUBLE_803e5b00;
      uStack92 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
      local_60 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5b00) +
                   *(float *)(iVar8 + 0x594));
      local_58 = (longlong)iVar1;
      *(short *)(param_1 + 2) = (short)iVar1;
      uStack76 = (int)*(short *)(param_1 + 4) ^ 0x80000000;
      local_50 = 0x43300000;
      uStack68 = *(uint *)(iVar8 + 0x410) ^ 0x80000000;
      local_48 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack76) - dVar10) +
                   (float)((double)CONCAT44(0x43300000,uStack68) - dVar10) +
                   *(float *)(iVar8 + 0x598));
      local_40 = (longlong)iVar1;
      *(short *)(param_1 + 4) = (short)iVar1;
    }
    if ((*(char *)(iVar8 + 0x3d9) == '\x04') || (*(char *)(iVar8 + 0x3d6) != '\0')) {
      *(float *)(param_1 + 0x28) =
           FLOAT_803db418 * (*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84));
      *(undefined4 *)(iVar8 + 0x498) = *(undefined4 *)(param_1 + 0x28);
    }
    if (((*(char *)(iVar8 + 0x3d6) != '\0') ||
        (((*(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 8) != 0 &&
         (iVar6 = FUN_8007fe74(&DAT_8032855c,10,(int)*(short *)(iVar6 + 0x46)), iVar6 == -1)))) ||
       ((*(int *)(iVar8 + 0x42c) != 0 && (*(float *)(iVar8 + 0x3e0) <= FLOAT_803e5aec)))) {
      dVar10 = (double)FUN_802477f0(param_1 + 0x24);
      if ((double)FLOAT_803e5aec < dVar10) {
        if ((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) {
          FUN_80014aa0((double)(float)((double)FLOAT_803e5bc4 * dVar10));
        }
        *(float *)(iVar8 + 0x430) = *(float *)(iVar8 + 0x430) * FLOAT_803e5bbc;
        if ((*(short *)(param_1 + 0x46) == 0x72) || (*(short *)(param_1 + 0x46) == 0x38c)) {
          uVar7 = (uint)((double)FLOAT_803e5c4c * dVar10);
          local_40 = (longlong)(int)uVar7;
          if ((int)uVar7 < 0x51) {
            if ((int)uVar7 < 0x1e) {
              uVar7 = 0x1e;
            }
          }
          else {
            uVar7 = 0x50;
          }
          iVar6 = FUN_8000b578(param_1,0x20);
          if (iVar6 == 0) {
            FUN_8000bb18(param_1,0x3bc);
            FUN_8000b99c((double)FLOAT_803e5b28,param_1,0x3bc,uVar7 & 0xff);
          }
        }
      }
      if (((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) && ((double)FLOAT_803e5bc4 < dVar10)) {
        FUN_8000fad8();
        FUN_8000e67c((double)(float)(dVar10 * (double)FLOAT_803e5af8));
      }
      fVar2 = FLOAT_803e5b88;
      if (*(int *)(iVar8 + 0x42c) == 0) {
        *(float *)(param_1 + 0x24) =
             FLOAT_803e5b88 *
             FLOAT_803db418 * (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80));
        *(float *)(param_1 + 0x2c) =
             fVar2 * FLOAT_803db418 * (*(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88));
      }
      else {
        dVar11 = (double)FLOAT_803e5c00;
        FUN_8007d6dc(dVar10,&DAT_803dc0e4);
        sVar4 = *(short *)(*(int *)(iVar8 + 0x42c) + 0x46);
        if (((sVar4 == 0x38d) || (sVar4 == 0x38e)) || (sVar4 == 0x4d4)) {
          dVar11 = (double)FLOAT_803e5b88;
        }
        *(float *)(param_1 + 0x24) =
             (float)(dVar11 * (double)(FLOAT_803db418 *
                                      (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80))));
        *(float *)(param_1 + 0x2c) =
             (float)(dVar11 * (double)(FLOAT_803db418 *
                                      (*(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88))));
      }
      FUN_800226cc((double)*(float *)(param_1 + 0x24),(double)FLOAT_803e5ae8,
                   (double)*(float *)(param_1 + 0x2c),iVar8 + 300,iVar8 + 0x494,auStack104,
                   iVar8 + 0x49c);
    }
    fVar2 = *(float *)(iVar8 + 0x494);
    fVar3 = *(float *)(iVar8 + 0x47c);
    fVar5 = -fVar3;
    if ((fVar5 <= fVar2) && (fVar5 = fVar2, fVar3 < fVar2)) {
      fVar5 = fVar3;
    }
    *(float *)(iVar8 + 0x494) = fVar5;
    if ((*(float *)(iVar8 + 0x494) < FLOAT_803e5b8c) && (FLOAT_803e5ba4 < *(float *)(iVar8 + 0x494))
       ) {
      *(float *)(iVar8 + 0x494) = FLOAT_803e5ae8;
    }
    fVar2 = *(float *)(iVar8 + 0x498);
    fVar3 = -*(float *)(iVar8 + 0x480);
    if ((fVar3 <= fVar2) && (fVar3 = fVar2, FLOAT_803e5aec < fVar2)) {
      fVar3 = FLOAT_803e5aec;
    }
    *(float *)(iVar8 + 0x498) = fVar3;
    if ((*(float *)(iVar8 + 0x498) < FLOAT_803e5b8c) && (FLOAT_803e5ba4 < *(float *)(iVar8 + 0x498))
       ) {
      *(float *)(iVar8 + 0x498) = FLOAT_803e5ae8;
    }
    fVar2 = *(float *)(iVar8 + 0x49c);
    fVar3 = *(float *)(iVar8 + 0x484);
    fVar5 = -fVar3;
    if ((fVar5 <= fVar2) && (fVar5 = fVar2, fVar3 < fVar2)) {
      fVar5 = fVar3;
    }
    *(float *)(iVar8 + 0x49c) = fVar5;
    if ((*(float *)(iVar8 + 0x49c) < FLOAT_803e5b8c) && (FLOAT_803e5ba4 < *(float *)(iVar8 + 0x49c))
       ) {
      *(float *)(iVar8 + 0x49c) = FLOAT_803e5ae8;
    }
    *(undefined4 *)(iVar8 + 0x16c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar8 + 0x170) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar8 + 0x174) = *(undefined4 *)(param_1 + 0x14);
    *(undefined4 *)(iVar8 + 0x42c) = 0;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  return;
}

