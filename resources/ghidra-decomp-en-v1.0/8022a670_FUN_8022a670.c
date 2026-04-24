// Function: FUN_8022a670
// Entry: 8022a670
// Size: 856 bytes

/* WARNING: Removing unreachable block (ram,0x8022a9a0) */
/* WARNING: Removing unreachable block (ram,0x8022a998) */
/* WARNING: Removing unreachable block (ram,0x8022a9a8) */

void FUN_8022a670(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  char cVar5;
  uint uVar3;
  undefined2 uVar4;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  double local_40;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  FUN_80137520(0xff,0xff,0xff,0xff);
  cVar5 = FUN_80014cc0(0);
  *(float *)(param_2 + 0x3e4) =
       (float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) - DOUBLE_803e6ee0) /
       FLOAT_803e6ec8;
  cVar5 = FUN_80014c6c(0);
  local_40 = (double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000);
  *(float *)(param_2 + 1000) = (float)(local_40 - DOUBLE_803e6ee0) / FLOAT_803e6ec8;
  fVar1 = FLOAT_803e6ecc;
  if (FLOAT_803e6ecc < *(float *)(param_2 + 0x328)) {
    dVar10 = -(double)*(float *)(param_2 + 0x32c);
    dVar9 = -(double)*(float *)(param_2 + 0x330);
    *(float *)(param_2 + 0x328) = *(float *)(param_2 + 0x328) - FLOAT_803db414;
    dVar8 = (double)*(float *)(&DAT_8032b4a8 + (int)*(float *)(param_2 + 0x328) * 4);
    if (*(float *)(param_2 + 0x328) <= fVar1) {
      *(undefined *)(param_2 + 0x338) = 0;
      (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,param_2 + 0xc0);
    }
    dVar7 = (double)FLOAT_803e6ed0;
    *(float *)(param_2 + 0x3e4) =
         *(float *)(param_2 + 0x3e4) * (float)(dVar7 - dVar8) + (float)(dVar10 * dVar8);
    *(float *)(param_2 + 1000) =
         *(float *)(param_2 + 1000) * (float)(dVar7 - dVar8) + (float)(dVar9 * dVar8);
  }
  uVar3 = FUN_80014d58(0);
  local_40 = (double)CONCAT44(0x43300000,uVar3 & 0xff);
  *(float *)(param_2 + 0x3ec) = (float)(local_40 - DOUBLE_803e6ee8) / FLOAT_803e6ed4;
  fVar1 = *(float *)(param_2 + 0x3ec);
  fVar2 = FLOAT_803e6ecc;
  if ((FLOAT_803e6ecc <= fVar1) && (fVar2 = fVar1, FLOAT_803e6ed0 < fVar1)) {
    fVar2 = FLOAT_803e6ed0;
  }
  *(float *)(param_2 + 0x3ec) = fVar2;
  uVar3 = FUN_80014d14(0);
  *(float *)(param_2 + 0x3f0) =
       -(float)((double)CONCAT44(0x43300000,uVar3 & 0xff) - DOUBLE_803e6ee8) / FLOAT_803e6ed4;
  fVar1 = *(float *)(param_2 + 0x3f0);
  fVar2 = FLOAT_803e6ed8;
  if ((FLOAT_803e6ed8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e6ecc < fVar1)) {
    fVar2 = FLOAT_803e6ecc;
  }
  *(float *)(param_2 + 0x3f0) = fVar2;
  uVar4 = FUN_80014e70(0);
  *(undefined2 *)(param_2 + 0x3f4) = uVar4;
  uVar4 = FUN_80014e14(0);
  *(undefined2 *)(param_2 + 0x3f6) = uVar4;
  uVar4 = FUN_80014ee8(0);
  *(undefined2 *)(param_2 + 0x3f8) = uVar4;
  if (*(char *)(param_2 + 0x478) == '\0') {
    if ((*(ushort *)(param_2 + 0x3f4) & 0x20) == 0) {
      if ((*(ushort *)(param_2 + 0x3f4) & 0x40) != 0) {
        FUN_8000bb18(param_1,0x2a4);
        *(undefined *)(param_2 + 0x478) = 1;
        *(int *)(param_2 + 0x398) = (int)*(short *)(param_1 + 4);
        *(float *)(param_2 + 0x3a0) = -*(float *)(param_2 + 0x39c);
        *(float *)(param_2 + 0x3a8) = FLOAT_803e6ed0;
        *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x54) * *(float *)(param_2 + 0x3ac);
        *(float *)(param_2 + 0x60) = *(float *)(param_2 + 0x60) * *(float *)(param_2 + 0x3b0);
        FUN_8022f148(*(undefined4 *)(param_2 + 0x10),1,1);
      }
    }
    else {
      FUN_8000bb18(param_1,0x2a4);
      *(undefined *)(param_2 + 0x478) = 1;
      *(int *)(param_2 + 0x398) = (int)*(short *)(param_1 + 4);
      *(undefined4 *)(param_2 + 0x3a0) = *(undefined4 *)(param_2 + 0x39c);
      *(float *)(param_2 + 0x3a8) = FLOAT_803e6ed0;
      *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x54) * *(float *)(param_2 + 0x3ac);
      *(float *)(param_2 + 0x60) = *(float *)(param_2 + 0x60) * *(float *)(param_2 + 0x3b0);
      FUN_8022f148(*(undefined4 *)(param_2 + 0x10),1,0);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  return;
}

