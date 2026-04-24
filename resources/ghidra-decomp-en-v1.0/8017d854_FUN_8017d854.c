// Function: FUN_8017d854
// Entry: 8017d854
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x8017dad0) */

void FUN_8017d854(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined2 uVar5;
  int iVar4;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar6 = *(int *)(param_1 + 0xb8);
  if (param_2 == 1) {
    uVar5 = 2;
  }
  else {
    if (param_2 < 1) {
      if (-1 < param_2) {
        uVar5 = 2;
        goto LAB_8017d8b8;
      }
    }
    else if (param_2 < 3) {
      uVar5 = 2;
      goto LAB_8017d8b8;
    }
    uVar5 = 0;
  }
LAB_8017d8b8:
  *(undefined2 *)(iVar6 + 0x38) = uVar5;
  *(undefined *)(iVar6 + 0x3a) = 4;
  *(float *)(iVar6 + 8) = FLOAT_803db414;
  *(float *)(iVar6 + 0xc) = FLOAT_803db414;
  uVar5 = FUN_800221a0(0xffff8000,0x7fff);
  *(undefined2 *)(iVar6 + 0x48) = uVar5;
  uVar5 = FUN_800221a0(0xffff8000,0x7fff);
  *(undefined2 *)(iVar6 + 0x4a) = uVar5;
  *(undefined2 *)(iVar6 + 0x4c) = 0x2000;
  iVar4 = FUN_80065684((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,iVar6 + 0x30,0);
  if (iVar4 == 0) {
    iVar6 = *(int *)(param_1 + 0xb8);
    if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
      if (*(int *)(param_1 + 0x54) != 0) {
        FUN_80035f00(param_1);
      }
      *(byte *)(iVar6 + 0x5a) = *(byte *)(iVar6 + 0x5a) | 2;
    }
    else {
      FUN_8002cbc4(param_1);
    }
  }
  else {
    dVar9 = (double)*(float *)(iVar6 + 0x40);
    dVar8 = (double)FUN_802931a0(-(double)((float)((double)FLOAT_803e37d8 * dVar9) *
                                           *(float *)(iVar6 + 0x30) - FLOAT_803e37d4));
    fVar1 = (float)((double)FLOAT_803e37dc * dVar9);
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e37d4) {
      fVar2 = -fVar1;
    }
    fVar3 = FLOAT_803e37c8;
    if (FLOAT_803e37e0 < fVar2) {
      fVar2 = (float)((double)FLOAT_803e37e4 - dVar8) / fVar1;
      fVar3 = (float)((double)FLOAT_803e37e4 + dVar8) / fVar1;
      if (FLOAT_803e37d4 < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(iVar6 + 0x50) = fVar3;
    if (FLOAT_803e37d4 <= *(float *)(iVar6 + 0x28)) {
      *(float *)(iVar6 + 0x30) =
           FLOAT_803e37e8 * FLOAT_803e37d8 * *(float *)(iVar6 + 0x24) + *(float *)(iVar6 + 0x30);
    }
    else {
      *(float *)(iVar6 + 0x30) =
           -(FLOAT_803e37d8 * *(float *)(iVar6 + 0x24) - *(float *)(iVar6 + 0x30));
    }
    if (FLOAT_803e37d4 < *(float *)(iVar6 + 0x30)) {
      *(undefined4 *)(iVar6 + 0x2c) = *(undefined4 *)(param_1 + 0x10);
      *(float *)(iVar6 + 0x34) = *(float *)(param_1 + 0x10) - *(float *)(iVar6 + 0x30);
      if (*(int *)(param_1 + 0x54) != 0) {
        FUN_80035f00(param_1);
      }
      FUN_8000bb18(param_1,0x52);
    }
    else {
      iVar6 = *(int *)(param_1 + 0xb8);
      if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
        if (*(int *)(param_1 + 0x54) != 0) {
          FUN_80035f00(param_1);
        }
        *(byte *)(iVar6 + 0x5a) = *(byte *)(iVar6 + 0x5a) | 2;
      }
      else {
        FUN_8002cbc4(param_1);
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

