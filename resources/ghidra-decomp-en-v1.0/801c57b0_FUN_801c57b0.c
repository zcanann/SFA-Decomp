// Function: FUN_801c57b0
// Entry: 801c57b0
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x801c590c) */

void FUN_801c57b0(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double in_f31;
  float **local_28 [4];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  iVar5 = *(int *)(param_1 + 0x4c);
  FUN_80035df4(param_1,9,1,0);
  iVar3 = FUN_8002e0b4(*(undefined4 *)(param_1 + 0xf8));
  if (iVar3 == 0) {
    FUN_80137948(s_WARNING_Water_Spike___d__as_inva_803261d8,*(undefined4 *)(iVar5 + 0x14));
    iVar3 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,local_28,0,0);
    if ((iVar3 != 0) && (in_f31 = (double)FLOAT_803e4f80, 0 < iVar3)) {
      do {
        if ((*(char *)(*local_28[0] + 5) == '\x0e') &&
           (dVar7 = (double)(**local_28[0] - *(float *)(param_1 + 0x10)), in_f31 < dVar7)) {
          in_f31 = dVar7;
        }
        local_28[0] = local_28[0] + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else {
    dVar7 = (double)FUN_801948c0(iVar3,3);
    in_f31 = (double)(float)(dVar7 - (double)*(float *)(param_1 + 0x10));
  }
  fVar1 = (float)((double)*(float *)(param_1 + 0x10) + in_f31);
  fVar2 = *(float *)(iVar5 + 0xc);
  if (fVar1 <= fVar2) {
    *(float *)(param_1 + 0x10) = fVar1;
    *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803db410;
    if (*(int *)(param_1 + 0xf4) < 1) {
      uVar4 = FUN_800221a0(0x3c,0xf0);
      *(undefined4 *)(param_1 + 0xf4) = uVar4;
      if ((double)FLOAT_803e4f84 == in_f31) {
        (**(code **)(*DAT_803dca98 + 0x14))
                  ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                   (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e4f88,0,3);
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = fVar2;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

