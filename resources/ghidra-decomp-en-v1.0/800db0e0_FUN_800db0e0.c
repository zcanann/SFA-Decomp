// Function: FUN_800db0e0
// Entry: 800db0e0
// Size: 324 bytes

/* WARNING: Removing unreachable block (ram,0x800db204) */

void FUN_800db0e0(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  int local_38 [12];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar13 = FUN_802860d4();
  pfVar4 = (float *)((ulonglong)uVar13 >> 0x20);
  piVar5 = (int *)(**(code **)(*DAT_803dca9c + 0x10))(local_38);
  dVar12 = (double)FLOAT_803e05f8;
  iVar7 = 0;
  for (iVar9 = 0; iVar9 < local_38[0]; iVar9 = iVar9 + 1) {
    iVar8 = *piVar5;
    if ((((((iVar8 != 0) && (*(char *)(iVar8 + 0x19) == '$')) &&
          (((uint)uVar13 == 0xffffffff || ((uint)*(byte *)(iVar8 + 3) == (uint)uVar13)))) &&
         ((param_3 == -1 || (*(char *)(iVar8 + 0x1a) == param_3)))) &&
        ((*(short *)(iVar8 + 0x30) == -1 || (iVar6 = FUN_8001ffb4(), iVar6 != 0)))) &&
       (((*(short *)(iVar8 + 0x32) == -1 || (iVar6 = FUN_8001ffb4(), iVar6 == 0)) &&
        (fVar1 = *pfVar4 - *(float *)(iVar8 + 8), fVar2 = pfVar4[1] - *(float *)(iVar8 + 0xc),
        fVar3 = pfVar4[2] - *(float *)(iVar8 + 0x10),
        dVar11 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2), dVar11 < dVar12)))) {
      iVar7 = iVar8;
      dVar12 = dVar11;
    }
    piVar5 = piVar5 + 1;
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286120(iVar7);
  return;
}

