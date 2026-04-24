// Function: FUN_8023a974
// Entry: 8023a974
// Size: 148 bytes

/* WARNING: Removing unreachable block (ram,0x8023a9e8) */

undefined4 FUN_8023a974(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  longlong lVar7;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar3 + 0x68) = FLOAT_803e74d4;
  dVar6 = (double)*(float *)(iVar3 + 0x68);
  piVar1 = (int *)FUN_8002b588();
  iVar3 = *piVar1;
  lVar7 = (longlong)(int)((double)FLOAT_803e74b4 * dVar6);
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xf8); iVar4 = iVar4 + 1) {
    iVar2 = FUN_80028424(iVar3,iVar4);
    *(char *)(iVar2 + 0x43) = (char)lVar7;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return 0;
}

