// Function: FUN_801638bc
// Entry: 801638bc
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x80163958) */

int FUN_801638bc(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  int local_28 [2];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar7 = (double)FLOAT_803e2f58;
  iVar3 = 0;
  piVar1 = (int *)FUN_80036f50(0x31,local_28);
  for (iVar4 = 0; iVar4 < local_28[0]; iVar4 = iVar4 + 1) {
    iVar2 = *piVar1;
    if (((*(short *)(iVar2 + 0x46) == 0x3fb) && (1 < *(byte *)(*(int *)(iVar2 + 0xb8) + 0x278))) &&
       (dVar6 = (double)FUN_800216d0(iVar2 + 0x18,param_1), dVar6 < dVar7)) {
      iVar3 = *piVar1;
      dVar7 = dVar6;
    }
    piVar1 = piVar1 + 1;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return iVar3;
}

