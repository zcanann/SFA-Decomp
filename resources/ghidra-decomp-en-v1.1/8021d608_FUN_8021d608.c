// Function: FUN_8021d608
// Entry: 8021d608
// Size: 312 bytes

undefined4 FUN_8021d608(int param_1,uint *param_2)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(undefined *)(iVar3 + 0xc4b) = 3;
    *param_2 = *param_2 | 0x1000000;
  }
  uVar1 = FUN_80020078(0x1c3);
  if (uVar1 == 0) {
    *(undefined *)(iVar3 + 0xc4b) = 3;
  }
  else {
    uVar1 = FUN_80020078(0xee);
    if (uVar1 == 2) {
      *(undefined *)(iVar3 + 0xc4b) = 7;
    }
    else {
      *(undefined *)(iVar3 + 0xc4b) = 9;
    }
  }
  iVar3 = FUN_8002bac4();
  dVar4 = (double)FUN_800217c8((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18));
  if (((double)FLOAT_803e773c < dVar4) && (uVar1 = FUN_8008038c(500), uVar1 != 0)) {
    uVar1 = FUN_80022264(0,100);
    iVar3 = 0;
    for (piVar2 = &DAT_8032b794; *piVar2 < (int)uVar1; piVar2 = piVar2 + 1) {
      uVar1 = uVar1 - (&DAT_8032b794)[iVar3];
      iVar3 = iVar3 + 1;
    }
    (**(code **)(*DAT_803dd6d4 + 0x48))((&DAT_8032b788)[iVar3],param_1,0xffffffff);
  }
  return 0;
}

