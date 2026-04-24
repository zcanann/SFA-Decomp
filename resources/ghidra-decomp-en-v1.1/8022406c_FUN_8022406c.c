// Function: FUN_8022406c
// Entry: 8022406c
// Size: 224 bytes

undefined4 FUN_8022406c(int param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(byte *)(iVar3 + 0xac0) = *(byte *)(iVar3 + 0xac0) | 1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
  }
  *(float *)(iVar3 + 0xabc) = *(float *)(iVar3 + 0xabc) - FLOAT_803dc074;
  if (*(float *)(iVar3 + 0xab8) <= FLOAT_803e7988) {
    if ((*(float *)(iVar3 + 0xab8) < FLOAT_803e798c) &&
       (*(float *)(iVar3 + 0xabc) <= FLOAT_803e7990)) {
      uVar2 = FUN_80022264(0x78,0xfa);
      *(float *)(iVar3 + 0xabc) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e7998);
      return 4;
    }
    uVar1 = 0;
  }
  else {
    uVar1 = 2;
  }
  return uVar1;
}

