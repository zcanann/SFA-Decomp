// Function: FUN_80223a1c
// Entry: 80223a1c
// Size: 224 bytes

undefined4 FUN_80223a1c(int param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(byte *)(iVar3 + 0xac0) = *(byte *)(iVar3 + 0xac0) | 1;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
  }
  *(float *)(iVar3 + 0xabc) = *(float *)(iVar3 + 0xabc) - FLOAT_803db414;
  if (*(float *)(iVar3 + 0xab8) <= FLOAT_803e6cf0) {
    if ((FLOAT_803e6cf4 <= *(float *)(iVar3 + 0xab8)) ||
       (FLOAT_803e6cf8 < *(float *)(iVar3 + 0xabc))) {
      uVar1 = 0;
    }
    else {
      uVar2 = FUN_800221a0(0x78,0xfa);
      *(float *)(iVar3 + 0xabc) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6d00);
      uVar1 = 4;
    }
  }
  else {
    uVar1 = 2;
  }
  return uVar1;
}

