// Function: FUN_801c0f60
// Entry: 801c0f60
// Size: 172 bytes

void FUN_801c0f60(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_80035eec(param_1,0,0,0);
  FUN_80035a6c(param_1,0);
  FUN_80035ff8(param_1);
  if (param_3 == 0) {
    uVar1 = FUN_80022264(0xf0,0x1e0);
    *(float *)(iVar2 + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5a60);
    uVar1 = FUN_80022264(0,9);
    *(char *)(iVar2 + 1) = (char)uVar1;
  }
  return;
}

