// Function: FUN_8022f27c
// Entry: 8022f27c
// Size: 132 bytes

void FUN_8022f27c(int param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  puVar1 = (undefined4 *)FUN_8002b588();
  uVar2 = FUN_800394ac(param_1,0,0);
  uVar3 = FUN_800283e8(*puVar1,0);
  FUN_800541a4(uVar3,*(uint *)(iVar4 + 4) & 0xffff);
  FUN_80053f2c(uVar3,iVar4,uVar2);
  return;
}

