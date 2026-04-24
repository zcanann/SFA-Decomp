// Function: FUN_80162ee4
// Entry: 80162ee4
// Size: 184 bytes

void FUN_80162ee4(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = 2;
  if (param_3 != 0) {
    uVar1 = 3;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e2f28,param_1,param_2,iVar2,0,0,0,uVar1);
  *(undefined **)(param_1 + 0xbc) = &LAB_801627ec;
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar2,0);
  *(undefined2 *)(iVar2 + 0x270) = 0;
  *(float *)(iVar2 + 0x280) = FLOAT_803e2eb8;
  *(undefined4 *)(*(int *)(iVar2 + 0x40c) + 0x34) = 0;
  return;
}

