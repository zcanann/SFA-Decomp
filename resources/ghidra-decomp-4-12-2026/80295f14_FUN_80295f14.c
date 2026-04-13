// Function: FUN_80295f14
// Entry: 80295f14
// Size: 356 bytes

undefined4 FUN_80295f14(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (param_1 == 0) {
    uVar1 = 0;
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x24))(0,1,0);
    (**(code **)(*DAT_803dd6d4 + 0x50))(0x42,4,0,0);
    iVar2 = *(int *)(iVar3 + 0x7f0);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x3c))(iVar2,0);
      (**(code **)(*DAT_803dd6d0 + 0x28))(param_1,0);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xfff7;
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xffffefff;
      *(undefined4 *)(iVar3 + 0x7f0) = 0;
      *(undefined2 *)(param_1 + 0xa2) = 0xffff;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar3,1);
      *(code **)(iVar3 + 0x304) = FUN_802a58ac;
      FUN_8000a538((int *)0x1f,0);
      FUN_8000a538((int *)0x97,0);
      FUN_8000a538((int *)0xe6,0);
      FUN_8000a538((int *)0xd5,0);
      uVar1 = 1;
    }
  }
  return uVar1;
}

