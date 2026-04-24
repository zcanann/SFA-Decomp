// Function: FUN_8017a28c
// Entry: 8017a28c
// Size: 188 bytes

void FUN_8017a28c(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_8017a048;
  iVar1 = FUN_80019570(*(undefined4 *)(param_2 + 0x1c));
  piVar2[1] = **(int **)(iVar1 + 8);
  piVar2[2] = 100;
  *piVar2 = iVar1;
  *(undefined *)(piVar2 + 3) = *(undefined *)(param_2 + 0x20);
  *(undefined2 *)((int)piVar2 + 0xe) = *(undefined2 *)(param_2 + 0x18);
  *(undefined *)(piVar2 + 5) = 0;
  *(undefined2 *)((int)piVar2 + 0x12) = 0;
  *(undefined2 *)(piVar2 + 4) = 0;
  if ((*(short *)((int)piVar2 + 0xe) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    *(undefined *)(piVar2 + 5) = 4;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

