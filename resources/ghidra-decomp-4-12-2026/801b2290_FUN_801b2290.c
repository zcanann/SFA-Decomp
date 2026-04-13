// Function: FUN_801b2290
// Entry: 801b2290
// Size: 160 bytes

void FUN_801b2290(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 3) = 1;
  *(undefined *)(iVar2 + 2) = 0;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    *(undefined *)(iVar2 + 3) = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(param_1 + 0x1b) = 0;
    *(undefined *)(iVar2 + 2) = 2;
  }
  return;
}

