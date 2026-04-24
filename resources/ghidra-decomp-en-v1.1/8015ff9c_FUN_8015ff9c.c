// Function: FUN_8015ff9c
// Entry: 8015ff9c
// Size: 244 bytes

void FUN_8015ff9c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  *(undefined2 *)(iVar2 + 10) = *(undefined2 *)(param_2 + 0x18);
  if (((int)*(short *)(iVar2 + 10) == 0xffffffff) ||
     (uVar1 = FUN_80020078((int)*(short *)(iVar2 + 10)), uVar1 == 0)) {
    *(ushort *)(iVar2 + 0xc) = (ushort)*(byte *)(param_2 + 0x29) << 3;
    *(undefined2 *)(iVar2 + 8) = *(undefined2 *)(param_2 + 0x22);
    *(undefined *)(iVar2 + 0x13) = *(undefined *)(param_2 + 0x32);
    *(short *)(iVar2 + 0xe) = *(char *)(param_2 + 0x28) * 0xb6;
    *(undefined *)(iVar2 + 0x14) = *(undefined *)(param_2 + 0x2f);
    *(undefined *)(iVar2 + 0x15) = *(undefined *)(param_2 + 0x27);
    *param_1 = (short)((int)*(char *)(param_2 + 0x2a) << 8);
  }
  else {
    FUN_80035ff8((int)param_1);
    param_1[3] = param_1[3] | 0x4000;
    *(byte *)(iVar2 + 0x12) = *(byte *)(iVar2 + 0x12) | 2;
  }
  return;
}

