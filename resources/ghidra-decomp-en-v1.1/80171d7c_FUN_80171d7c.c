// Function: FUN_80171d7c
// Entry: 80171d7c
// Size: 264 bytes

void FUN_80171d7c(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  FUN_800372f8((int)param_1,0x3e);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x2000;
  DAT_803de730 = FUN_80013ee8(0x5b);
  DAT_803de734 = FUN_80013ee8(0x5a);
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x810;
  }
  *(undefined *)(iVar2 + 10) = 2;
  *(undefined *)(iVar2 + 0xb) = *(undefined *)(param_2 + 0x19);
  if ((*(char *)(iVar2 + 0xb) == '\0') &&
     (iVar1 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(param_2 + 0x14)), iVar1 == 0)) {
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(iVar2 + 9) = 1;
    *(undefined *)(iVar2 + 8) = 0;
  }
  return;
}

