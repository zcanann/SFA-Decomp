// Function: FUN_8028f4b8
// Entry: 8028f4b8
// Size: 192 bytes

int FUN_8028f4b8(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  if (param_1 == (undefined4 *)0x0) {
    iVar1 = -1;
  }
  else if ((*(ushort *)(param_1 + 1) >> 6 & 7) == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_8028f380(param_1);
    iVar2 = (*(code *)param_1[0x11])(*param_1);
    *(ushort *)(param_1 + 1) = *(ushort *)(param_1 + 1) & 0xfe3f;
    *param_1 = 0;
    if ((*(byte *)(param_1 + 2) >> 4 & 1) != 0) {
      FUN_8028dcd4((int *)param_1[7]);
    }
    uVar3 = 0;
    if ((iVar1 != 0) || (iVar2 != 0)) {
      uVar3 = 1;
    }
    iVar1 = (int)(-uVar3 | uVar3) >> 0x1f;
  }
  return iVar1;
}

