// Function: FUN_80036450
// Entry: 80036450
// Size: 360 bytes

undefined4 FUN_80036450(int param_1,int param_2,char param_3,undefined param_4,undefined param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_3 == '\0') {
    return 0;
  }
  iVar2 = *(int *)(param_1 + 0x54);
  if ((*(ushort *)(iVar2 + 0x60) & 1) == 0) {
    return 0;
  }
  if ((param_2 != 0) && (*(int *)(param_2 + 0x54) != 0)) {
    *(int *)(*(int *)(param_2 + 0x54) + 0x50) = param_1;
  }
  iVar3 = 0;
  while( true ) {
    iVar1 = (int)*(char *)(iVar2 + 0x71);
    if (iVar1 <= iVar3) break;
    iVar1 = iVar2 + iVar3 * 4;
    if (*(int *)(iVar1 + 0x7c) == param_2) {
      iVar3 = iVar2 + iVar3;
      if (param_3 < *(char *)(iVar3 + 0x75)) {
        *(undefined *)(iVar3 + 0x72) = param_5;
        *(char *)(iVar3 + 0x75) = param_3;
        *(undefined *)(iVar3 + 0x78) = param_4;
        *(undefined4 *)(iVar1 + 0x88) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(iVar1 + 0x94) = *(undefined4 *)(param_1 + 0x10);
        *(undefined4 *)(iVar1 + 0xa0) = *(undefined4 *)(param_1 + 0x14);
      }
      iVar3 = *(char *)(iVar2 + 0x71) + 1;
    }
    iVar3 = iVar3 + 1;
  }
  if ((iVar3 == iVar1) && (iVar1 < 3)) {
    *(undefined *)(iVar2 + iVar1 + 0x72) = param_5;
    *(char *)(iVar2 + *(char *)(iVar2 + 0x71) + 0x75) = param_3;
    *(undefined *)(iVar2 + *(char *)(iVar2 + 0x71) + 0x78) = param_4;
    *(int *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0x7c) = param_2;
    *(undefined4 *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0x88) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0x94) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0xa0) = *(undefined4 *)(param_1 + 0x14);
    *(char *)(iVar2 + 0x71) = *(char *)(iVar2 + 0x71) + '\x01';
  }
  return 1;
}

