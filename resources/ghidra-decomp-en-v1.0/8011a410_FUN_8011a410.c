// Function: FUN_8011a410
// Entry: 8011a410
// Size: 216 bytes

void FUN_8011a410(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = 0;
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_1 + 1); iVar3 = iVar3 + 1) {
    DAT_803dd6b0 = DAT_803dd6a8;
    if (*(char *)(DAT_803dd6a8 + iVar1 + 0x20) == '\0') {
      *(undefined2 *)(*param_1 + iVar2) = 0x39d;
      iVar4 = iVar2 + 0x16;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) & 0xfffe;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) | 2;
      *(undefined4 *)(*param_1 + iVar2 + 0x10) = 0xffffffff;
    }
    else {
      *(short *)(*param_1 + iVar2) = (short)iVar3;
      iVar4 = iVar2 + 0x16;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) & 0xfffd;
      *(ushort *)(*param_1 + iVar4) = *(ushort *)(*param_1 + iVar4) | 1;
      *(undefined4 *)(*param_1 + iVar2 + 0x10) = 0xffffffff;
    }
    iVar1 = iVar1 + 0x24;
    iVar2 = iVar2 + 0x3c;
  }
  return;
}

