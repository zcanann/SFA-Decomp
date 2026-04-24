// Function: FUN_8017b908
// Entry: 8017b908
// Size: 196 bytes

void FUN_8017b908(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(char *)(iVar3 + 5) != '\0') {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*(char *)(iVar3 + 4) == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = *(byte *)(iVar2 + 0x20) & 0x7f;
      (**(code **)(*DAT_803dca54 + 0x54))();
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,uVar1);
    }
    *(undefined *)(iVar3 + 5) = 0;
  }
  return;
}

