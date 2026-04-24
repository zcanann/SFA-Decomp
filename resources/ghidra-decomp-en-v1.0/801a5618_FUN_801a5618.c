// Function: FUN_801a5618
// Entry: 801a5618
// Size: 232 bytes

void FUN_801a5618(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar3 + 0x69) == '\x01') && (iVar2 = FUN_801a5298(param_1,iVar3), iVar2 != 0)) {
    *(undefined *)(iVar3 + 0x69) = 0;
  }
  if (*(int *)(iVar3 + 0x5c) != -1) {
    iVar2 = *(int *)(iVar3 + 0x58) + (uint)DAT_803db410;
    *(int *)(iVar3 + 0x58) = iVar2;
    if (*(int *)(iVar3 + 0x5c) <= iVar2) {
      *(undefined4 *)(iVar3 + 0x5c) = 0xffffffff;
      *(undefined *)(param_1 + 0x36) = 0;
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      bVar1 = true;
      goto LAB_801a56d8;
    }
    iVar2 = *(int *)(iVar3 + 0x5c) - *(int *)(iVar3 + 0x58);
    if (iVar2 < 0xff) {
      *(char *)(param_1 + 0x36) = (char)iVar2;
    }
  }
  bVar1 = false;
LAB_801a56d8:
  if (bVar1) {
    *(undefined *)(iVar3 + 0x69) = 2;
  }
  return;
}

