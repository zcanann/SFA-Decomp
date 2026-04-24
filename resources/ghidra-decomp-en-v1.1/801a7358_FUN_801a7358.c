// Function: FUN_801a7358
// Entry: 801a7358
// Size: 204 bytes

void FUN_801a7358(int param_1)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((pcVar3[1] & 1U) != 0) {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*pcVar3 == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = (uint)*(byte *)(iVar2 + 0x20);
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,uVar1);
    }
    pcVar3[1] = pcVar3[1] & 0xfe;
  }
  return;
}

