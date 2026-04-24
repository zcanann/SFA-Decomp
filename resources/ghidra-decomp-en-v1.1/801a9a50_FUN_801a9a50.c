// Function: FUN_801a9a50
// Entry: 801a9a50
// Size: 248 bytes

undefined4 FUN_801a9a50(int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  char *pcVar3;
  undefined *puVar4;
  int iVar5;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  uVar2 = 0;
  if (param_2 == 0) {
    if ((pcVar3[1] & 2U) != 0) {
      *pcVar3 = '\x03';
      pcVar3[0xc] = '\0';
      pcVar3[0xd] = '\0';
    }
    uVar2 = 1;
  }
  else if ((param_2 == 1) && (*pcVar3 == '\x03')) {
    uVar2 = 1;
    uVar1 = FUN_80020078((int)*(short *)(pcVar3 + 8));
    if ((uVar1 != 0) && (uVar1 = FUN_80020078((int)*(short *)(pcVar3 + 10)), uVar1 == 0)) {
      puVar4 = *(undefined **)(param_1 + 0xb8);
      iVar5 = *(int *)(param_1 + 0x4c);
      uVar1 = FUN_80020078((int)*(short *)(puVar4 + 8));
      if (uVar1 != 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        FUN_800201ac((int)*(short *)(puVar4 + 10),1);
        *puVar4 = 4;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
      }
    }
  }
  return uVar2;
}

