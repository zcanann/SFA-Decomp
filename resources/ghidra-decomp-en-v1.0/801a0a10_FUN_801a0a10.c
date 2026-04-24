// Function: FUN_801a0a10
// Entry: 801a0a10
// Size: 232 bytes

void FUN_801a0a10(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  
  pcVar4 = *(char **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (*pcVar4 == '\0') {
    uVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e));
    uVar1 = countLeadingZeros(uVar2);
    uVar1 = uVar1 >> 5 & 0xff;
    *pcVar4 = (char)uVar1;
    if (uVar1 != 0) {
      FUN_80037200(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != '\0') {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + -1;
    }
  }
  else {
    FUN_80098b18((double)FLOAT_803dbe78,param_1,5,0,0,0);
    uVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e));
    uVar1 = countLeadingZeros(uVar2);
    uVar1 = uVar1 >> 5 & 0xff;
    *pcVar4 = (char)uVar1;
    if (uVar1 == 0) {
      FUN_80036fa4(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != -1) {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + '\x01';
    }
  }
  return;
}

