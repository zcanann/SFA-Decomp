// Function: FUN_801914ac
// Entry: 801914ac
// Size: 428 bytes

void FUN_801914ac(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (DAT_803dceb8 < 0) {
    if ((*(char *)(*(int *)(param_1 + 0x4c) + 0x1a) == -1) || ((*(byte *)(iVar2 + 0xe) & 0x20) != 0)
       ) {
      if ((*(byte *)(iVar2 + 0xe) & 0x40) == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) & 0xfe;
    }
    else {
      if ((*(char *)(iVar2 + 0xd) == '\0') && (*(char *)(iVar2 + 0xc) == '\0')) {
        if ((*(short *)(*(int *)(param_1 + 0x4c) + 0x20) == -1) ||
           (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xe7;
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 1;
        }
        else {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) & 0xfe;
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) & 0xfe;
      }
      if (*(int *)(param_1 + 0x74) != 0) {
        FUN_80041018(param_1);
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xe7;
    *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 1;
    if (*(int *)(param_1 + 0x74) != 0) {
      FUN_80041018();
    }
  }
  return;
}

