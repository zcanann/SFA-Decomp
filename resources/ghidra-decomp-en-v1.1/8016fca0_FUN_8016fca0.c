// Function: FUN_8016fca0
// Entry: 8016fca0
// Size: 320 bytes

void FUN_8016fca0(int param_1)

{
  int iVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  if (((*(short *)(param_1 + 0x46) != 0x83e) && ((*(byte *)(puVar2 + 0x1c) & 8) == 0)) &&
     (iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50), iVar1 != 0)) {
    if (*(short *)(iVar1 + 0x46) == 0x6e8) {
      iVar1 = FUN_802371d4(iVar1);
      if ((char)iVar1 != -1) {
        *(char *)((int)puVar2 + 0x71) = (char)iVar1;
        if (*puVar2 != 0) {
          iVar1 = (uint)*(byte *)((int)puVar2 + 0x71) * 3;
          FUN_8001dbb4(*puVar2,(&DAT_803215c8)[iVar1],(&DAT_803215c9)[iVar1],(&DAT_803215ca)[iVar1],
                       0);
        }
      }
      FUN_80036018(param_1);
    }
    else {
      puVar2[0xe] = (uint)FLOAT_803e3ff0;
      if (*(char *)((int)puVar2 + 0x71) == '\0') {
        FUN_800998ec(param_1,3);
      }
      else if (*(char *)((int)puVar2 + 0x71) == '\x01') {
        FUN_800998ec(param_1,0);
      }
      else {
        FUN_800998ec(param_1,6);
      }
      *(undefined *)(param_1 + 0x36) = 0;
      if (*puVar2 != 0) {
        FUN_8001f448(*puVar2);
        *puVar2 = 0;
      }
    }
    FUN_8003709c(param_1,2);
  }
  return;
}

