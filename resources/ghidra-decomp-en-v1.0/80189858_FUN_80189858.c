// Function: FUN_80189858
// Entry: 80189858
// Size: 348 bytes

void FUN_80189858(int param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(iVar4 + 0x24) != -1) {
    uVar2 = FUN_8001ffb4();
    *(byte *)(param_2 + 0x1d) =
         (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)(param_2 + 0x1d) & 0xdf;
    bVar1 = *(byte *)(param_2 + 0x1d) >> 5 & 1;
    if ((bVar1 == 0) || (*(char *)(iVar4 + 0x1c) != '\x05')) {
      if (bVar1 == 0) {
        *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0xbf;
      }
    }
    else {
      *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0xbf | 0x40;
    }
  }
  if (*(char *)(param_2 + 0x1d) < '\0') {
    if ((*(short *)(iVar4 + 0x22) != -1) && (iVar4 = FUN_8001ffb4(), iVar4 == 0)) {
      *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0x7f;
    }
  }
  else if ((*(short *)(iVar4 + 0x22) != -1) && (iVar4 = FUN_8001ffb4(), iVar4 != 0)) {
    *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0x7f | 0x80;
  }
  puVar3 = (undefined4 *)FUN_800394ac(param_1,0,0);
  if (puVar3 != (undefined4 *)0x0) {
    if ((char)*(byte *)(param_2 + 0x1d) < '\0') {
      if ((*(byte *)(param_2 + 0x1d) >> 5 & 1) == 0) {
        *puVar3 = 0x100;
      }
      else {
        *puVar3 = 0x200;
      }
    }
    else {
      *puVar3 = 0;
    }
  }
  return;
}

