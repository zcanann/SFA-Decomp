// Function: FUN_80282d24
// Entry: 80282d24
// Size: 160 bytes

uint FUN_80282d24(int param_1,undefined4 param_2)

{
  byte bVar2;
  uint uVar1;
  
  bVar2 = FUN_80282cb4(param_2);
  if (bVar2 == 0xa1) {
    uVar1 = *(short *)(param_1 + 0x1d0) * 2 + 0x2000;
  }
  else if ((bVar2 < 0xa1) && (0x9f < bVar2)) {
    uVar1 = *(short *)(param_1 + 0x1c4) * 2 + 0x2000;
  }
  else if (*(char *)(param_1 + 0x121) == -1) {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_80281b24(param_2,*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122));
    uVar1 = uVar1 & 0xffff;
  }
  return uVar1;
}

