// Function: FUN_8021b934
// Entry: 8021b934
// Size: 196 bytes

void FUN_8021b934(int param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,0x37);
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  uVar2 = countLeadingZeros(uVar2);
  *(byte *)(iVar3 + 0x1a) = (byte)((uVar2 >> 5 & 0xff) << 7) | *(byte *)(iVar3 + 0x1a) & 0x7f;
  cVar1 = (char)*(byte *)(param_2 + 0x18) >> 7;
  *(byte *)(iVar3 + 0x1b) = (*(byte *)(param_2 + 0x18) & 1 ^ -cVar1) + cVar1;
  *(undefined **)(param_1 + 0xbc) = &LAB_8021b390;
  if (*(short *)(param_2 + 0x1c) == 1) {
    *(undefined4 *)(iVar3 + 0x14) = 2;
    *(char *)(iVar3 + 0x1c) = '\x01' - *(char *)(iVar3 + 0x1b);
  }
  else {
    *(undefined4 *)(iVar3 + 0x14) = 1;
  }
  return;
}

