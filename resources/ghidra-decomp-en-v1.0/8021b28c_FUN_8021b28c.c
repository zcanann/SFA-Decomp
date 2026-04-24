// Function: FUN_8021b28c
// Entry: 8021b28c
// Size: 196 bytes

void FUN_8021b28c(int param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  FUN_80037200(param_1,0x37);
  uVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  uVar2 = countLeadingZeros(uVar3);
  *(byte *)(iVar4 + 0x1a) = (byte)((uVar2 >> 5 & 0xff) << 7) | *(byte *)(iVar4 + 0x1a) & 0x7f;
  cVar1 = (char)*(byte *)(param_2 + 0x18) >> 7;
  *(byte *)(iVar4 + 0x1b) = (*(byte *)(param_2 + 0x18) & 1 ^ -cVar1) + cVar1;
  *(undefined **)(param_1 + 0xbc) = &LAB_8021ace8;
  if (*(short *)(param_2 + 0x1c) == 1) {
    *(undefined4 *)(iVar4 + 0x14) = 2;
    *(char *)(iVar4 + 0x1c) = '\x01' - *(char *)(iVar4 + 0x1b);
  }
  else {
    *(undefined4 *)(iVar4 + 0x14) = 1;
  }
  return;
}

