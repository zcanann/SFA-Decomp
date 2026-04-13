// Function: FUN_80296164
// Entry: 80296164
// Size: 296 bytes

uint FUN_80296164(int param_1,undefined4 param_2)

{
  short sVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  switch(param_2) {
  default:
    return 0;
  case 1:
    if (((*(uint *)(iVar4 + 0x310) & 0x1000) == 0) && ((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0))
    {
      return 1;
    }
    return 0;
  case 2:
    break;
  case 9:
    uVar2 = countLeadingZeros(3 - *(char *)(iVar4 + 0x34d));
    return uVar2 >> 5;
  case 10:
    return *(uint *)(iVar4 + 0x360) & 0x200;
  case 0xb:
    return *(uint *)(iVar4 + 0x360) & 0x100;
  case 0xd:
    uVar2 = countLeadingZeros(1 - (uint)*(byte *)(iVar4 + 0x349));
    return uVar2 >> 5;
  case 0xe:
    return (int)*(short *)(iVar4 + 0x80a);
  case 0x12:
    if (*(int *)(iVar4 + 0x7f0) != 0) {
      return (int)*(short *)(*(int *)(iVar4 + 0x7f0) + 0x46);
    }
    return 0;
  }
  sVar1 = *(short *)(iVar4 + 0x274);
  if (sVar1 == 2) {
    psVar3 = *(short **)(iVar4 + 0x3f8);
    for (iVar4 = 0; (*(short *)(param_1 + 0xa0) != *psVar3 && (iVar4 < 0x14)); iVar4 = iVar4 + 4) {
      psVar3 = psVar3 + 4;
    }
    return iVar4 >> 2;
  }
  if ((sVar1 < 2) && (0 < sVar1)) {
    return 0;
  }
  return 5;
}

