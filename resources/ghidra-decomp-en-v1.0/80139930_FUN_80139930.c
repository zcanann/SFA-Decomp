// Function: FUN_80139930
// Entry: 80139930
// Size: 348 bytes

int FUN_80139930(short *param_1,short param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(short *)(iVar2 + 0x5a) = param_2;
  sVar1 = *param_1;
  iVar3 = (int)sVar1 - ((int)param_2 & 0xffffU);
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  uVar4 = *(uint *)(iVar2 + 0x54);
  if ((uVar4 & 0x100000) == 0) {
    *(uint *)(iVar2 + 0x54) = uVar4 & 0xffdfffff;
  }
  else {
    *(uint *)(iVar2 + 0x54) = uVar4 | 0x200000;
  }
  *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xef2fffff;
  if (iVar3 < 0x11) {
    if (-0x11 < iVar3) {
      *param_1 = param_2;
      return 0;
    }
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x500000;
  }
  else {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x900000;
  }
  if (iVar3 < 0x201) {
    if (iVar3 < -0x200) {
      *param_1 = sVar1 + (short)(int)(FLOAT_803e2450 * FLOAT_803db414);
      *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000000;
    }
    else {
      *param_1 = param_2;
    }
  }
  else {
    *param_1 = sVar1 - (short)(int)(FLOAT_803e2450 * FLOAT_803db414);
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000000;
  }
  return iVar3;
}

