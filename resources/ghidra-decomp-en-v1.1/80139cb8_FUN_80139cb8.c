// Function: FUN_80139cb8
// Entry: 80139cb8
// Size: 348 bytes

int FUN_80139cb8(ushort *param_1,ushort param_2)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(ushort *)(iVar2 + 0x5a) = param_2;
  uVar1 = *param_1;
  iVar3 = (int)(short)uVar1 - (uint)param_2;
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
      return iVar3;
    }
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x500000;
  }
  else {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x900000;
  }
  if (iVar3 < 0x201) {
    if (iVar3 < -0x200) {
      *param_1 = uVar1 + (short)(int)(FLOAT_803e30e0 * FLOAT_803dc074);
      *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000000;
    }
    else {
      *param_1 = param_2;
    }
  }
  else {
    *param_1 = uVar1 - (short)(int)(FLOAT_803e30e0 * FLOAT_803dc074);
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000000;
  }
  return iVar3;
}

