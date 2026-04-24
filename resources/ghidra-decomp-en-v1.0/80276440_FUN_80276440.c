// Function: FUN_80276440
// Entry: 80276440
// Size: 300 bytes

void FUN_80276440(int param_1,uint *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint local_1c [2];
  
  local_1c[0] = param_2[1] >> 0x10;
  if ((param_2[1] >> 8 & 1) == 0) {
    FUN_80282f90(local_1c,param_1);
  }
  else {
    FUN_80282f80(local_1c);
  }
  iVar1 = FUN_80282fd8(local_1c[0]);
  if (iVar1 == 0) {
    iVar1 = 1;
  }
  uVar3 = *param_2;
  uVar4 = (*(int *)(param_1 + 0x154) * (uVar3 >> 8 & 0xff) >> 7) + (uVar3 & 0xff0000);
  if (0x7f0000 < uVar4) {
    uVar4 = 0x7f0000;
  }
  if (((uVar3 >> 0x18 | (param_2[1] & 0xff) << 8) != 0xffff) && (iVar2 = FUN_80275058(), iVar2 != 0)
     ) {
    uVar3 = uVar4 >> 0x10;
    if (uVar3 < 0x7f) {
      uVar4 = (uVar4 & 0xffff) *
              ((uint)*(byte *)(iVar2 + uVar3 + 1) - (uint)*(byte *)(iVar2 + uVar3)) +
              (uint)*(byte *)(iVar2 + uVar3) * 0x10000;
    }
    else {
      uVar4 = (uint)*(byte *)(iVar2 + uVar3) << 0x10;
    }
  }
  *(uint *)(param_1 + 0x198) = uVar4;
  *(int *)(param_1 + 0x19c) = param_3;
  *(int *)(param_1 + 0x194) = (int)(uVar4 - param_3) / iVar1;
  *(int *)(param_1 + 0x154) = param_3;
  *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x8000;
  return;
}

