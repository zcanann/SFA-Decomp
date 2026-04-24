// Function: FUN_80216aa8
// Entry: 80216aa8
// Size: 152 bytes

void FUN_80216aa8(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(float *)(iVar3 + 4) = FLOAT_803e6898;
  uVar1 = FUN_800221a0(0x50,0x78);
  *(float *)(iVar3 + 0xc) =
       FLOAT_803e68bc * (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e68a8);
  iVar2 = FUN_800221a0(0,1);
  if (iVar2 != 0) {
    *(float *)(iVar3 + 0xc) = -*(float *)(iVar3 + 0xc);
  }
  return;
}

