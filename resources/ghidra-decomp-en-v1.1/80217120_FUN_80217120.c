// Function: FUN_80217120
// Entry: 80217120
// Size: 152 bytes

void FUN_80217120(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(float *)(iVar2 + 4) = FLOAT_803e7530;
  uVar1 = FUN_80022264(0x50,0x78);
  *(float *)(iVar2 + 0xc) =
       FLOAT_803e7554 * (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e7540);
  uVar1 = FUN_80022264(0,1);
  if (uVar1 != 0) {
    *(float *)(iVar2 + 0xc) = -*(float *)(iVar2 + 0xc);
  }
  return;
}

