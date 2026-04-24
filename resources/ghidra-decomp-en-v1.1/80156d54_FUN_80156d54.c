// Function: FUN_80156d54
// Entry: 80156d54
// Size: 168 bytes

void FUN_80156d54(undefined4 param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3780;
  *(undefined4 *)(param_2 + 0x2e4) = 0x2002b029;
  *(float *)(param_2 + 0x308) = FLOAT_803e3764;
  *(float *)(param_2 + 0x300) = FLOAT_803e3784;
  *(float *)(param_2 + 0x304) = FLOAT_803e3788;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e378c;
  *(float *)(param_2 + 0x314) = FLOAT_803e378c;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 2;
  *(float *)(param_2 + 0x31c) = fVar1;
  uVar2 = FUN_80022264(0x78,0x1e0);
  *(float *)(param_2 + 0x328) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
  return;
}

