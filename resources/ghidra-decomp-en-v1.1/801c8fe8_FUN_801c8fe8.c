// Function: FUN_801c8fe8
// Entry: 801c8fe8
// Size: 300 bytes

void FUN_801c8fe8(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  undefined4 *puVar3;
  float local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e5cfc;
  DAT_803de848 = 0;
  *puVar3 = *(undefined4 *)(param_1 + 0xc);
  puVar3[1] = *(undefined4 *)(param_1 + 0x10);
  puVar3[2] = *(undefined4 *)(param_1 + 0x14);
  puVar3[6] = *(undefined4 *)(param_1 + 0x10);
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e5d1c;
  fVar1 = FLOAT_803e5d00;
  puVar3[3] = FLOAT_803e5d00;
  puVar3[4] = fVar1;
  puVar3[5] = fVar1;
  puVar3[9] = 0;
  puVar3[10] = (int)*(short *)(param_2 + 0x1a);
  uStack_c = FUN_80022264(0,600);
  uStack_c = uStack_c ^ 0x80000000;
  local_10 = 0x43300000;
  puVar3[8] = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e5d28);
  uVar2 = FUN_80022264(0xfffffce0,800);
  *(short *)(puVar3 + 0xb) = (short)uVar2;
  *(undefined *)((int)puVar3 + 0x2e) = 1;
  *(undefined *)(param_1 + 0x37) = 0;
  puVar3[7] = FLOAT_803e5d00;
  if (DAT_803de848 == 0) {
    DAT_803de848 = FUN_80036f50(0xb,param_1,local_18);
  }
  FUN_80036018(param_1);
  FUN_80035eec(param_1,0,0,0);
  FUN_80035f9c(param_1);
  return;
}

