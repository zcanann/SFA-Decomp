// Function: FUN_801c8a34
// Entry: 801c8a34
// Size: 300 bytes

void FUN_801c8a34(int param_1,int param_2)

{
  float fVar1;
  undefined2 uVar2;
  undefined4 *puVar3;
  float local_18 [2];
  undefined4 local_10;
  uint uStack12;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e5064;
  DAT_803ddbc8 = 0;
  *puVar3 = *(undefined4 *)(param_1 + 0xc);
  puVar3[1] = *(undefined4 *)(param_1 + 0x10);
  puVar3[2] = *(undefined4 *)(param_1 + 0x14);
  puVar3[6] = *(undefined4 *)(param_1 + 0x10);
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e5084;
  fVar1 = FLOAT_803e5068;
  puVar3[3] = FLOAT_803e5068;
  puVar3[4] = fVar1;
  puVar3[5] = fVar1;
  puVar3[9] = 0;
  puVar3[10] = (int)*(short *)(param_2 + 0x1a);
  uStack12 = FUN_800221a0(0,600);
  uStack12 = uStack12 ^ 0x80000000;
  local_10 = 0x43300000;
  puVar3[8] = (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e5090);
  uVar2 = FUN_800221a0(0xfffffce0,800);
  *(undefined2 *)(puVar3 + 0xb) = uVar2;
  *(undefined *)((int)puVar3 + 0x2e) = 1;
  *(undefined *)(param_1 + 0x37) = 0;
  puVar3[7] = FLOAT_803e5068;
  if (DAT_803ddbc8 == 0) {
    DAT_803ddbc8 = FUN_80036e58(0xb,param_1,local_18);
  }
  FUN_80035f20(param_1);
  FUN_80035df4(param_1,0,0,0);
  FUN_80035ea4(param_1);
  return;
}

