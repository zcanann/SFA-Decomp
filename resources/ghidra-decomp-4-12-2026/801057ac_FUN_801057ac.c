// Function: FUN_801057ac
// Entry: 801057ac
// Size: 672 bytes

void FUN_801057ac(int param_1)

{
  float fVar1;
  double dVar2;
  double dVar3;
  int iVar4;
  
  iVar4 = (**(code **)(*DAT_803dd6d0 + 0xc))();
  DAT_803de1a8[0x24] = DAT_803de1a8[0x23];
  DAT_803de1a8[0xf] = DAT_803de1a8[2];
  DAT_803de1a8[0x11] = DAT_803de1a8[3];
  DAT_803de1a8[0xb] = *DAT_803de1a8;
  DAT_803de1a8[0xd] = DAT_803de1a8[1];
  DAT_803de1a8[0x1b] = *(float *)(iVar4 + 0xb4);
  DAT_803de1a8[0x17] = DAT_803de1a8[6];
  DAT_803de1a8[0x19] = DAT_803de1a8[7];
  DAT_803de1a8[0x15] = DAT_803de1a8[5];
  DAT_803de1a8[0x13] = DAT_803de1a8[4];
  dVar2 = DOUBLE_803e2318;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_1 + 5) ^ 0x80000000) -
                 DOUBLE_803e2318);
  DAT_803de1a8[0x23] = fVar1;
  DAT_803de1a8[0x25] = fVar1;
  dVar3 = DOUBLE_803e2378;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 6)) - DOUBLE_803e2378);
  DAT_803de1a8[2] = fVar1;
  DAT_803de1a8[0x26] = fVar1;
  DAT_803de1a8[0x10] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 8)) - dVar3);
  DAT_803de1a8[3] = fVar1;
  DAT_803de1a8[0x27] = fVar1;
  DAT_803de1a8[0x12] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 3)) - dVar3);
  *DAT_803de1a8 = fVar1;
  DAT_803de1a8[0xc] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 4)) - dVar3);
  DAT_803de1a8[1] = fVar1;
  DAT_803de1a8[0xe] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_1 + 2) ^ 0x80000000) - dVar2);
  *(float *)(iVar4 + 0xb4) = fVar1;
  DAT_803de1a8[0x1c] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 9)) - dVar3);
  DAT_803de1a8[6] = fVar1;
  DAT_803de1a8[0x18] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 10)) - dVar3);
  DAT_803de1a8[7] = fVar1;
  DAT_803de1a8[0x1a] = fVar1;
  if (*(byte *)(param_1 + 0xb) == 0) {
    DAT_803de1a8[0x14] = FLOAT_803e2394;
  }
  else {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xb)) - dVar3) /
            FLOAT_803e2390;
    DAT_803de1a8[4] = fVar1;
    DAT_803de1a8[0x14] = fVar1;
  }
  if (*(byte *)(param_1 + 0xc) == 0) {
    DAT_803de1a8[0x16] = FLOAT_803e2394;
  }
  else {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xc)) - DOUBLE_803e2378) /
            FLOAT_803e2390;
    DAT_803de1a8[5] = fVar1;
    DAT_803de1a8[0x16] = fVar1;
  }
  *(undefined2 *)((int)DAT_803de1a8 + 0x82) = 0;
  *(undefined2 *)(DAT_803de1a8 + 0x21) = 0;
  return;
}

