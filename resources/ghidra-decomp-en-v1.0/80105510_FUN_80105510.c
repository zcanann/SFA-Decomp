// Function: FUN_80105510
// Entry: 80105510
// Size: 672 bytes

void FUN_80105510(int param_1)

{
  float fVar1;
  double dVar2;
  double dVar3;
  int iVar4;
  
  iVar4 = (**(code **)(*DAT_803dca50 + 0xc))();
  DAT_803dd530[0x24] = DAT_803dd530[0x23];
  DAT_803dd530[0xf] = DAT_803dd530[2];
  DAT_803dd530[0x11] = DAT_803dd530[3];
  DAT_803dd530[0xb] = *DAT_803dd530;
  DAT_803dd530[0xd] = DAT_803dd530[1];
  DAT_803dd530[0x1b] = *(float *)(iVar4 + 0xb4);
  DAT_803dd530[0x17] = DAT_803dd530[6];
  DAT_803dd530[0x19] = DAT_803dd530[7];
  DAT_803dd530[0x15] = DAT_803dd530[5];
  DAT_803dd530[0x13] = DAT_803dd530[4];
  dVar2 = DOUBLE_803e1698;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_1 + 5) ^ 0x80000000) -
                 DOUBLE_803e1698);
  DAT_803dd530[0x23] = fVar1;
  DAT_803dd530[0x25] = fVar1;
  dVar3 = DOUBLE_803e16f8;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 6)) - DOUBLE_803e16f8);
  DAT_803dd530[2] = fVar1;
  DAT_803dd530[0x26] = fVar1;
  DAT_803dd530[0x10] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 8)) - dVar3);
  DAT_803dd530[3] = fVar1;
  DAT_803dd530[0x27] = fVar1;
  DAT_803dd530[0x12] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 3)) - dVar3);
  *DAT_803dd530 = fVar1;
  DAT_803dd530[0xc] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 4)) - dVar3);
  DAT_803dd530[1] = fVar1;
  DAT_803dd530[0xe] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_1 + 2) ^ 0x80000000) - dVar2);
  *(float *)(iVar4 + 0xb4) = fVar1;
  DAT_803dd530[0x1c] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 9)) - dVar3);
  DAT_803dd530[6] = fVar1;
  DAT_803dd530[0x18] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 10)) - dVar3);
  DAT_803dd530[7] = fVar1;
  DAT_803dd530[0x1a] = fVar1;
  if (*(byte *)(param_1 + 0xb) == 0) {
    DAT_803dd530[0x14] = FLOAT_803e1714;
  }
  else {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xb)) - dVar3) /
            FLOAT_803e1710;
    DAT_803dd530[4] = fVar1;
    DAT_803dd530[0x14] = fVar1;
  }
  if (*(byte *)(param_1 + 0xc) == 0) {
    DAT_803dd530[0x16] = FLOAT_803e1714;
  }
  else {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xc)) - DOUBLE_803e16f8) /
            FLOAT_803e1710;
    DAT_803dd530[5] = fVar1;
    DAT_803dd530[0x16] = fVar1;
  }
  *(undefined2 *)((int)DAT_803dd530 + 0x82) = 0;
  *(undefined2 *)(DAT_803dd530 + 0x21) = 0;
  return;
}

