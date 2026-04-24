// Function: FUN_80110580
// Entry: 80110580
// Size: 300 bytes

void FUN_80110580(int param_1,uint param_2,float *param_3)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xa4);
  if (DAT_803dd5b8 == (float *)0x0) {
    DAT_803dd5b8 = (float *)FUN_80023cc8(0x10,0xf,0);
  }
  if (param_3 == (float *)0x0) {
    *DAT_803dd5b8 = *(float *)(iVar2 + 0x18);
    DAT_803dd5b8[1] = *(float *)(iVar2 + 0x1c);
    DAT_803dd5b8[2] = *(float *)(iVar2 + 0x20);
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e1b38);
  }
  else {
    *DAT_803dd5b8 = *param_3;
    DAT_803dd5b8[1] = param_3[1];
    DAT_803dd5b8[2] = param_3[2];
    fVar1 = param_3[3];
  }
  DAT_803dd5b8[3] = fVar1;
  FUN_800217c0((double)(*(float *)(param_1 + 0x18) - *DAT_803dd5b8),
               (double)(*(float *)(param_1 + 0x20) - DAT_803dd5b8[2]));
  FUN_800217c0((double)(*(float *)(*(int *)(param_1 + 0xa4) + 0x18) - *DAT_803dd5b8),
               (double)(*(float *)(*(int *)(param_1 + 0xa4) + 0x20) - DAT_803dd5b8[2]));
  return;
}

