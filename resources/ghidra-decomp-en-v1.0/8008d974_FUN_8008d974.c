// Function: FUN_8008d974
// Entry: 8008d974
// Size: 292 bytes

void FUN_8008d974(uint *param_1,uint *param_2,uint *param_3,undefined4 param_4,int param_5,
                 int param_6,int param_7)

{
  float fVar1;
  double dVar2;
  uint uVar3;
  uint uVar4;
  
  dVar2 = DOUBLE_803df130;
  if ((DAT_803dd184 != 0) && ((DAT_803dd184 == 0 || (*(char *)(DAT_803dd184 + 0x316) != '\0')))) {
    uVar3 = *param_2;
    uVar4 = *param_3;
    fVar1 = FLOAT_803df108;
    if (DAT_803dd184 != 0) {
      param_5 = *(int *)(DAT_803dd184 + 0x24);
      param_6 = *(int *)(DAT_803dd184 + 0x28);
      param_7 = *(int *)(DAT_803dd184 + 0x2c);
      fVar1 = *(float *)(DAT_803dd184 + 0x30c);
    }
    fVar1 = FLOAT_803df144 * fVar1;
    *param_1 = (int)((float)((double)CONCAT44(0x43300000,param_5 - *param_1 ^ 0x80000000) -
                            DOUBLE_803df130) * fVar1 +
                    (float)((double)CONCAT44(0x43300000,*param_1 ^ 0x80000000) - DOUBLE_803df130));
    *param_2 = (int)((float)((double)CONCAT44(0x43300000,param_6 - uVar3 ^ 0x80000000) - dVar2) *
                     fVar1 + (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - dVar2));
    *param_3 = (int)((float)((double)CONCAT44(0x43300000,param_7 - uVar4 ^ 0x80000000) - dVar2) *
                     fVar1 + (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar2));
  }
  return;
}

