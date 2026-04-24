// Function: FUN_8008718c
// Entry: 8008718c
// Size: 500 bytes

void FUN_8008718c(short *param_1,short *param_2,int param_3)

{
  float fVar1;
  short sVar4;
  short sVar6;
  double dVar7;
  float fVar2;
  float fVar3;
  short sVar5;
  
  if ((*(int *)(param_2 + 0x18) == *(int *)(param_1 + 0x18)) ||
     (sVar5 = DAT_803dd116, fVar1 = FLOAT_803dd120, fVar2 = FLOAT_803dd11c, fVar3 = FLOAT_803dd118,
     DAT_803dd114 == '\0')) {
    sVar5 = *param_1;
    fVar1 = *(float *)(param_1 + 6);
    fVar2 = *(float *)(param_1 + 8);
    fVar3 = *(float *)(param_1 + 10);
  }
  sVar4 = param_1[1];
  sVar6 = param_1[2];
  if (param_2 != param_1) {
    if ((*(ushort *)(param_3 + 0x6e) & 1) != 0) {
      if (*(char *)(param_3 + 0x56) == '\x02') {
        *(float *)(param_2 + 6) = *(float *)(param_3 + 0x40) * *(float *)(param_3 + 0x4c) + fVar1;
        *(float *)(param_2 + 8) = *(float *)(param_3 + 0x44) * *(float *)(param_3 + 0x4c) + fVar2;
        *(float *)(param_2 + 10) = *(float *)(param_3 + 0x48) * *(float *)(param_3 + 0x4c) + fVar3;
      }
      else {
        *(float *)(param_2 + 6) = fVar1;
        *(float *)(param_2 + 8) = fVar2;
        *(float *)(param_2 + 10) = fVar3;
      }
    }
    dVar7 = DOUBLE_803defb8;
    if ((*(ushort *)(param_3 + 0x6e) & 2) != 0) {
      if (*(char *)(param_3 + 0x56) == '\x02') {
        *param_2 = sVar5 + (short)(int)((float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_3 + 0x50) ^
                                                                 0x80000000) - DOUBLE_803defb8) *
                                       *(float *)(param_3 + 0x4c));
        param_2[1] = sVar4 + (short)(int)((float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_3 + 0x52) ^
                                                                   0x80000000) - dVar7) *
                                         *(float *)(param_3 + 0x4c));
        param_2[2] = sVar6 + (short)(int)((float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_3 + 0x54) ^
                                                                   0x80000000) - dVar7) *
                                         *(float *)(param_3 + 0x4c));
      }
      else {
        *param_2 = sVar5;
        param_2[1] = sVar4;
        param_2[2] = sVar6;
      }
    }
  }
  if ((*(char *)(param_3 + 0x7b) != '\0') && (*(char *)(param_3 + 0x78) != '\0')) {
    DAT_803dd0b6 = (ushort)DAT_803db410;
    DAT_803dd0b8 = param_1;
  }
  FUN_8000e10c(param_2,param_2 + 0xc,param_2 + 0xe,param_2 + 0x10);
  return;
}

