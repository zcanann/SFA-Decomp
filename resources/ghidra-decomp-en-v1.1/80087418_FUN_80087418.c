// Function: FUN_80087418
// Entry: 80087418
// Size: 500 bytes

void FUN_80087418(short *param_1,short *param_2,int param_3)

{
  short sVar1;
  short sVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  double dVar7;
  short sVar2;
  
  if ((*(int *)(param_2 + 0x18) == *(int *)(param_1 + 0x18)) ||
     (fVar4 = FLOAT_803ddda0, fVar5 = FLOAT_803ddd9c, fVar6 = FLOAT_803ddd98, sVar2 = DAT_803ddd96,
     DAT_803ddd94 == '\0')) {
    fVar4 = *(float *)(param_1 + 6);
    fVar5 = *(float *)(param_1 + 8);
    fVar6 = *(float *)(param_1 + 10);
    sVar2 = *param_1;
  }
  sVar1 = param_1[1];
  sVar3 = param_1[2];
  if (param_2 != param_1) {
    if ((*(ushort *)(param_3 + 0x6e) & 1) != 0) {
      if (*(char *)(param_3 + 0x56) == '\x02') {
        *(float *)(param_2 + 6) = *(float *)(param_3 + 0x40) * *(float *)(param_3 + 0x4c) + fVar4;
        *(float *)(param_2 + 8) = *(float *)(param_3 + 0x44) * *(float *)(param_3 + 0x4c) + fVar5;
        *(float *)(param_2 + 10) = *(float *)(param_3 + 0x48) * *(float *)(param_3 + 0x4c) + fVar6;
      }
      else {
        *(float *)(param_2 + 6) = fVar4;
        *(float *)(param_2 + 8) = fVar5;
        *(float *)(param_2 + 10) = fVar6;
      }
    }
    dVar7 = DOUBLE_803dfc38;
    if ((*(ushort *)(param_3 + 0x6e) & 2) != 0) {
      if (*(char *)(param_3 + 0x56) == '\x02') {
        *param_2 = sVar2 + (short)(int)((float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_3 + 0x50) ^
                                                                 0x80000000) - DOUBLE_803dfc38) *
                                       *(float *)(param_3 + 0x4c));
        param_2[1] = sVar1 + (short)(int)((float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_3 + 0x52) ^
                                                                   0x80000000) - dVar7) *
                                         *(float *)(param_3 + 0x4c));
        param_2[2] = sVar3 + (short)(int)((float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_3 + 0x54) ^
                                                                   0x80000000) - dVar7) *
                                         *(float *)(param_3 + 0x4c));
      }
      else {
        *param_2 = sVar2;
        param_2[1] = sVar1;
        param_2[2] = sVar3;
      }
    }
  }
  if ((*(char *)(param_3 + 0x7b) != '\0') && (*(char *)(param_3 + 0x78) != '\0')) {
    DAT_803ddd36 = (ushort)DAT_803dc070;
    DAT_803ddd38 = param_1;
  }
  FUN_8000e12c((int)param_2,(float *)(param_2 + 0xc),(float *)(param_2 + 0xe),
               (float *)(param_2 + 0x10));
  return;
}

