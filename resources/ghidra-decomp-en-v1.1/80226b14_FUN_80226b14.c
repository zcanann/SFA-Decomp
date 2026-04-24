// Function: FUN_80226b14
// Entry: 80226b14
// Size: 1156 bytes

void FUN_80226b14(undefined4 param_1,undefined4 param_2,short param_3,float *param_4,float *param_5,
                 int param_6,int param_7)

{
  short sVar1;
  float fVar2;
  char *pcVar3;
  short extraout_r4;
  int iVar4;
  int iVar5;
  float fStack_68;
  float local_64;
  float fStack_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float fStack_44;
  float local_40;
  float fStack_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  uint uStack_24;
  
  FUN_80286838();
  if (param_6 == 0) {
    if (param_7 == -1) {
      FUN_8005b224(&local_50,&local_4c);
      fVar2 = FLOAT_803e7a4c;
      uStack_24 = extraout_r4 * 0x30 ^ 0x80000000;
      *param_4 = FLOAT_803e7a4c +
                 FLOAT_803e7a68 + local_50 +
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
      *param_5 = fVar2 + FLOAT_803e7a6c + local_4c + FLOAT_803e7a54;
      sVar1 = 1;
      iVar4 = 8;
    }
    else {
      FUN_8005b224(&local_58,&local_54);
      fVar2 = FLOAT_803e7a4c;
      uStack_24 = extraout_r4 * 0x30 ^ 0x80000000;
      *param_4 = FLOAT_803e7a4c +
                 FLOAT_803e7a68 + local_58 +
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
      *param_5 = fVar2 + FLOAT_803e7a6c + local_54 + FLOAT_803e7a40;
      sVar1 = -1;
      iVar4 = -1;
    }
    local_2c[1] = 176.0;
    iVar5 = (int)(short)(param_3 + sVar1);
    pcVar3 = &DAT_803adf38 + iVar5 + extraout_r4 * 8;
    for (; iVar5 != iVar4; iVar5 = iVar5 - param_7) {
      if (*pcVar3 != '\0') {
        if ((byte)(&DAT_803adf38)[iVar5 + extraout_r4 * 8] < 5) {
          FUN_8005b224(&fStack_60,&local_5c);
          uStack_24 = (short)((short)iVar5 + (short)param_7) * 0x30 ^ 0x80000000;
          *param_5 = FLOAT_803e7a4c +
                     FLOAT_803e7a6c + local_5c +
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
        }
        else {
          FUN_8005b224(&fStack_68,&local_64);
          uStack_24 = (short)iVar5 * 0x30 ^ 0x80000000;
          *param_5 = FLOAT_803e7a4c +
                     FLOAT_803e7a6c + local_64 +
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
        }
        break;
      }
      pcVar3 = pcVar3 + -param_7;
    }
  }
  else {
    if (param_6 == -1) {
      FUN_8005b224(&local_30,local_2c);
      fVar2 = FLOAT_803e7a4c;
      *param_4 = FLOAT_803e7a4c + FLOAT_803e7a68 + local_30 + FLOAT_803e7a54;
      uStack_24 = param_3 * 0x30 ^ 0x80000000;
      *param_5 = fVar2 + FLOAT_803e7a6c + local_2c[0] +
                         (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
      sVar1 = 1;
      iVar4 = 8;
    }
    else {
      FUN_8005b224(&local_38,&local_34);
      fVar2 = FLOAT_803e7a4c;
      *param_4 = FLOAT_803e7a4c + FLOAT_803e7a68 + local_38 + FLOAT_803e7a40;
      uStack_24 = param_3 * 0x30 ^ 0x80000000;
      *param_5 = fVar2 + FLOAT_803e7a6c + local_34 +
                         (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
      sVar1 = -1;
      iVar4 = -1;
    }
    local_2c[1] = 176.0;
    iVar5 = (int)(short)(extraout_r4 + sVar1);
    pcVar3 = &DAT_803adf38 + iVar5 * 8 + (int)param_3;
    for (; iVar5 != iVar4; iVar5 = iVar5 - param_6) {
      if (*pcVar3 != '\0') {
        if ((byte)(&DAT_803adf38)[(int)param_3 + iVar5 * 8] < 5) {
          FUN_8005b224(&local_40,&fStack_3c);
          uStack_24 = (short)((short)iVar5 + (short)param_6) * 0x30 ^ 0x80000000;
          *param_4 = FLOAT_803e7a4c +
                     FLOAT_803e7a68 + local_40 +
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
        }
        else {
          FUN_8005b224(&local_48,&fStack_44);
          uStack_24 = (short)iVar5 * 0x30 ^ 0x80000000;
          *param_4 = FLOAT_803e7a4c +
                     FLOAT_803e7a68 + local_48 +
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7a60);
        }
        break;
      }
      pcVar3 = pcVar3 + param_6 * -8;
    }
  }
  local_2c[1] = 176.0;
  FUN_80286884();
  return;
}

