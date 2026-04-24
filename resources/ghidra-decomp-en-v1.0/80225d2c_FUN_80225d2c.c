// Function: FUN_80225d2c
// Entry: 80225d2c
// Size: 1156 bytes

void FUN_80225d2c(undefined4 param_1,undefined4 param_2,short param_3,float *param_4,float *param_5,
                 int param_6,int param_7)

{
  short sVar1;
  float fVar2;
  int iVar3;
  char *pcVar4;
  undefined4 uVar5;
  short extraout_r4;
  int iVar6;
  int iVar7;
  undefined auStack104 [4];
  float local_64;
  undefined auStack96 [4];
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack68 [4];
  float local_40;
  undefined auStack60 [4];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  
  iVar3 = FUN_802860d4();
  if (param_6 == 0) {
    if (param_7 == -1) {
      FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                   (double)*(float *)(iVar3 + 0x14),&local_50,&local_4c);
      fVar2 = FLOAT_803e6db4;
      uStack36 = extraout_r4 * 0x30 ^ 0x80000000;
      *param_4 = FLOAT_803e6db4 +
                 FLOAT_803e6db8 + local_50 +
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
      *param_5 = fVar2 + FLOAT_803e6dc0 + local_4c + FLOAT_803e6dbc;
      param_3 = param_3 + 1;
      iVar6 = 8;
    }
    else {
      FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                   (double)*(float *)(iVar3 + 0x14),&local_58,&local_54);
      fVar2 = FLOAT_803e6db4;
      uStack36 = extraout_r4 * 0x30 ^ 0x80000000;
      *param_4 = FLOAT_803e6db4 +
                 FLOAT_803e6db8 + local_58 +
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
      *param_5 = fVar2 + FLOAT_803e6dc0 + local_54 + FLOAT_803e6da8;
      param_3 = param_3 + -1;
      iVar6 = -1;
    }
    local_28 = 0x43300000;
    iVar7 = (int)param_3;
    pcVar4 = &DAT_803ad298 + iVar7 + extraout_r4 * 8;
    for (; iVar7 != iVar6; iVar7 = iVar7 - param_7) {
      if (*pcVar4 != '\0') {
        if ((byte)(&DAT_803ad298)[iVar7 + extraout_r4 * 8] < 5) {
          FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),auStack96,&local_5c);
          uStack36 = (short)((short)iVar7 + (short)param_7) * 0x30 ^ 0x80000000;
          *param_5 = FLOAT_803e6db4 +
                     FLOAT_803e6dc0 + local_5c +
                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
          uVar5 = 1;
        }
        else {
          FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),auStack104,&local_64);
          uStack36 = (short)iVar7 * 0x30 ^ 0x80000000;
          *param_5 = FLOAT_803e6db4 +
                     FLOAT_803e6dc0 + local_64 +
                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
          uVar5 = 2;
        }
        goto LAB_80226198;
      }
      pcVar4 = pcVar4 + -param_7;
    }
  }
  else {
    if (param_6 == -1) {
      FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                   (double)*(float *)(iVar3 + 0x14),&local_30,&local_2c);
      fVar2 = FLOAT_803e6db4;
      *param_4 = FLOAT_803e6db4 + FLOAT_803e6db8 + local_30 + FLOAT_803e6dbc;
      uStack36 = param_3 * 0x30 ^ 0x80000000;
      *param_5 = fVar2 + FLOAT_803e6dc0 + local_2c +
                         (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
      sVar1 = 1;
      iVar6 = 8;
    }
    else {
      FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                   (double)*(float *)(iVar3 + 0x14),&local_38,&local_34);
      fVar2 = FLOAT_803e6db4;
      *param_4 = FLOAT_803e6db4 + FLOAT_803e6db8 + local_38 + FLOAT_803e6da8;
      uStack36 = param_3 * 0x30 ^ 0x80000000;
      *param_5 = fVar2 + FLOAT_803e6dc0 + local_34 +
                         (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
      sVar1 = -1;
      iVar6 = -1;
    }
    local_28 = 0x43300000;
    iVar7 = (int)(short)(extraout_r4 + sVar1);
    pcVar4 = &DAT_803ad298 + iVar7 * 8 + (int)param_3;
    for (; iVar7 != iVar6; iVar7 = iVar7 - param_6) {
      if (*pcVar4 != '\0') {
        if ((byte)(&DAT_803ad298)[(int)param_3 + iVar7 * 8] < 5) {
          FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),&local_40,auStack60);
          uStack36 = (short)((short)iVar7 + (short)param_6) * 0x30 ^ 0x80000000;
          *param_4 = FLOAT_803e6db4 +
                     FLOAT_803e6db8 + local_40 +
                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
          uVar5 = 1;
        }
        else {
          FUN_8005b0a8((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),&local_48,auStack68);
          uStack36 = (short)iVar7 * 0x30 ^ 0x80000000;
          *param_4 = FLOAT_803e6db4 +
                     FLOAT_803e6db8 + local_48 +
                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6dc8);
          uVar5 = 2;
        }
        goto LAB_80226198;
      }
      pcVar4 = pcVar4 + param_6 * -8;
    }
  }
  uVar5 = 4;
LAB_80226198:
  local_28 = 0x43300000;
  FUN_80286120(uVar5);
  return;
}

