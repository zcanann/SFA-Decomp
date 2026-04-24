// Function: FUN_801ec1ac
// Entry: 801ec1ac
// Size: 1524 bytes

void FUN_801ec1ac(int param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  double dVar7;
  undefined4 local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60 [2];
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  double local_18;
  
  bVar2 = *(byte *)(param_2 + 0x428);
  if ((*(uint *)(param_2 + 0x458) & 0x100) == 0) {
    *(byte *)(param_2 + 0x428) = bVar2 & 0xbf;
  }
  else {
    *(byte *)(param_2 + 0x428) = bVar2 & 0xbf | 0x40;
  }
  if ((*(uint *)(param_2 + 0x458) & 0x200) == 0) {
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef;
  }
  else {
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef | 0x10;
  }
  if (((bVar2 >> 4 & 1) == 0) && ((*(byte *)(param_2 + 0x428) >> 4 & 1) != 0)) {
    FUN_8000bb18(param_1,0x45f);
  }
  fVar3 = FLOAT_803e5ae8;
  if ((*(byte *)(param_2 + 0x428) >> 6 & 1) != 0) {
    fVar3 = *(float *)(param_2 + 0x538);
  }
  fVar3 = FLOAT_803e5c28 * (fVar3 - *(float *)(param_2 + 0x430));
  fVar6 = FLOAT_803e5c2c;
  if ((FLOAT_803e5c2c <= fVar3) && (fVar6 = fVar3, FLOAT_803e5b8c < fVar3)) {
    fVar6 = FLOAT_803e5b8c;
  }
  *(float *)(param_2 + 0x430) = fVar6 * FLOAT_803db414 + *(float *)(param_2 + 0x430);
  fVar6 = FLOAT_803e5ae8;
  fVar3 = FLOAT_803e5ae8;
  if ((*(byte *)(param_2 + 0x428) >> 4 & 1) != 0) {
    fVar4 = *(float *)(param_2 + 0x53c);
    fVar5 = *(float *)(param_2 + 0x49c);
    if (fVar5 < FLOAT_803e5ae8) {
      if ((FLOAT_803e5ae8 <= fVar4) && (fVar3 = fVar4, -fVar5 * FLOAT_803db418 < fVar4)) {
        fVar3 = -fVar5 * FLOAT_803db418;
      }
    }
    else {
      fVar4 = -fVar4;
      fVar3 = -fVar5 * FLOAT_803db418;
      if ((fVar3 <= fVar4) && (fVar3 = fVar4, FLOAT_803e5ae8 < fVar4)) {
        fVar3 = FLOAT_803e5ae8;
      }
    }
  }
  *(float *)(param_2 + 0x4a0) = FLOAT_803e5ae8;
  *(float *)(param_2 + 0x4a4) = fVar6;
  *(float *)(param_2 + 0x4a8) = FLOAT_803db414 * (*(float *)(param_2 + 0x430) + fVar3);
  FUN_800226cc((double)*(float *)(param_2 + 0x4a0),(double)*(float *)(param_2 + 0x4a4),
               (double)*(float *)(param_2 + 0x4a8),param_2 + 0x6c,&local_68,&local_64,local_60);
  FUN_800226cc((double)local_68,(double)local_64,(double)local_60[0],param_2 + 300,&local_68,
               &local_64,local_60);
  FUN_80247730(&local_68,param_2 + 0x494,param_2 + 0x494);
  *(float *)(param_2 + 0x414) =
       FLOAT_803db414 * -*(float *)(param_2 + 0x45c) * *(float *)(param_2 + 0x52c) +
       *(float *)(param_2 + 0x414);
  dVar7 = (double)FUN_80292b44((double)*(float *)(param_2 + 0x530),(double)FLOAT_803db414);
  *(float *)(param_2 + 0x414) = (float)((double)*(float *)(param_2 + 0x414) * dVar7);
  fVar3 = *(float *)(param_2 + 0x414);
  fVar6 = *(float *)(param_2 + 0x534);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x414) = fVar4;
  uStack84 = (int)*(short *)(param_2 + 0x40e) ^ 0x80000000;
  local_58 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x414) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e5b00));
  local_50 = (longlong)iVar1;
  *(short *)(param_2 + 0x40e) = (short)iVar1;
  iVar1 = (int)(*(float *)(param_2 + 0x414) * *(float *)(param_2 + 0x550));
  local_48 = (longlong)iVar1;
  uStack60 = iVar1 - (*(uint *)(param_2 + 0x410) & 0xffff);
  if (0x8000 < (int)uStack60) {
    uStack60 = uStack60 - 0xffff;
  }
  if ((int)uStack60 < -0x8000) {
    uStack60 = uStack60 + 0xffff;
  }
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  uStack52 = *(uint *)(param_2 + 0x410) ^ 0x80000000;
  local_38 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e5b00) *
                *(float *)(param_2 + 0x554) +
               (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e5b00));
  local_30 = (longlong)iVar1;
  *(int *)(param_2 + 0x410) = iVar1;
  uStack36 = (int)*(short *)(param_2 + 0x40e) - ((int)*(short *)(param_2 + 0x40c) & 0xffffU);
  if (0x8000 < (int)uStack36) {
    uStack36 = uStack36 - 0xffff;
  }
  if ((int)uStack36 < -0x8000) {
    uStack36 = uStack36 + 0xffff;
  }
  uStack36 = uStack36 ^ 0x80000000;
  local_28 = 0x43300000;
  local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x40c) ^ 0x80000000);
  *(short *)(param_2 + 0x40c) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e5b00) *
                    *(float *)(param_2 + 0x558) + (float)(local_20 - DOUBLE_803e5b00));
  if (*(char *)(param_2 + 0x428) < '\0') {
    *(float *)(param_2 + 0x584) =
         -*(float *)(param_2 + 0x570) * FLOAT_803db414 + *(float *)(param_2 + 0x584);
    fVar3 = *(float *)(param_2 + 0x584);
    fVar6 = FLOAT_803e5c30;
    if ((FLOAT_803e5c30 <= fVar3) && (fVar6 = fVar3, FLOAT_803e5b48 < fVar3)) {
      fVar6 = FLOAT_803e5b48;
    }
    *(float *)(param_2 + 0x584) = fVar6;
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 2) ^ 0x80000000);
    *(short *)(param_1 + 2) =
         (short)(int)(*(float *)(param_2 + 0x584) * FLOAT_803db414 +
                     (float)(local_18 - DOUBLE_803e5b00));
  }
  if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
    local_78 = *(undefined4 *)(param_2 + 0x414);
    local_74 = *(undefined4 *)(param_2 + 0x49c);
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000);
    local_70 = (float)(local_18 - DOUBLE_803e5b00);
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 2) ^ 0x80000000);
    local_6c = (float)(local_20 - DOUBLE_803e5b00);
    (**(code **)(*DAT_803dca50 + 0x60))(&local_78,0x10);
  }
  fVar3 = *(float *)(param_2 + 0x494);
  fVar6 = *(float *)(param_2 + 0x47c);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x494) = fVar4;
  if ((*(float *)(param_2 + 0x494) < FLOAT_803e5b8c) &&
     (FLOAT_803e5ba4 < *(float *)(param_2 + 0x494))) {
    *(float *)(param_2 + 0x494) = FLOAT_803e5ae8;
  }
  fVar3 = *(float *)(param_2 + 0x498);
  fVar6 = -*(float *)(param_2 + 0x480);
  if ((fVar6 <= fVar3) && (fVar6 = fVar3, FLOAT_803e5aec < fVar3)) {
    fVar6 = FLOAT_803e5aec;
  }
  *(float *)(param_2 + 0x498) = fVar6;
  if ((*(float *)(param_2 + 0x498) < FLOAT_803e5b8c) &&
     (FLOAT_803e5ba4 < *(float *)(param_2 + 0x498))) {
    *(float *)(param_2 + 0x498) = FLOAT_803e5ae8;
  }
  fVar3 = *(float *)(param_2 + 0x49c);
  fVar6 = *(float *)(param_2 + 0x484);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x49c) = fVar4;
  if ((*(float *)(param_2 + 0x49c) < FLOAT_803e5b8c) &&
     (FLOAT_803e5ba4 < *(float *)(param_2 + 0x49c))) {
    *(float *)(param_2 + 0x49c) = FLOAT_803e5ae8;
  }
  return;
}

