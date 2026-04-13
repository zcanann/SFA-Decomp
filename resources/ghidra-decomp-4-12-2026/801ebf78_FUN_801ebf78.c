// Function: FUN_801ebf78
// Entry: 801ebf78
// Size: 1056 bytes

void FUN_801ebf78(short *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined8 local_48;
  undefined8 local_40;
  
  iVar5 = param_2 + 0x178;
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,iVar5);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar5);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,iVar5);
  fVar1 = FLOAT_803e6854;
  dVar6 = DOUBLE_803e6798;
  iVar5 = 2;
  if (*(char *)(param_2 + 0x3d9) == '\0') {
    *(float *)(param_2 + 0x424) = *(float *)(param_2 + 0x424) + FLOAT_803dc074;
    fVar1 = *(float *)(param_2 + 0x424);
    fVar2 = FLOAT_803e6780;
    if ((FLOAT_803e6780 <= fVar1) && (fVar2 = fVar1, FLOAT_803e684c < fVar1)) {
      fVar2 = FLOAT_803e684c;
    }
    *(float *)(param_2 + 0x424) = fVar2;
    if (FLOAT_803e6850 <= *(float *)(param_2 + 0x424)) {
      if (-1 < *(char *)(param_2 + 0x428)) {
        *(float *)(param_2 + 0x584) = FLOAT_803e6780;
      }
      *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0x7f | 0x80;
    }
  }
  else {
    if (*(char *)(param_2 + 0x428) < '\0') {
      iVar5 = 0;
      local_48 = (double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000);
      *(float *)(param_2 + 0x58c) = FLOAT_803e6854 * (float)(local_48 - DOUBLE_803e6798);
      local_40 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
      *(float *)(param_2 + 0x590) = fVar1 * (float)(local_40 - dVar6);
      *(undefined2 *)(param_2 + 0x588) = 0;
      *(undefined2 *)(param_2 + 0x58a) = 0;
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        FUN_80014acc((double)(*(float *)(param_2 + 0x424) * fVar1));
        FUN_8000faf8();
        FUN_8000e69c((double)(*(float *)(param_2 + 0x424) / FLOAT_803e6858));
        FUN_8000bb38((uint)param_1,0x3bc);
        fVar1 = FLOAT_803e685c * *(float *)(param_2 + 0x424);
        if (FLOAT_803e67d8 < fVar1) {
          fVar1 = FLOAT_803e67d8;
        }
        FUN_8000b9bc((double)FLOAT_803e67b8,(int)param_1,0x3bc,(byte)(int)fVar1);
      }
    }
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0x7f;
    *(float *)(param_2 + 0x424) = FLOAT_803e6780;
    *(undefined *)(param_2 + 0x4b4) = *(undefined *)(param_2 + 0x230);
  }
  fVar1 = FLOAT_803e6860;
  dVar6 = DOUBLE_803e6798;
  local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x588) ^ 0x80000000);
  *(short *)(param_2 + 0x588) =
       (short)(int)(FLOAT_803e6860 * FLOAT_803dc074 + (float)(local_40 - DOUBLE_803e6798));
  *(short *)(param_2 + 0x58a) =
       (short)(int)(fVar1 * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x58a) ^ 0x80000000
                                           ) - dVar6));
  dVar6 = (double)FUN_802932a4((double)FLOAT_803e6864,(double)FLOAT_803dc074);
  *(float *)(param_2 + 0x58c) = (float)((double)*(float *)(param_2 + 0x58c) * dVar6);
  dVar6 = (double)FUN_802932a4((double)FLOAT_803e6864,(double)FLOAT_803dc074);
  *(float *)(param_2 + 0x590) = (float)((double)*(float *)(param_2 + 0x590) * dVar6);
  dVar6 = (double)FUN_802945e0();
  *(float *)(param_2 + 0x594) = (float)((double)*(float *)(param_2 + 0x58c) * dVar6);
  dVar6 = (double)FUN_802945e0();
  *(float *)(param_2 + 0x598) = (float)((double)*(float *)(param_2 + 0x590) * dVar6);
  iVar4 = (int)*param_1 - (uint)*(ushort *)(param_2 + 0x40e);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *(short *)(param_2 + 0x40e) = *(short *)(param_2 + 0x40e) + (short)iVar4;
  *(short *)(param_2 + 0x40c) = *(short *)(param_2 + 0x40c) + (short)iVar4;
  param_1[1] = param_1[1] + (short)((int)*(short *)(param_2 + 0x310) >> iVar5);
  param_1[2] = param_1[2] + (short)((int)*(short *)(param_2 + 0x312) >> iVar5);
  sVar3 = param_1[1];
  if (sVar3 < -0x2000) {
    sVar3 = -0x2000;
  }
  else if (0x2000 < sVar3) {
    sVar3 = 0x2000;
  }
  param_1[1] = sVar3;
  sVar3 = param_1[2];
  if (sVar3 < -0x2000) {
    sVar3 = -0x2000;
  }
  else if (0x2000 < sVar3) {
    sVar3 = 0x2000;
  }
  param_1[2] = sVar3;
  return;
}

