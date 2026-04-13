// Function: FUN_801ea878
// Entry: 801ea878
// Size: 1080 bytes

/* WARNING: Removing unreachable block (ram,0x801eac88) */
/* WARNING: Removing unreachable block (ram,0x801ea888) */

void FUN_801ea878(double param_1,uint param_2,int param_3,uint param_4,undefined4 param_5,
                 uint param_6)

{
  float fVar1;
  int iVar2;
  bool bVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  undefined8 local_28;
  
  dVar6 = (double)FLOAT_803e6780;
  if ((dVar6 <= param_1) && (dVar6 = param_1, (double)FLOAT_803e67a0 < param_1)) {
    dVar6 = (double)FLOAT_803e67a0;
  }
  if (((param_6 & 1) != 0) && (bVar3 = FUN_8000b598(param_2,8), bVar3)) {
    FLOAT_803de8e4 = (float)((double)FLOAT_803e67a4 * dVar6);
    if (FLOAT_803de8e4 < FLOAT_803e6780) {
      FLOAT_803de8e4 = -FLOAT_803de8e4;
    }
    if (FLOAT_803de8e4 < FLOAT_803e67a8) {
      FLOAT_803de8e4 = FLOAT_803e67a8;
    }
    if (FLOAT_803e67ac < FLOAT_803de8e4) {
      FLOAT_803de8e4 = FLOAT_803e67ac;
    }
    if (FLOAT_803e67b0 <= *(float *)(param_3 + 0x424)) {
      iVar2 = 0;
    }
    else {
      iVar2 = (int)((double)FLOAT_803e67b4 * dVar6);
      if (iVar2 < 0) {
        iVar2 = -iVar2;
      }
      if (0x7f < iVar2) {
        iVar2 = 0x7f;
      }
    }
    FUN_8000b8a8((double)(FLOAT_803e67b8 + FLOAT_803de8e4 / FLOAT_803e67a0),param_2,8,(byte)iVar2);
  }
  if ((((param_6 & 2) != 0) && (bVar3 = FUN_8000b598(param_2,1), bVar3)) &&
     (*(float *)(param_3 + 0x424) < FLOAT_803e67b0)) {
    dVar5 = (double)FLOAT_803e6780;
    if (dVar5 != dVar6) {
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 4) ^ 0x80000000);
      dVar5 = (double)((float)(dVar6 * (double)(float)(local_30 - DOUBLE_803e6798)) / FLOAT_803e67bc
                      );
    }
    FLOAT_803de8e4 = (float)dVar5;
    fVar1 = (float)dVar5;
    if (FLOAT_803e6780 <= fVar1) {
      if (FLOAT_803e6784 < fVar1) {
        FLOAT_803de8e4 = FLOAT_803e6784;
      }
    }
    else {
      FLOAT_803de8e4 = -fVar1;
    }
    uVar4 = (uint)(FLOAT_803e67c0 * FLOAT_803de8e4);
    local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    if ((float)(local_28 - DOUBLE_803e6798) <= FLOAT_803e67c0) {
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      if ((float)(local_28 - DOUBLE_803e6798) < FLOAT_803e6780) {
        uVar4 = 0;
      }
    }
    else {
      uVar4 = 0x7f;
    }
    FUN_8000b8a8((double)(FLOAT_803e67b8 + FLOAT_803de8e4),param_2,1,(byte)uVar4);
  }
  if ((param_6 & 4) != 0) {
    FUN_8000bb38(param_2,*(ushort *)(param_3 + 0x440));
    FUN_8000bb38(param_2,0x11b);
    if ((int)param_4 < 6) {
      if (FLOAT_803e67a8 < *(float *)(param_3 + 0x3f8)) {
        *(float *)(param_3 + 0x3f8) =
             -(FLOAT_803e67c4 * FLOAT_803dc074 - *(float *)(param_3 + 0x3f8));
      }
    }
    else {
      *(float *)(param_3 + 0x3f8) = *(float *)(param_3 + 0x3f8) + FLOAT_803dc074;
    }
    if (FLOAT_803e67a0 < *(float *)(param_3 + 0x3f8)) {
      *(float *)(param_3 + 0x3f8) = FLOAT_803e67a0;
    }
    if (*(float *)(param_3 + 0x3f8) < FLOAT_803e67c8) {
      *(float *)(param_3 + 0x3f8) = FLOAT_803e67c8;
    }
    FUN_8000b8a8((double)(*(float *)(param_3 + 0x3f8) * FLOAT_803e67d0 + FLOAT_803e67cc),param_2,2,
                 (byte)(int)*(float *)(param_3 + 0x3f8));
    if ((int)param_4 < 6) {
      if (FLOAT_803e67d4 < *(float *)(param_3 + 0x3f4)) {
        *(float *)(param_3 + 0x3f4) =
             -(FLOAT_803e6790 * FLOAT_803dc074 - *(float *)(param_3 + 0x3f4));
      }
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,param_4 ^ 0x80000000);
      *(float *)(param_3 + 0x3f4) = FLOAT_803e67d4 + (float)(local_28 - DOUBLE_803e6798);
    }
    if (FLOAT_803e67d8 < *(float *)(param_3 + 0x3f4)) {
      *(float *)(param_3 + 0x3f4) = FLOAT_803e67d8;
    }
    if (*(float *)(param_3 + 0x3f4) < FLOAT_803e67dc) {
      *(float *)(param_3 + 0x3f4) = FLOAT_803e67dc;
    }
    FUN_8000b8a8((double)(*(float *)(param_3 + 0x3f4) / FLOAT_803e67e0),param_2,4,
                 (byte)(int)*(float *)(param_3 + 0x3f4));
    FUN_80098608((double)FLOAT_803e6790,(double)(*(float *)(param_3 + 0x3f4) / FLOAT_803e67f0));
    FUN_80098608((double)FLOAT_803e6790,(double)(*(float *)(param_3 + 0x3f4) / FLOAT_803e67f0));
  }
  FUN_801ea238();
  return;
}

