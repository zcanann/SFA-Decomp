// Function: FUN_802aca8c
// Entry: 802aca8c
// Size: 1200 bytes

void FUN_802aca8c(undefined4 param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  short sVar4;
  int iVar3;
  int iVar5;
  uint uVar6;
  double dVar7;
  undefined8 local_78;
  undefined8 local_70;
  
  iVar5 = FUN_802ab930();
  if (((iVar5 == 0) || ((char)*(byte *)(param_3 + 0x3f0) < '\0')) ||
     ((*(byte *)(param_3 + 0x3f0) >> 6 & 1) != 0)) {
    iVar5 = 0;
    *(undefined2 *)(param_3 + 0x4a0) = 0;
  }
  else {
    sVar4 = *(short *)(param_3 + 0x4a0) + -1;
    *(short *)(param_3 + 0x4a0) = sVar4;
    if (sVar4 < 1) {
      uVar6 = FUN_80022264(0x78,0xf0);
      *(short *)(param_3 + 0x4a0) = (short)uVar6;
      uVar6 = FUN_80022264(0,0x28);
      *(short *)(param_3 + 0x4a2) = (short)uVar6;
    }
    uVar6 = FUN_80021884();
    uVar6 = (uVar6 & 0xffff) - (uint)*(ushort *)(param_3 + 0x478);
    if (0x8000 < (int)uVar6) {
      uVar6 = uVar6 - 0xffff;
    }
    if ((int)uVar6 < -0x8000) {
      uVar6 = uVar6 + 0xffff;
    }
    fVar1 = FLOAT_803e8b78 -
            (*(float *)(param_2 + 0x294) - FLOAT_803e8b34) /
            (*(float *)(param_3 + 0x404) - FLOAT_803e8b34);
    fVar2 = FLOAT_803e8b3c;
    if ((FLOAT_803e8b3c <= fVar1) && (fVar2 = fVar1, FLOAT_803e8b78 < fVar1)) {
      fVar2 = FLOAT_803e8b78;
    }
    fVar2 = FLOAT_803e8d5c * fVar2 + FLOAT_803e8d8c;
    uVar6 = uVar6 ^ 0x80000000;
    local_78 = (double)CONCAT44(0x43300000,uVar6);
    fVar1 = FLOAT_803e8d90 * -fVar2;
    if (fVar1 <= (float)(local_78 - DOUBLE_803e8b58)) {
      local_78 = (double)CONCAT44(0x43300000,uVar6);
      fVar1 = FLOAT_803e8d90 * fVar2;
      if ((float)(local_78 - DOUBLE_803e8b58) <= fVar1) {
        local_70 = (double)CONCAT44(0x43300000,uVar6);
        fVar1 = (float)(local_70 - DOUBLE_803e8b58);
      }
    }
    iVar5 = (int)fVar1;
  }
  if ((*(byte *)(param_3 + 0x3f1) >> 5 & 1) == 0) {
    iVar3 = *(int *)(param_3 + 0x480);
  }
  else {
    iVar3 = 0;
  }
  if (iVar3 < -0x28) {
    iVar3 = -0x28;
  }
  else if (0x28 < iVar3) {
    iVar3 = 0x28;
  }
  iVar5 = iVar5 + iVar3 * 0xb6;
  if (iVar5 < -0x3ffc) {
    iVar5 = -0x3ffc;
  }
  else if (0x3ffc < iVar5) {
    iVar5 = 0x3ffc;
  }
  uVar6 = iVar5 - (uint)*(ushort *)(param_3 + 0x4d4);
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
  uVar6 = (uint)((float)(local_70 - DOUBLE_803e8b58) * FLOAT_803e8b4c);
  if ((int)uVar6 < -0x16c) {
    uVar6 = 0xfffffe94;
  }
  else if (0x16c < (int)uVar6) {
    uVar6 = 0x16c;
  }
  *(short *)(param_3 + 0x4d4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e8b58) *
                    FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d4) ^ 0x80000000
                                           ) - DOUBLE_803e8b58));
  *(short *)(param_3 + 0x4d2) = *(short *)(param_3 + 0x4d4) / 2;
  uVar6 = (int)*(short *)(param_3 + 0x478) - (uint)*(ushort *)(param_3 + 0x492);
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  if ((*(byte *)(param_3 + 0x3f1) >> 5 & 1) != 0) {
    uVar6 = 0;
  }
  fVar1 = FLOAT_803e8b30 * (*(float *)(param_2 + 0x294) - FLOAT_803e8b34) + FLOAT_803e8b78;
  if (fVar1 < FLOAT_803e8b3c) {
    fVar1 = FLOAT_803e8b3c;
  }
  iVar5 = (int)((float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e8b58) *
               FLOAT_803e8c5c * fVar1);
  if (iVar5 < -0xccc) {
    iVar5 = -0xccc;
  }
  else if (0xccc < iVar5) {
    iVar5 = 0xccc;
  }
  uVar6 = iVar5 - (uint)*(ushort *)(param_3 + 0x4d0);
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  dVar7 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                      DOUBLE_803e8b58),(double)FLOAT_803e8b4c,(double)FLOAT_803dc074
                      );
  *(short *)(param_3 + 0x4d0) =
       (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_3 + 0x4d0) ^ 0x80000000)
                                   - DOUBLE_803e8b58) + dVar7);
  dVar7 = (double)FUN_802932a4((double)FLOAT_803e8bb4,(double)FLOAT_803dc074);
  *(short *)(param_3 + 0x4d6) =
       (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_3 + 0x4d6) ^ 0x80000000)
                                   - DOUBLE_803e8b58) * dVar7);
  return;
}

