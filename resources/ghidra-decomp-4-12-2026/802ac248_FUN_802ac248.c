// Function: FUN_802ac248
// Entry: 802ac248
// Size: 1236 bytes

/* WARNING: Removing unreachable block (ram,0x802ac6f8) */
/* WARNING: Removing unreachable block (ram,0x802ac258) */

void FUN_802ac248(double param_1,undefined4 param_2,int param_3,int param_4)

{
  float fVar1;
  byte bVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_40;
  undefined8 local_38;
  
  uVar5 = (int)*(short *)(param_4 + 0x478) - (uint)*(ushort *)(param_4 + 0x492);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  if (((*(byte *)(param_4 + 0x3f1) >> 5 & 1) != 0) || ((*(byte *)(param_4 + 0x3f0) >> 4 & 1) != 0))
  {
    uVar5 = 0;
  }
  fVar1 = FLOAT_803e8b30 * (*(float *)(param_3 + 0x294) - FLOAT_803e8b34) + FLOAT_803e8b78;
  if (fVar1 < FLOAT_803e8b3c) {
    fVar1 = FLOAT_803e8b3c;
  }
  local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
  iVar6 = (int)((float)(local_58 - DOUBLE_803e8b58) * FLOAT_803e8c5c * fVar1);
  if (iVar6 < -0xccc) {
    iVar6 = -0xccc;
  }
  else if (0xccc < iVar6) {
    iVar6 = 0xccc;
  }
  uVar5 = iVar6 - (uint)*(ushort *)(param_4 + 0x4d0);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  dVar7 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                      DOUBLE_803e8b58),(double)FLOAT_803e8b4c,(double)FLOAT_803dc074
                      );
  local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(param_4 + 0x4d0) ^ 0x80000000);
  *(short *)(param_4 + 0x4d0) = (short)(int)((double)(float)(local_40 - DOUBLE_803e8b58) + dVar7);
  iVar6 = FUN_802ab930();
  if ((((iVar6 == 0) || (bVar2 = *(byte *)(param_4 + 0x3f0), (char)bVar2 < '\0')) ||
      ((bVar2 >> 6 & 1) != 0)) || (((bVar2 >> 4 & 1) != 0 || ((bVar2 >> 5 & 1) != 0)))) {
    iVar6 = 0;
  }
  else {
    uVar5 = FUN_80021884();
    uVar5 = (uVar5 & 0xffff) - (uint)*(ushort *)(param_4 + 0x478);
    if (0x8000 < (int)uVar5) {
      uVar5 = uVar5 - 0xffff;
    }
    if ((int)uVar5 < -0x8000) {
      uVar5 = uVar5 + 0xffff;
    }
    fVar1 = FLOAT_803e8b78 -
            (*(float *)(param_3 + 0x294) - FLOAT_803e8b34) /
            (*(float *)(param_4 + 0x404) - FLOAT_803e8b34);
    fVar3 = FLOAT_803e8b3c;
    if ((FLOAT_803e8b3c <= fVar1) && (fVar3 = fVar1, FLOAT_803e8b78 < fVar1)) {
      fVar3 = FLOAT_803e8b78;
    }
    fVar3 = FLOAT_803e8d5c * fVar3 + FLOAT_803e8d8c;
    uVar5 = uVar5 ^ 0x80000000;
    local_38 = (double)CONCAT44(0x43300000,uVar5);
    fVar1 = FLOAT_803e8d90 * -fVar3;
    if (fVar1 <= (float)(local_38 - DOUBLE_803e8b58)) {
      local_38 = (double)CONCAT44(0x43300000,uVar5);
      fVar1 = FLOAT_803e8d90 * fVar3;
      if ((float)(local_38 - DOUBLE_803e8b58) <= fVar1) {
        local_40 = (double)CONCAT44(0x43300000,uVar5);
        fVar1 = (float)(local_40 - DOUBLE_803e8b58);
      }
    }
    iVar6 = (int)fVar1;
  }
  if (((*(byte *)(param_4 + 0x3f1) >> 5 & 1) == 0) && ((*(byte *)(param_4 + 0x3f0) >> 4 & 1) == 0))
  {
    iVar4 = *(int *)(param_4 + 0x480);
  }
  else {
    iVar4 = 0;
  }
  if (iVar4 < -0x28) {
    iVar4 = -0x28;
  }
  else if (0x28 < iVar4) {
    iVar4 = 0x28;
  }
  iVar6 = iVar6 + iVar4 * 0xb6;
  if (iVar6 < -0x3ffc) {
    iVar6 = -0x3ffc;
  }
  else if (0x3ffc < iVar6) {
    iVar6 = 0x3ffc;
  }
  uVar5 = iVar6 - (uint)*(ushort *)(param_4 + 0x4d4);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  local_38 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
  uVar5 = (uint)((float)(local_38 - DOUBLE_803e8b58) * FLOAT_803e8b4c);
  if ((int)uVar5 < -0x16c) {
    uVar5 = 0xfffffe94;
  }
  else if (0x16c < (int)uVar5) {
    uVar5 = 0x16c;
  }
  local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(param_4 + 0x4d4) ^ 0x80000000);
  *(short *)(param_4 + 0x4d4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e8b58) *
                    FLOAT_803dc074 + (float)(local_50 - DOUBLE_803e8b58));
  *(short *)(param_4 + 0x4d2) = *(short *)(param_4 + 0x4d4) / 2;
  iVar6 = (int)(FLOAT_803e8d90 * (float)((double)FLOAT_803e8b70 * -param_1)) -
          (uint)*(ushort *)(param_4 + 0x4d6);
  if (0x8000 < iVar6) {
    iVar6 = iVar6 + -0xffff;
  }
  if (iVar6 < -0x8000) {
    iVar6 = iVar6 + 0xffff;
  }
  *(short *)(param_4 + 0x4d6) = *(short *)(param_4 + 0x4d6) + (short)iVar6;
  return;
}

