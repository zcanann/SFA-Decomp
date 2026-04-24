// Function: FUN_802a8350
// Entry: 802a8350
// Size: 816 bytes

undefined4 FUN_802a8350(int param_1,int param_2,int param_3,char *param_4,int param_5)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  float **ppfVar6;
  int iVar7;
  float **local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  param_4[3] = '\0';
  param_4[99] = param_4[99] & 0x7fU | 0x80;
  if ((*(byte *)(param_3 + 0x52) & 8) == 0) {
    param_4[99] = param_4[99] & 0x7f;
  }
  fVar1 = FLOAT_803e7e98;
  *(float *)(param_4 + 0x48) =
       FLOAT_803e7e98 * (*(float *)(param_3 + 8) - *(float *)(param_3 + 4)) +
       *(float *)(param_3 + 4);
  *(undefined4 *)(param_4 + 0x4c) = *(undefined4 *)(param_3 + 0xc);
  *(float *)(param_4 + 0x50) =
       fVar1 * (*(float *)(param_3 + 0x18) - *(float *)(param_3 + 0x14)) +
       *(float *)(param_3 + 0x14);
  if (param_5 == 0) {
    *(undefined4 *)(param_4 + 0x28) = *(undefined4 *)(param_3 + 0x1c);
    *(undefined4 *)(param_4 + 0x2c) = *(undefined4 *)(param_3 + 0x20);
    *(undefined4 *)(param_4 + 0x30) = *(undefined4 *)(param_3 + 0x24);
    *(undefined4 *)(param_4 + 0x34) = *(undefined4 *)(param_3 + 0x28);
  }
  else {
    *(float *)(param_4 + 0x28) = -*(float *)(param_3 + 0x1c);
    *(float *)(param_4 + 0x2c) = -*(float *)(param_3 + 0x20);
    *(float *)(param_4 + 0x30) = -*(float *)(param_3 + 0x24);
    *(float *)(param_4 + 0x34) = -*(float *)(param_3 + 0x28);
  }
  *(float *)(param_4 + 0x38) = -*(float *)(param_3 + 0x24);
  fVar1 = FLOAT_803e7ea4;
  *(float *)(param_4 + 0x3c) = FLOAT_803e7ea4;
  *(undefined4 *)(param_4 + 0x40) = *(undefined4 *)(param_3 + 0x1c);
  *(float *)(param_4 + 0x44) =
       -(*(float *)(param_4 + 0x50) * *(float *)(param_4 + 0x40) +
        *(float *)(param_4 + 0x48) * *(float *)(param_4 + 0x38) +
        *(float *)(param_4 + 0x4c) * *(float *)(param_4 + 0x3c));
  *(undefined4 *)(param_4 + 0x54) = *(undefined4 *)(param_2 + 0x768);
  *(float *)(param_4 + 0x58) = fVar1;
  *(undefined4 *)(param_4 + 0x5c) = *(undefined4 *)(param_2 + 0x770);
  *(float *)(param_4 + 0x18) =
       *(float *)(param_4 + 0x44) +
       *(float *)(param_4 + 0x5c) * *(float *)(param_4 + 0x40) +
       *(float *)(param_4 + 0x54) * *(float *)(param_4 + 0x38) +
       *(float *)(param_4 + 0x58) * *(float *)(param_4 + 0x3c);
  param_4[0x62] = *(char *)(param_3 + 0x53);
  if ((*(float *)(param_4 + 0x18) <= FLOAT_803e80a4) ||
     (FLOAT_803e80a8 <= *(float *)(param_4 + 0x18))) {
    uVar5 = 0;
  }
  else {
    *(undefined4 *)(param_4 + 8) = *(undefined4 *)(param_3 + 0xc);
    FUN_80247778(-(double)fRam803dc6bc,param_3 + 0x1c,&local_34);
    FUN_80247730(param_4 + 0x48,&local_34,&local_34);
    local_30 = *(float *)(param_3 + 0x3c);
    iVar4 = FUN_80065e50((double)local_34,(double)local_30,(double)local_2c,param_1,&local_38,0,
                         0x204);
    iVar3 = -1;
    iVar7 = 0;
    ppfVar6 = local_38;
    fVar1 = FLOAT_803e80ac;
    if (0 < iVar4) {
      do {
        if (FLOAT_803e80b0 < (*ppfVar6)[2]) {
          fVar2 = local_30 - **ppfVar6;
          if (fVar2 < FLOAT_803e7ea4) {
            fVar2 = -fVar2;
          }
          if (fVar2 < fVar1) {
            iVar3 = iVar7;
            fVar1 = fVar2;
          }
        }
        ppfVar6 = ppfVar6 + 1;
        iVar7 = iVar7 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    *(float *)(param_4 + 4) = *local_38[iVar3];
    param_4[1] = (char)(int)((FLOAT_803e80b4 +
                             (*(float *)(param_3 + 0x3c) - *(float *)(param_4 + 8))) /
                            FLOAT_803e80b8);
    *(float *)(param_4 + 0xc) =
         (*(float *)(param_3 + 0x3c) - *(float *)(param_4 + 8)) /
         (float)((double)CONCAT44(0x43300000,(int)param_4[1] ^ 0x80000000) - DOUBLE_803e7ec0);
    if (*(float *)(param_1 + 0x10) <= *(float *)(param_4 + 4) - FLOAT_803e7ed8) {
      *param_4 = '\x01';
    }
    else {
      *param_4 = param_4[1] + -3;
    }
    uVar5 = 1;
  }
  return uVar5;
}

