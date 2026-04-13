// Function: FUN_802a8ab0
// Entry: 802a8ab0
// Size: 816 bytes

undefined4 FUN_802a8ab0(int param_1,int param_2,int param_3,char *param_4,int param_5)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  param_4[3] = '\0';
  param_4[99] = param_4[99] & 0x7fU | 0x80;
  if ((*(byte *)(param_3 + 0x52) & 8) == 0) {
    param_4[99] = param_4[99] & 0x7f;
  }
  fVar1 = FLOAT_803e8b30;
  *(float *)(param_4 + 0x48) =
       FLOAT_803e8b30 * (*(float *)(param_3 + 8) - *(float *)(param_3 + 4)) +
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
  fVar1 = FLOAT_803e8b3c;
  *(float *)(param_4 + 0x3c) = FLOAT_803e8b3c;
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
  if ((*(float *)(param_4 + 0x18) <= FLOAT_803e8d3c) ||
     (FLOAT_803e8d40 <= *(float *)(param_4 + 0x18))) {
    uVar5 = 0;
  }
  else {
    *(undefined4 *)(param_4 + 8) = *(undefined4 *)(param_3 + 0xc);
    FUN_80247edc(-(double)fRam803dd324,(float *)(param_3 + 0x1c),&local_34);
    FUN_80247e94((float *)(param_4 + 0x48),&local_34,&local_34);
    local_30 = *(float *)(param_3 + 0x3c);
    iVar4 = FUN_80065fcc((double)local_34,(double)local_30,(double)local_2c,param_1,&local_38,0,
                         0x204);
    iVar3 = -1;
    iVar7 = 0;
    puVar6 = local_38;
    fVar1 = FLOAT_803e8d44;
    if (0 < iVar4) {
      do {
        if (FLOAT_803e8d48 < ((float *)*puVar6)[2]) {
          fVar2 = local_30 - *(float *)*puVar6;
          if (fVar2 < FLOAT_803e8b3c) {
            fVar2 = -fVar2;
          }
          if (fVar2 < fVar1) {
            iVar3 = iVar7;
            fVar1 = fVar2;
          }
        }
        puVar6 = puVar6 + 1;
        iVar7 = iVar7 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    *(undefined4 *)(param_4 + 4) = *(undefined4 *)local_38[iVar3];
    param_4[1] = (char)(int)((FLOAT_803e8d4c +
                             (*(float *)(param_3 + 0x3c) - *(float *)(param_4 + 8))) /
                            FLOAT_803e8d50);
    *(float *)(param_4 + 0xc) =
         (*(float *)(param_3 + 0x3c) - *(float *)(param_4 + 8)) /
         (float)((double)CONCAT44(0x43300000,(int)param_4[1] ^ 0x80000000) - DOUBLE_803e8b58);
    if (*(float *)(param_1 + 0x10) <= *(float *)(param_4 + 4) - FLOAT_803e8b70) {
      *param_4 = '\x01';
    }
    else {
      *param_4 = param_4[1] + -3;
    }
    uVar5 = 1;
  }
  return uVar5;
}

