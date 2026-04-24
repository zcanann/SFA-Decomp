// Function: FUN_801e72f8
// Entry: 801e72f8
// Size: 1052 bytes

void FUN_801e72f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  undefined4 local_28;
  int local_24 [9];
  
  uVar12 = FUN_80286840();
  puVar5 = (ushort *)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  iVar6 = FUN_8002bac4();
  iVar10 = *(int *)(puVar5 + 0x5c);
  if (*(char *)(iVar8 + 0x27a) != '\0') {
    local_24[2] = FUN_80022264(500,1000);
    local_24[2] = local_24[2] ^ 0x80000000;
    local_24[1] = 0x43300000;
    *(float *)(iVar10 + 0x9c0) = (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e6698)
    ;
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) & 0xf7;
  }
  if ((*(byte *)(iVar10 + 0x9d4) & 8) == 0) {
    if ((puVar5[0x50] != 0x12) && (puVar5[0x50] != 0)) {
      FUN_8003042c((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e667c;
    }
  }
  else if (*(char *)(iVar8 + 0x346) != '\0') {
    if ((puVar5[0x50] != 0x11) || ((double)*(float *)(iVar8 + 0x2a0) <= (double)FLOAT_803e6674)) {
      if (puVar5[0x50] != 0) {
        FUN_8003042c((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar5,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      }
    }
    else {
      FUN_8003042c((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,0x12,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    *(float *)(iVar8 + 0x2a0) = FLOAT_803e667c;
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) & 0xf7;
    local_24[2] = FUN_80022264(500,1000);
    local_24[2] = local_24[2] ^ 0x80000000;
    local_24[1] = 0x43300000;
    *(float *)(iVar10 + 0x9c0) = (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e6698)
    ;
  }
  *(float *)(iVar10 + 0x9c0) = *(float *)(iVar10 + 0x9c0) - FLOAT_803dc074;
  if ((*(float *)(iVar10 + 0x9c0) <= FLOAT_803e6674) && ((*(byte *)(iVar10 + 0x9d4) & 8) == 0)) {
    FUN_8000bb38((uint)puVar5,0x40d);
    if (puVar5[0x50] == 0x12) {
      FUN_8003042c((double)FLOAT_803e66a0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,0x11,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e66a4;
    }
    else {
      uVar7 = FUN_80022264(0,1);
      FUN_8003042c((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,(int)*(short *)(&DAT_803dcd08 + uVar7 * 2),0,in_r6,in_r7,in_r8,in_r9,
                   in_r10);
      *(undefined4 *)(iVar8 + 0x2a0) = *(undefined4 *)(&DAT_803dcd0c + uVar7 * 4);
    }
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) | 8;
  }
  uVar7 = FUN_80020078(0x617);
  if (uVar7 == 0) {
    local_28 = 4;
    psVar9 = *(short **)(iVar10 + 0x9b0);
    uVar7 = FUN_800138e4(psVar9);
    if (uVar7 == 0) {
      FUN_80013978(psVar9,(uint)&local_28);
    }
  }
  else {
    dVar11 = FUN_801e823c(puVar5,iVar6,0);
    fVar1 = FLOAT_803e6674;
    if ((double)FLOAT_803e66b0 < dVar11) {
      fVar1 = FLOAT_803e66ac;
    }
    *(float *)(iVar8 + 0x280) =
         FLOAT_803e66a8 * (fVar1 - *(float *)(iVar8 + 0x280)) * FLOAT_803dc074 +
         *(float *)(iVar8 + 0x280);
    if (FLOAT_803e66b4 < *(float *)(iVar8 + 0x280)) {
      *(float *)(iVar8 + 0x280) = FLOAT_803e6674;
    }
    *(float *)(iVar8 + 0x280) = FLOAT_803e6674;
    iVar6 = FUN_80065fcc((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                         (double)*(float *)(puVar5 + 10),puVar5,local_24,0,0);
    fVar4 = FLOAT_803e6678;
    fVar3 = FLOAT_803e6674;
    iVar8 = 0;
    fVar1 = FLOAT_803e66b8;
    if (0 < iVar6) {
      do {
        fVar2 = **(float **)(local_24[0] + iVar8) - *(float *)(puVar5 + 8);
        if (fVar2 < fVar3) {
          fVar2 = -fVar2;
        }
        if (fVar2 < fVar1) {
          *(float *)(iVar10 + 0x9bc) = fVar4 + **(float **)(local_24[0] + iVar8);
          fVar1 = fVar2;
        }
        iVar8 = iVar8 + 4;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    local_24[2] = (int)*(ushort *)(iVar10 + 0x9ca);
    local_24[1] = 0x43300000;
    dVar11 = (double)FUN_802945e0();
    *(float *)(puVar5 + 8) =
         (float)((double)*(float *)(iVar10 + 0x9b8) * dVar11 + (double)*(float *)(iVar10 + 0x9bc));
    uVar7 = (uint)*(ushort *)(iVar10 + 0x9ca) + (uint)DAT_803dc070 * 0x100;
    if (0xffff < uVar7) {
      local_24[2] = FUN_80022264(0xf,0x23);
      local_24[2] = local_24[2] ^ 0x80000000;
      local_24[1] = 0x43300000;
      *(float *)(iVar10 + 0x9b8) =
           FLOAT_803e6688 * (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e6698);
    }
    *(short *)(iVar10 + 0x9ca) = (short)uVar7;
    iVar6 = FUN_8003811c((int)puVar5);
    if (iVar6 != 0) {
      uVar7 = FUN_80022264(0,2);
      (**(code **)(*DAT_803dd6d4 + 0x48))(uVar7,puVar5,0xffffffff);
    }
  }
  FUN_8028688c();
  return;
}

