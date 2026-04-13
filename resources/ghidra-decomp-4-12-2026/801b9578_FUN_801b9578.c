// Function: FUN_801b9578
// Entry: 801b9578
// Size: 576 bytes

void FUN_801b9578(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  float fVar2;
  short *psVar3;
  float *pfVar4;
  float fVar5;
  float *pfVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar9;
  undefined8 extraout_f1;
  double dVar10;
  undefined8 uVar11;
  
  pfVar9 = *(float **)(param_9 + 0xb8);
  if ((pfVar9[0x27] == 0.0) || ((*(ushort *)((int)pfVar9[0x27] + 0xb0) & 0x40) == 0)) {
    if (*(char *)(pfVar9 + 0x2e) == '\0') {
      uVar1 = (uint)*(byte *)(param_9 + 0x36) + (uint)DAT_803dc070 * 4;
      if (0xff < uVar1) {
        uVar1 = 0xff;
      }
      *(char *)(param_9 + 0x36) = (char)uVar1;
      if ((*(byte *)((int)pfVar9 + 0xb6) & 1) == 0) {
        fVar2 = (float)FUN_8002e1ac((int)pfVar9[0x28]);
        pfVar9[0x27] = fVar2;
        pfVar4 = pfVar9 + 0x22;
        pfVar6 = pfVar9 + 0x23;
        uVar7 = 0;
        iVar8 = **(int **)((int)pfVar9[0x27] + 0x68);
        uVar11 = (**(code **)(iVar8 + 0x20))(pfVar9[0x27],pfVar9 + 0x21);
        pfVar9[0x24] = (float)((ulonglong)uVar11 >> 0x20);
        pfVar9[0x20] = 0.0;
        pfVar9[0x25] = (float)FUN_80010de0;
        pfVar9[0x26] = (float)&LAB_80010d74;
        FUN_80010a8c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,pfVar9,
                     (int)uVar11,pfVar4,pfVar6,uVar7,iVar8,in_r9,in_r10);
        *(byte *)((int)pfVar9 + 0xb6) = *(byte *)((int)pfVar9 + 0xb6) | 1;
      }
      FUN_80010340((double)pfVar9[0x29],pfVar9);
      fVar5 = pfVar9[4];
      fVar2 = pfVar9[0x24];
      *(float *)(param_9 + 0xc) = pfVar9[0x1a];
      if (-1 < *(char *)((int)pfVar9 + 0xb9)) {
        *(float *)(param_9 + 0x10) = FLOAT_803e57cc + pfVar9[0x1b];
      }
      *(float *)(param_9 + 0x14) = pfVar9[0x1c];
      if (((int)fVar5 >> 0x1f) +
          ((uint)((int)fVar2 - 4U <= (uint)fVar5) - ((int)((int)fVar2 - 4U) >> 0x1f)) != 0) {
        *(byte *)((int)pfVar9 + 0xb9) = *(byte *)((int)pfVar9 + 0xb9) & 0x7f | 0x80;
      }
      dVar10 = (double)FLOAT_803dc074;
      *(short *)(pfVar9 + 0x2d) =
           (short)(int)(dVar10 * (double)pfVar9[0x2b] +
                       (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pfVar9 + 0x2d))
                                      - DOUBLE_803e57d8));
      if (*(char *)((int)pfVar9 + 0xb9) < '\0') {
        *(float *)(param_9 + 0x10) = -(FLOAT_803e57d0 * FLOAT_803dc074 - *(float *)(param_9 + 0x10))
        ;
        if (*(float *)(param_9 + 0x10) < pfVar9[0x1b]) {
          FUN_80035ff8(param_9);
          *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x100;
          psVar3 = (short *)FUN_8002bac4();
          FUN_80297480(psVar3,param_9);
        }
        if ((double)*(float *)(param_9 + 0x10) <
            (double)(float)((double)pfVar9[0x1b] - (double)FLOAT_803e57d4)) {
          FUN_8002cc9c((double)pfVar9[0x1b],(double)*(float *)(param_9 + 0x10),dVar10,param_4,
                       param_5,param_6,param_7,param_8,param_9);
        }
      }
    }
  }
  else {
    *(byte *)((int)pfVar9 + 0xb6) = *(byte *)((int)pfVar9 + 0xb6) & 0xfe;
    pfVar9[0x27] = 0.0;
  }
  return;
}

