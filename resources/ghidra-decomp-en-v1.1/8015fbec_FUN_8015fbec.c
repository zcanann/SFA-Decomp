// Function: FUN_8015fbec
// Entry: 8015fbec
// Size: 944 bytes

void FUN_8015fbec(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  float fVar1;
  float fVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  double dVar8;
  undefined8 uVar9;
  uint uStack_38;
  int iStack_34;
  undefined4 uStack_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined8 local_20;
  
  pfVar7 = *(float **)(param_9 + 0x5c);
  if (pfVar7[1] != FLOAT_803e3acc) {
    pfVar7[1] = pfVar7[1] - FLOAT_803dc074;
    FUN_8009a010((double)FLOAT_803e3ac8,(double)(pfVar7[1] / FLOAT_803e3ad0),param_9,1,(int *)0x0);
    if (pfVar7[1] <= FLOAT_803e3acc) {
      pfVar7[1] = FLOAT_803e3acc;
    }
  }
  if ((*(byte *)((int)pfVar7 + 0x12) & 2) == 0) {
    piVar3 = (int *)FUN_800395a4((int)param_9,0);
    fVar1 = *pfVar7;
    if (FLOAT_803e3ad4 <= fVar1) {
      if (FLOAT_803e3ad8 - fVar1 < FLOAT_803dc074) {
        *pfVar7 = FLOAT_803e3acc;
      }
      else {
        *pfVar7 = fVar1 + FLOAT_803dc074;
      }
      *piVar3 = 0;
    }
    else {
      if ((int)fVar1 == 10) {
        *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) | 1;
      }
      local_20 = (double)(longlong)(int)*pfVar7;
      *piVar3 = (uint)(byte)(&DAT_80320bd0)[(int)*pfVar7] << 8;
      fVar2 = FLOAT_803e3ad4;
      fVar1 = *pfVar7 + FLOAT_803e3ac8;
      *pfVar7 = fVar1;
      if (fVar2 == fVar1) {
        uVar4 = FUN_80022264(0x10,0xf5);
        local_20 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        *pfVar7 = (float)(local_20 - DOUBLE_803e3ae0);
      }
    }
    iVar5 = FUN_8002bac4();
    fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(param_9 + 6);
    fVar2 = *(float *)(iVar5 + 0x14) - *(float *)(param_9 + 10);
    dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    uVar4 = (uint)dVar8;
    local_20 = (double)(longlong)(int)uVar4;
    if ((uVar4 & 0xffff) < (uint)*(ushort *)(pfVar7 + 3)) {
      if ((uint)*(ushort *)(pfVar7 + 3) <= (uint)*(ushort *)(pfVar7 + 4)) {
        *(undefined *)((int)pfVar7 + 0x12) = 5;
        *pfVar7 = FLOAT_803e3acc;
      }
      if ((*(byte *)((int)pfVar7 + 0x12) & 5) != 0) {
        local_2c = *(float *)(iVar5 + 0x18) - *(float *)(param_9 + 0xc);
        local_28 = *(float *)(iVar5 + 0x1c) - *(float *)(param_9 + 0xe);
        local_24 = *(float *)(iVar5 + 0x20) - *(float *)(param_9 + 0x10);
        dVar8 = (double)local_24;
        uVar6 = FUN_80021884();
        uVar6 = (uVar6 & 0xffff) - (uint)*param_9;
        if (0x8000 < (int)uVar6) {
          uVar6 = uVar6 - 0xffff;
        }
        if ((int)uVar6 < -0x8000) {
          uVar6 = uVar6 + 0xffff;
        }
        if (((uVar6 & 0xffff) < (uint)*(ushort *)((int)pfVar7 + 0xe)) ||
           ((0xffff - *(ushort *)((int)pfVar7 + 0xe) & 0xffff) < (uVar6 & 0xffff))) {
          uVar6 = FUN_80022264(0,99);
          if (((int)uVar6 < (int)(uint)*(byte *)(pfVar7 + 5)) ||
             ((*(byte *)((int)pfVar7 + 0x12) & 4) != 0)) {
            uVar9 = FUN_8000bb38((uint)param_9,0x268);
            FUN_8015fa5c(uVar9,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
          }
          else {
            FUN_8000bb38((uint)param_9,0x269);
          }
        }
        else {
          FUN_8000bb38((uint)param_9,0x269);
        }
      }
    }
    else if ((*(byte *)((int)pfVar7 + 0x12) & 1) != 0) {
      FUN_8000bb38((uint)param_9,0x269);
    }
    *(short *)(pfVar7 + 4) = (short)uVar4;
    iVar5 = FUN_80036974((int)param_9,&uStack_30,&iStack_34,&uStack_38);
    if ((iVar5 == 0xe) &&
       (*(char *)((int)pfVar7 + 0x13) = *(char *)((int)pfVar7 + 0x13) + -1,
       *(char *)((int)pfVar7 + 0x13) == '\0')) {
      FUN_80035ff8((int)param_9);
      param_9[3] = param_9[3] | 0x4000;
      *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) | 2;
      FUN_8000bb38((uint)param_9,0x26a);
      FUN_800201ac((int)*(short *)((int)pfVar7 + 10),1);
      pfVar7[1] = FLOAT_803e3ad0;
      FUN_8000bb38((uint)param_9,0x1ec);
    }
    *(byte *)((int)pfVar7 + 0x12) = *(byte *)((int)pfVar7 + 0x12) & 0xfa;
  }
  return;
}

