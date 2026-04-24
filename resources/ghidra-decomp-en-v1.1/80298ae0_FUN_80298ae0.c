// Function: FUN_80298ae0
// Entry: 80298ae0
// Size: 428 bytes

/* WARNING: Removing unreachable block (ram,0x80298c68) */
/* WARNING: Removing unreachable block (ram,0x80298af0) */

int FUN_80298ae0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)

{
  short sVar1;
  float fVar2;
  int iVar3;
  undefined *puVar4;
  float *pfVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_11 = 0;
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xfb,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8bc0;
    fVar2 = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x284) = fVar2;
    *(float *)(param_10 + 0x280) = fVar2;
    *(float *)(param_9 + 0x12) = fVar2;
    *(float *)(param_9 + 0x14) = fVar2;
    *(float *)(param_9 + 0x16) = fVar2;
  }
  iVar3 = FUN_8029c15c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (iVar3 == 0) {
    (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,1);
    sVar1 = *param_9;
    *(short *)(iVar6 + 0x484) = sVar1;
    *(short *)(iVar6 + 0x478) = sVar1;
    puVar4 = (undefined *)0x2;
    pfVar5 = (float *)*DAT_803dd70c;
    (*(code *)pfVar5[8])(param_1,param_9,param_10);
    if (*(char *)(param_10 + 0x346) == '\0') {
      if (FLOAT_803e8bc4 < *(float *)(param_9 + 0x4c)) {
        if (*(char *)(param_10 + 0x349) != '\x01') {
          if ((DAT_803df0cc != 0) && ((*(byte *)(iVar6 + 0x3f4) >> 6 & 1) != 0)) {
            *(undefined *)(iVar6 + 0x8b4) = 0;
            *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xf7;
          }
          *(code **)(param_10 + 0x308) = FUN_802a58ac;
          return -1;
        }
        iVar6 = FUN_8029a5a4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,param_10,puVar4,pfVar5,param_13,param_14,param_15,param_16);
        if (iVar6 != 0) {
          return iVar6;
        }
      }
      iVar3 = 0;
    }
    else {
      *(code **)(param_10 + 0x308) = FUN_8029d028;
      iVar3 = 0x25;
    }
  }
  return iVar3;
}

