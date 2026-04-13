// Function: FUN_801e997c
// Entry: 801e997c
// Size: 760 bytes

void FUN_801e997c(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined uVar5;
  float *pfVar6;
  double dVar7;
  
  pfVar6 = *(float **)(param_9 + 0xb8);
  iVar3 = FUN_8002bac4();
  switch(*(undefined2 *)(param_9 + 0xa0)) {
  case 0:
    sVar1 = *(short *)(pfVar6 + 5);
    uVar2 = (ushort)DAT_803dc070;
    *(ushort *)(pfVar6 + 5) = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 1) {
      FUN_8000bb38(param_9,0x13f);
      uVar4 = FUN_80022264(0xb4,300);
      *(short *)(pfVar6 + 5) = (short)uVar4;
    }
    dVar7 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar3 + 0x18));
    if (dVar7 < (double)FLOAT_803e673c) {
      if (iVar3 != 0) {
        param_4 = (double)pfVar6[3];
        param_3 = (double)pfVar6[1];
        param_2 = (double)*(float *)(iVar3 + 0xc);
        if (FLOAT_803e6738 <=
            (float)(param_4 +
                   (double)(float)(param_3 * param_2 +
                                  (double)(pfVar6[2] * *(float *)(iVar3 + 0x14))))) {
          pfVar6[4] = (float)&DAT_803dcd1c;
        }
        else {
          pfVar6[4] = (float)&DAT_803dcd18;
        }
      }
      FUN_8003042c((double)FLOAT_803e6738,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(uint)*(byte *)pfVar6[4],0,param_12,param_13,param_14,param_15,param_16);
      *pfVar6 = FLOAT_803e6740;
      FUN_8000bb38(param_9,0x140);
      FUN_8000facc();
    }
    break;
  case 1:
  case 4:
    if (*(char *)((int)pfVar6 + 0x16) != '\0') {
      dVar7 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar3 + 0x18));
      if (dVar7 <= (double)FLOAT_803e6744) {
        FUN_8003042c((double)FLOAT_803e6738,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,(uint)*(byte *)((int)pfVar6[4] + 1),0,param_12,param_13,param_14,
                     param_15,param_16);
        *pfVar6 = FLOAT_803e674c;
      }
      else {
        FUN_8003042c((double)FLOAT_803e6738,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,(uint)*(byte *)((int)pfVar6[4] + 2),0,param_12,param_13,param_14,
                     param_15,param_16);
        FUN_8000bb38(param_9,0x140);
        *pfVar6 = FLOAT_803e6748;
      }
    }
    break;
  case 2:
  case 5:
    FUN_8000bb38(param_9,0x141);
    dVar7 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar3 + 0x18));
    if ((double)FLOAT_803e6744 < dVar7) {
      FUN_8003042c((double)FLOAT_803e6738,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(uint)*(byte *)((int)pfVar6[4] + 2),0,param_12,param_13,param_14,param_15
                   ,param_16);
      FUN_8000b7dc(param_9,0x40);
      FUN_8000bb38(param_9,0x140);
      *pfVar6 = FLOAT_803e6748;
    }
    break;
  case 3:
  case 6:
    if ((*(float *)(param_9 + 0x98) <= FLOAT_803e6750) ||
       (dVar7 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar3 + 0x18)),
       (double)FLOAT_803e673c <= dVar7)) {
      if (*(char *)((int)pfVar6 + 0x16) != '\0') {
        FUN_8003042c((double)FLOAT_803e6738,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,param_12,param_13,param_14,param_15,param_16);
        *pfVar6 = FLOAT_803e6754;
        FUN_8000facc();
      }
    }
    else {
      if (iVar3 != 0) {
        param_4 = (double)pfVar6[3];
        param_3 = (double)pfVar6[1];
        param_2 = (double)*(float *)(iVar3 + 0xc);
        if (FLOAT_803e6738 <=
            (float)(param_4 +
                   (double)(float)(param_3 * param_2 +
                                  (double)(pfVar6[2] * *(float *)(iVar3 + 0x14))))) {
          pfVar6[4] = (float)&DAT_803dcd1c;
        }
        else {
          pfVar6[4] = (float)&DAT_803dcd18;
        }
      }
      FUN_8003042c((double)FLOAT_803e6738,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(uint)*(byte *)pfVar6[4],0,param_12,param_13,param_14,param_15,param_16);
      FUN_8000bb38(param_9,0x140);
      *pfVar6 = FLOAT_803e6740;
    }
  }
  uVar5 = FUN_8002fb40((double)*pfVar6,(double)FLOAT_803dc074);
  *(undefined *)((int)pfVar6 + 0x16) = uVar5;
  return;
}

