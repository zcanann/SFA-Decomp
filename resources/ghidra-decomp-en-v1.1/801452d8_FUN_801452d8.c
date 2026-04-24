// Function: FUN_801452d8
// Entry: 801452d8
// Size: 648 bytes

void FUN_801452d8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = FUN_80144994(param_9,param_10);
  if (iVar2 == 0) {
    dVar5 = (double)FUN_802945e0();
    param_10[0x1cb] = (int)(float)((double)*(float *)(param_9 + 0x18) - dVar5);
    param_10[0x1cc] = *(int *)(param_9 + 0x1c);
    dVar6 = (double)FLOAT_803e30e4;
    dVar5 = (double)FUN_80294964();
    param_10[0x1cd] = (int)(float)((double)*(float *)(param_9 + 0x20) - dVar5);
    iVar2 = FUN_8013b6f0((double)FLOAT_803e310c,dVar6,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar2 != 1) {
      param_10[0x1d0] = (int)((float)param_10[0x1d0] - FLOAT_803dc074);
      if ((float)param_10[0x1d0] <= FLOAT_803e306c) {
        uVar3 = FUN_80022264(500,0x2ee);
        param_10[0x1d0] =
             (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar4 = FUN_8000b598(param_9,0x10), !bVar4)))) {
          FUN_800394f0(param_9,iVar2 + 0x3a8,0x360,0x500,0xffffffff,0);
        }
      }
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
        param_10[0x1e7] = (int)FLOAT_803e30d0;
        param_10[0x20e] = (int)FLOAT_803e306c;
        FUN_80148ff0();
      }
      else {
        sVar1 = *(short *)(param_9 + 0xa0);
        if (sVar1 != 0x31) {
          if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
            if ((param_10[0x15] & 0x8000000U) != 0) {
              FUN_8013a778((double)FLOAT_803e30cc,param_9,0x31,0);
            }
          }
          else {
            FUN_8013a778((double)FLOAT_803e30d4,param_9,0xd,0);
          }
        }
        FUN_80148ff0();
      }
    }
  }
  return;
}

