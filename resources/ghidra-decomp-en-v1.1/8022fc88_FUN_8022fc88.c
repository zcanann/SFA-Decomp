// Function: FUN_8022fc88
// Entry: 8022fc88
// Size: 1044 bytes

void FUN_8022fc88(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  short sVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  bool bVar5;
  double dVar6;
  double dVar7;
  int local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  iVar2 = FUN_8022de2c();
  pfVar4 = *(float **)(param_9 + 0x5c);
  dVar7 = (double)*pfVar4;
  dVar6 = (double)FLOAT_803e7d14;
  if ((dVar7 <= dVar6) ||
     (*pfVar4 = (float)(dVar7 - (double)FLOAT_803dc074), dVar6 < (double)*pfVar4)) {
    if ((iVar2 == 0) || (iVar3 = FUN_8022ddd4(iVar2), iVar3 == 0)) {
      if (-1 < *(char *)(pfVar4 + 1)) {
        iVar3 = FUN_8022de2c();
        if (iVar3 == 0) {
          bVar5 = false;
        }
        else {
          bVar5 = *(float *)(param_9 + 10) - *(float *)(iVar3 + 0x14) < FLOAT_803e7d18;
        }
        if (bVar5) {
          uStack_2c = (uint)*(byte *)(param_9 + 0x1b);
          local_30 = 0x43300000;
          iVar3 = (int)(FLOAT_803e7d1c * FLOAT_803dc074 +
                       (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e7d28));
          local_28 = (longlong)iVar3;
          if (0xff < iVar3) {
            iVar3 = 0xff;
          }
          *(char *)(param_9 + 0x1b) = (char)iVar3;
          param_9[3] = param_9[3] & 0xbfff;
          dVar7 = (double)FLOAT_803e7d20;
          dVar6 = (double)FLOAT_803dc074;
          uStack_1c = (int)*param_9 ^ 0x80000000;
          local_20 = 0x43300000;
          iVar3 = (int)(dVar7 * dVar6 +
                       (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7d08));
          local_18 = (longlong)iVar3;
          *param_9 = (short)iVar3;
          FUN_80035eec((int)param_9,0x13,0,0);
          if ((*(byte *)(pfVar4 + 1) >> 6 & 1) == 0) {
            iVar3 = FUN_80036974((int)param_9,local_38,(int *)0x0,(uint *)0x0);
            if (((iVar3 != 0) && (local_38[0] != 0)) &&
               ((*(short *)(local_38[0] + 0x46) == 0x604 ||
                (*(short *)(local_38[0] + 0x46) == 0x605)))) {
              FUN_8022dbe4(iVar2,0xf);
              *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf | 0x40;
              FUN_8002b95c((int)param_9,1);
              FUN_8009adfc((double)FLOAT_803e7d24,dVar6,dVar7,param_4,param_5,param_6,param_7,
                           param_8,param_9,1,0,0,0,0,0,2);
            }
            if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) &&
               (iVar3 = FUN_8022de2c(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar3)) {
              param_9[3] = param_9[3] | 0x4000;
              FUN_80035ff8((int)param_9);
              FUN_8009adfc((double)FLOAT_803e7d24,dVar6,dVar7,param_4,param_5,param_6,param_7,
                           param_8,param_9,1,0,0,0,0,0,2);
            }
          }
          else if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) &&
                  (iVar3 = FUN_8022de2c(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar3)) {
            FUN_8022dbe4(iVar2,0x19);
            *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f | 0x80;
            param_9[3] = param_9[3] | 0x4000;
            FUN_80035ff8((int)param_9);
          }
          if (iVar2 == 0) {
            return;
          }
          if (-1 < *(char *)(pfVar4 + 1)) {
            return;
          }
          sVar1 = param_9[0x23];
          if (sVar1 == 0x6d8) {
            FUN_8000bb38((uint)param_9,0x2a8);
            FUN_8022dca0(iVar2);
            return;
          }
          if (0x6d7 < sVar1) {
            if (sVar1 == 0x6db) {
              FUN_8000bb38((uint)param_9,0x2a8);
              FUN_8022dc78(iVar2);
              return;
            }
            if (0x6da < sVar1) {
              return;
            }
            if (sVar1 < 0x6da) {
              FUN_8000bb38((uint)param_9,0x2a8);
              FUN_8022dc8c(iVar2);
              return;
            }
            FUN_8000bb38((uint)param_9,0x2a8);
            FUN_8022dc64(iVar2);
            return;
          }
          if (sVar1 == 0x609) {
            FUN_8000bb38((uint)param_9,0x2a6);
            FUN_8022ddb4(iVar2);
            return;
          }
          if (0x608 < sVar1) {
            return;
          }
          if (sVar1 < 0x608) {
            return;
          }
          FUN_8000bb38((uint)param_9,0x2a7);
          FUN_8022dd94(iVar2);
          return;
        }
      }
      param_9[3] = param_9[3] | 0x4000;
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    else {
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f;
      param_9[3] = param_9[3] & 0xbfff;
      FUN_80036018((int)param_9);
    }
  }
  else {
    FUN_8002cc9c(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

