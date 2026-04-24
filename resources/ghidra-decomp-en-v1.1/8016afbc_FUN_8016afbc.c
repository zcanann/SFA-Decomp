// Function: FUN_8016afbc
// Entry: 8016afbc
// Size: 1428 bytes

void FUN_8016afbc(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 double param_5,double param_6,undefined8 param_7,undefined8 param_8,ushort *param_9
                 )

{
  bool bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  float local_68;
  float local_64;
  float local_60;
  float afStack_5c [3];
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  piVar5 = *(int **)(param_9 + 0x5c);
  iVar3 = FUN_80080490();
  if (iVar3 == 0) {
    uVar6 = extraout_f1;
    uVar4 = FUN_800803dc((float *)(piVar5 + 8));
    if (uVar4 == 0) {
      iVar3 = FUN_80080434((float *)(piVar5 + 9));
      if (iVar3 != 0) {
        FUN_80080404((float *)(piVar5 + 8),0x78);
      }
      if (*(int *)(param_9 + 0x62) != 0) {
        *piVar5 = *(int *)(param_9 + 0x62);
        param_9[0x62] = 0;
        param_9[99] = 0;
      }
      if ((*(byte *)(piVar5[7] + 0x12) >> 6 & 1) != 0) {
        piVar5[2] = (int)((float)piVar5[2] - FLOAT_803dc074);
        dVar7 = (double)(float)piVar5[2];
        if (dVar7 <= (double)FLOAT_803e3df8) {
          if (*(char *)(param_9 + 0x1b) == -1) {
            iVar3 = 2;
            do {
              dVar7 = (double)(**(code **)(*DAT_803dd708 + 8))
                                        (param_9,(int)*(short *)(piVar5[7] + 8),0,1,0xffffffff,0);
              bVar1 = iVar3 != 0;
              iVar3 = iVar3 + -1;
            } while (bVar1);
          }
          piVar5[2] = (int)FLOAT_803e3df8;
          if ((uint)*(byte *)(param_9 + 0x1b) < (uint)DAT_803dc070 << 3) {
            *(undefined *)(param_9 + 0x1b) = 0;
            FUN_8002cc9c(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
            ;
            return;
          }
          *(byte *)(param_9 + 0x1b) = *(byte *)(param_9 + 0x1b) - (char)((uint)DAT_803dc070 << 3);
        }
      }
      if (*(short *)(piVar5[7] + 10) != -1) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,(int)*(short *)(piVar5[7] + 10),0,1,0xffffffff,0);
      }
      iVar3 = FUN_80036f50((int)*(short *)(piVar5[7] + 0x10),param_9,(float *)0x0);
      if ((iVar3 != 0) &&
         (((*(byte *)(piVar5[7] + 0x12) >> 6 & 1) == 0 || ((float)piVar5[2] < FLOAT_803e3dfc)))) {
        if ((*(byte *)(piVar5[7] + 0x12) >> 4 & 1) == 0) {
          local_68 = *(float *)(iVar3 + 0x18);
          local_64 = *(float *)(iVar3 + 0xa8) * *(float *)(iVar3 + 8) * FLOAT_803e3e00 +
                     *(float *)(iVar3 + 0x1c);
          local_60 = *(float *)(iVar3 + 0x20);
        }
        else {
          FUN_80038524(iVar3,0,&local_68,&local_64,&local_60,0);
        }
        FUN_80247eb8(&local_68,(float *)(param_9 + 0xc),&local_50);
        FUN_80247f54(&local_50);
        FUN_80247ef8(&local_50,&local_50);
        FUN_80247eb8(&local_50,(float *)(piVar5 + 3),afStack_5c);
        piVar5[3] = (int)local_50;
        piVar5[4] = (int)local_4c;
        piVar5[5] = (int)local_48;
        FUN_80247edc((double)FLOAT_803e3df4,afStack_5c,afStack_5c);
        FUN_80247e94(&local_50,afStack_5c,&local_50);
        param_6 = (double)FLOAT_803e3df4;
        param_5 = (double)FLOAT_803e3dfc;
        *(float *)(param_9 + 0x12) =
             *(float *)(param_9 + 0x12) +
             (float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                             local_50 * (float)piVar5[1]) / param_5);
        *(float *)(param_9 + 0x16) =
             *(float *)(param_9 + 0x16) +
             (float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                             local_48 * (float)piVar5[1]) / param_5);
        if (-1 < *(char *)(piVar5[7] + 0x12)) {
          param_4 = (double)*(float *)(param_9 + 0x14);
          *(float *)(param_9 + 0x14) =
               (float)(param_4 +
                      (double)(float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                                              FLOAT_803e3e04 * local_4c * (float)piVar5[1]) /
                                     param_5));
        }
      }
      fVar2 = FLOAT_803e3e08;
      *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) * FLOAT_803e3e08;
      *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) * fVar2;
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e3e0c;
      if (*(char *)(piVar5[7] + 0x12) < '\0') {
        *(float *)(param_9 + 0x14) =
             *(float *)(param_9 + 0x14) -
             (FLOAT_803e3e10 * FLOAT_803dc074 * (float)piVar5[2]) / FLOAT_803e3e14;
      }
      dVar8 = DOUBLE_803e3e28;
      dVar7 = DOUBLE_803e3e20;
      if ((*(byte *)(piVar5[7] + 0x12) >> 5 & 1) == 0) {
        if (param_9[0x23] == 0x482) {
          uStack_3c = (uint)DAT_803dc070;
          local_40 = 0x43300000;
          uStack_34 = (int)(short)*param_9 ^ 0x80000000;
          local_38 = 0x43300000;
          iVar3 = (int)(FLOAT_803e3e18 * FLOAT_803dc9b0 *
                        (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3e20) +
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3e28));
          local_30 = (longlong)iVar3;
          *param_9 = (ushort)iVar3;
          uStack_24 = (uint)DAT_803dc070;
          local_28 = 0x43300000;
          uStack_1c = (int)(short)param_9[1] ^ 0x80000000;
          local_20 = 0x43300000;
          iVar3 = (int)(FLOAT_803dc9b4 * (float)((double)CONCAT44(0x43300000,uStack_24) - dVar7) +
                       (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar8));
          local_18 = (longlong)iVar3;
          param_9[1] = (ushort)iVar3;
          param_4 = dVar7;
        }
      }
      else {
        FUN_80222ba0((double)FLOAT_803e3df8,(double)FLOAT_803e3df0,param_9,(float *)(param_9 + 0x12)
                     ,10);
        param_9[2] = param_9[2] + (ushort)DAT_803dc070 * 0x500;
      }
      FUN_8000da78((uint)param_9,*(ushort *)(piVar5[7] + 2));
      dVar7 = (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074);
      dVar8 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),dVar7,dVar8,(int)param_9);
      FUN_80035eec((int)param_9,0x16,1,0);
      FUN_80036018((int)param_9);
      iVar3 = *(int *)(*(int *)(param_9 + 0x2a) + 0x50);
      if (((iVar3 != 0) && (*(ushort *)(iVar3 + 0x46) != param_9[0x23])) && (iVar3 != *piVar5)) {
        piVar5[2] = (int)FLOAT_803e3df8;
        FUN_80035ff8((int)param_9);
        if (*(short *)(piVar5[7] + 4) != -1) {
          FUN_8009adfc((double)FLOAT_803e3df4,dVar7,dVar8,param_4,param_5,param_6,param_7,param_8,
                       param_9,0,1,0,1,0,1,0);
          FUN_8000b4f0((uint)param_9,*(ushort *)(piVar5[7] + 4),3);
        }
        FUN_80080404((float *)(piVar5 + 8),0x78);
      }
    }
    else {
      iVar3 = FUN_80080434((float *)(piVar5 + 8));
      if (iVar3 != 0) {
        FUN_8002cc9c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      }
    }
  }
  else {
    FUN_8002cc9c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

