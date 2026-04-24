// Function: FUN_8016ab10
// Entry: 8016ab10
// Size: 1428 bytes

void FUN_8016ab10(short *param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  int iVar6;
  int *piVar7;
  undefined4 local_68;
  float local_64;
  undefined4 local_60;
  undefined auStack92 [12];
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  piVar7 = *(int **)(param_1 + 0x5c);
  iVar6 = FUN_80080204();
  if (iVar6 == 0) {
    iVar6 = FUN_80080150(piVar7 + 8);
    if (iVar6 == 0) {
      iVar6 = FUN_800801a8(piVar7 + 9);
      if (iVar6 != 0) {
        FUN_80080178(piVar7 + 8,0x78);
      }
      if (*(int *)(param_1 + 0x62) != 0) {
        *piVar7 = *(int *)(param_1 + 0x62);
        *(undefined4 *)(param_1 + 0x62) = 0;
      }
      if (((*(byte *)(piVar7[7] + 0x12) >> 6 & 1) != 0) &&
         (piVar7[2] = (int)((float)piVar7[2] - FLOAT_803db414), (float)piVar7[2] <= FLOAT_803e3160))
      {
        if (*(char *)(param_1 + 0x1b) == -1) {
          iVar6 = 2;
          do {
            (**(code **)(*DAT_803dca88 + 8))
                      (param_1,(int)*(short *)(piVar7[7] + 8),0,1,0xffffffff,0);
            bVar1 = iVar6 != 0;
            iVar6 = iVar6 + -1;
          } while (bVar1);
        }
        piVar7[2] = (int)FLOAT_803e3160;
        if ((uint)*(byte *)(param_1 + 0x1b) < (uint)DAT_803db410 << 3) {
          *(undefined *)(param_1 + 0x1b) = 0;
          FUN_8002cbc4(param_1);
          return;
        }
        *(byte *)(param_1 + 0x1b) = *(byte *)(param_1 + 0x1b) - (char)((uint)DAT_803db410 << 3);
      }
      if (*(short *)(piVar7[7] + 10) != -1) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,(int)*(short *)(piVar7[7] + 10),0,1,0xffffffff,0);
      }
      iVar6 = FUN_80036e58((int)*(short *)(piVar7[7] + 0x10),param_1,0);
      if ((iVar6 != 0) &&
         (((*(byte *)(piVar7[7] + 0x12) >> 6 & 1) == 0 || ((float)piVar7[2] < FLOAT_803e3164)))) {
        if ((*(byte *)(piVar7[7] + 0x12) >> 4 & 1) == 0) {
          local_68 = *(undefined4 *)(iVar6 + 0x18);
          local_64 = *(float *)(iVar6 + 0xa8) * *(float *)(iVar6 + 8) * FLOAT_803e3168 +
                     *(float *)(iVar6 + 0x1c);
          local_60 = *(undefined4 *)(iVar6 + 0x20);
        }
        else {
          FUN_8003842c(iVar6,0,&local_68,&local_64,&local_60,0);
        }
        FUN_80247754(&local_68,param_1 + 0xc,&local_50);
        FUN_802477f0(&local_50);
        FUN_80247794(&local_50,&local_50);
        FUN_80247754(&local_50,piVar7 + 3,auStack92);
        piVar7[3] = (int)local_50;
        piVar7[4] = (int)local_4c;
        piVar7[5] = (int)local_48;
        FUN_80247778((double)FLOAT_803e315c,auStack92,auStack92);
        FUN_80247730(&local_50,auStack92,&local_50);
        fVar3 = FLOAT_803e3164;
        fVar2 = FLOAT_803e315c;
        *(float *)(param_1 + 0x12) =
             *(float *)(param_1 + 0x12) +
             ((FLOAT_803e315c + (float)piVar7[2]) * local_50 * (float)piVar7[1]) / FLOAT_803e3164;
        *(float *)(param_1 + 0x16) =
             *(float *)(param_1 + 0x16) +
             ((fVar2 + (float)piVar7[2]) * local_48 * (float)piVar7[1]) / fVar3;
        if (-1 < *(char *)(piVar7[7] + 0x12)) {
          *(float *)(param_1 + 0x14) =
               *(float *)(param_1 + 0x14) +
               ((fVar2 + (float)piVar7[2]) * FLOAT_803e316c * local_4c * (float)piVar7[1]) / fVar3;
        }
      }
      fVar2 = FLOAT_803e3170;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e3170;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar2;
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * FLOAT_803e3174;
      if (*(char *)(piVar7[7] + 0x12) < '\0') {
        *(float *)(param_1 + 0x14) =
             *(float *)(param_1 + 0x14) -
             (FLOAT_803e3178 * FLOAT_803db414 * (float)piVar7[2]) / FLOAT_803e317c;
      }
      dVar5 = DOUBLE_803e3190;
      dVar4 = DOUBLE_803e3188;
      if ((*(byte *)(piVar7[7] + 0x12) >> 5 & 1) == 0) {
        if (param_1[0x23] == 0x482) {
          uStack60 = (uint)DAT_803db410;
          local_40 = 0x43300000;
          uStack52 = (int)*param_1 ^ 0x80000000;
          local_38 = 0x43300000;
          iVar6 = (int)(FLOAT_803e3180 * FLOAT_803dbd48 *
                        (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e3188) +
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3190));
          local_30 = (longlong)iVar6;
          *param_1 = (short)iVar6;
          uStack36 = (uint)DAT_803db410;
          local_28 = 0x43300000;
          uStack28 = (int)param_1[1] ^ 0x80000000;
          local_20 = 0x43300000;
          iVar6 = (int)(FLOAT_803dbd4c * (float)((double)CONCAT44(0x43300000,uStack36) - dVar4) +
                       (float)((double)CONCAT44(0x43300000,uStack28) - dVar5));
          local_18 = (longlong)iVar6;
          param_1[1] = (short)iVar6;
        }
      }
      else {
        FUN_80222550((double)FLOAT_803e3160,(double)FLOAT_803e3158,param_1,param_1 + 0x12,10);
        param_1[2] = param_1[2] + (ushort)DAT_803db410 * 0x500;
      }
      FUN_8000da58(param_1,*(undefined2 *)(piVar7[7] + 2));
      FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
      FUN_80035df4(param_1,0x16,1,0);
      FUN_80035f20(param_1);
      iVar6 = *(int *)(*(int *)(param_1 + 0x2a) + 0x50);
      if (((iVar6 != 0) && (*(short *)(iVar6 + 0x46) != param_1[0x23])) && (iVar6 != *piVar7)) {
        piVar7[2] = (int)FLOAT_803e3160;
        FUN_80035f00(param_1);
        if (*(short *)(piVar7[7] + 4) != -1) {
          FUN_8009ab70((double)FLOAT_803e315c,param_1,0,1,0,1,0,1,0);
          FUN_8000b4d0(param_1,*(undefined2 *)(piVar7[7] + 4),3);
        }
        FUN_80080178(piVar7 + 8,0x78);
      }
    }
    else {
      iVar6 = FUN_800801a8(piVar7 + 8);
      if (iVar6 != 0) {
        FUN_8002cbc4(param_1);
      }
    }
  }
  else {
    FUN_8002cbc4(param_1);
  }
  return;
}

