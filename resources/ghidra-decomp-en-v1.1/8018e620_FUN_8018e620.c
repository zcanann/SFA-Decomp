// Function: FUN_8018e620
// Entry: 8018e620
// Size: 1560 bytes

void FUN_8018e620(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,short *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  
  fVar2 = FLOAT_803e4a70;
  sVar1 = *param_10;
  iVar4 = *(int *)(param_9 + 0x5c);
  dVar5 = (double)FLOAT_803e4a70;
  *(float *)(iVar4 + 0x2c) = FLOAT_803e4a70;
  if (sVar1 == 0x4bf) {
    *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
    *(undefined *)((int)param_9 + 0xad) = *(undefined *)((int)param_10 + 0x19);
    *(short *)(iVar4 + 0x38) = param_10[0x10];
    uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x38));
    if (uVar3 == 0) {
      return;
    }
    *(float *)(param_9 + 8) = FLOAT_803e4a94 + *(float *)(param_10 + 6);
    return;
  }
  if (sVar1 < 0x4bf) {
    if (sVar1 != 0x1e6) {
      if (sVar1 < 0x1e6) {
        if (sVar1 == 0x125) {
          *param_9 = 0;
          param_9[1] = 0;
          param_9[2] = 0;
          *(float *)(param_9 + 4) = fVar2;
          *(undefined4 *)(param_9 + 0x7a) = 0;
          *(undefined4 *)(param_9 + 0x7c) = 0;
          *(float *)(iVar4 + 0x24) = FLOAT_803e4ad8;
          *(float *)(iVar4 + 0x1c) = FLOAT_803e4a84;
          *(undefined2 *)(iVar4 + 0x32) = 0;
          uVar3 = FUN_80022264(1000,5000);
          *(short *)(iVar4 + 0x34) = (short)uVar3;
          *(undefined *)(iVar4 + 0x3f) = 1;
          *(code **)(param_9 + 0x5e) = FUN_8018dd40;
          return;
        }
        if (sVar1 < 0x125) {
          if (sVar1 == 0xd7) {
            *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
            *(float *)(param_9 + 4) = fVar2;
            *(undefined *)(iVar4 + 0x3e) = 0;
            *(undefined4 *)(iVar4 + 4) = *(undefined4 *)(param_10 + 4);
            *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(param_10 + 6);
            *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_10 + 8);
            fVar2 = FLOAT_803e4ac8;
            *(float *)(iVar4 + 0x18) = FLOAT_803e4ac8;
            *(float *)(iVar4 + 0x14) = fVar2;
            *(float *)(iVar4 + 0x28) = fVar2;
            *(float *)(iVar4 + 0x20) = fVar2;
            *(float *)(iVar4 + 0x24) = fVar2;
            *(float *)(iVar4 + 0x1c) = fVar2;
            *(code **)(param_9 + 0x5e) = FUN_8018dd40;
            return;
          }
          if (sVar1 < 0xd7) {
            if (sVar1 != 0x8e) {
              return;
            }
            *param_9 = 0;
            param_9[1] = 0;
            if (param_10[0xe] < 1000) {
              *(float *)(param_9 + 4) = FLOAT_803e4acc;
            }
            else {
              *(float *)(param_9 + 4) =
                   (float)(dVar5 / (double)((float)((double)CONCAT44(0x43300000,
                                                                     (int)param_10[0xe] ^ 0x80000000
                                                                    ) - DOUBLE_803e4ac0) /
                                           FLOAT_803e4a8c));
            }
            *(undefined *)(iVar4 + 0x3e) = 0;
            *(undefined4 *)(iVar4 + 4) = *(undefined4 *)(param_10 + 4);
            *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(param_10 + 6);
            *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_10 + 8);
            fVar2 = FLOAT_803e4ac8;
            *(float *)(iVar4 + 0x18) = FLOAT_803e4ac8;
            *(float *)(iVar4 + 0x14) = fVar2;
            *(float *)(iVar4 + 0x28) = FLOAT_803e4a8c;
            *(float *)(iVar4 + 0x20) = FLOAT_803e4ad0;
            fVar2 = FLOAT_803e4a84;
            *(float *)(iVar4 + 0x24) = FLOAT_803e4a84;
            *(float *)(iVar4 + 0x1c) = fVar2;
            param_9[2] = 0;
            *(code **)(param_9 + 0x5e) = FUN_8018dd40;
            return;
          }
          if (sVar1 != 0x10d) {
            return;
          }
          *(undefined4 *)(param_9 + 0x2a) = 0;
          if (param_10[0xd] == 0) {
            *(undefined **)(iVar4 + 0x44) = &DAT_803dca50;
            *(undefined *)(iVar4 + 0x40) = 1;
          }
          *(short *)(iVar4 + 0x48) = param_10[0xe];
          *(undefined2 *)(iVar4 + 0x3c) = *(undefined2 *)(iVar4 + 0x48);
          return;
        }
        if (sVar1 != 0x1d7) {
          if (0x1d6 < sVar1) {
            return;
          }
          if (0x1d1 < sVar1) {
            return;
          }
          if (sVar1 < 0x1d0) {
            return;
          }
        }
      }
      else if (sVar1 != 0x23b) {
        if (sVar1 < 0x23b) {
          if (sVar1 == 0x216) {
            *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
            param_9[1] = param_10[0xd];
            return;
          }
          if (0x215 < sVar1) {
            return;
          }
          if (sVar1 != 0x201) {
            return;
          }
        }
        else if (sVar1 != 0x492) {
          if (0x491 < sVar1) {
            return;
          }
          if (sVar1 != 699) {
            return;
          }
          *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
          param_9[1] = param_10[0xd];
          param_9[2] = param_10[0xe];
          *(float *)(param_9 + 4) = fVar2;
          return;
        }
      }
    }
  }
  else {
    if (sVar1 == 0x708) {
      *(char *)((int)param_9 + 0xad) = (char)param_10[0xd];
      *(short *)(iVar4 + 0x38) = param_10[0x10];
      if ('\x02' < *(char *)((int)param_9 + 0xad)) {
        *(undefined *)((int)param_9 + 0xad) = 0;
      }
      FUN_8002b95c((int)param_9,(int)*(char *)((int)param_9 + 0xad));
      return;
    }
    if (sVar1 < 0x708) {
      if (sVar1 == 0x6b4) {
        *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
        param_9[1] = param_10[0xd];
        FUN_8003042c((double)FLOAT_803e4ac8,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,param_12,param_13,param_14,param_15,param_16);
        return;
      }
      if (0x6b3 < sVar1) {
        if (sVar1 == 0x6bf) {
          *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
          param_9[1] = param_10[0xd];
          *(short *)(iVar4 + 0x3a) = param_10[0x10];
          return;
        }
        if (sVar1 < 0x6bf) {
          if (sVar1 < 0x6be) {
            return;
          }
          *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
          *(undefined *)(iVar4 + 0x3e) = 0;
          *(short *)(iVar4 + 0x3a) = param_10[0x10];
          return;
        }
        if (sVar1 != 0x6fc) {
          return;
        }
        *(short *)(iVar4 + 0x38) = param_10[0x10];
        return;
      }
      if (sVar1 == 0x66c) {
        *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
        *(short *)(iVar4 + 0x38) = param_10[0x10];
        return;
      }
      if (0x66b < sVar1) {
        return;
      }
      if (sVar1 != 0x622) {
        return;
      }
      *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
      *(short *)(iVar4 + 0x38) = param_10[0x10];
      return;
    }
    if (0x78c < sVar1) {
      if (sVar1 == 0x828) {
        *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
        *(undefined *)(iVar4 + 0x3e) = 0;
        *(short *)(iVar4 + 0x3a) = param_10[0x10];
        uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x3a));
        if (uVar3 == 0) {
          return;
        }
        if (*(char *)(iVar4 + 0x3e) != '\0') {
          return;
        }
        param_9[2] = 0x7fff;
        *(undefined *)(iVar4 + 0x3e) = 1;
        return;
      }
      if (0x827 < sVar1) {
        return;
      }
      if (sVar1 != 0x7de) {
        return;
      }
      *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
      param_9[1] = 0;
      if (param_10[0xe] < 1000) {
        *(float *)(param_9 + 4) = fVar2;
      }
      else {
        *(float *)(param_9 + 4) =
             (float)(dVar5 / (double)((float)((double)CONCAT44(0x43300000,
                                                               (int)param_10[0xe] ^ 0x80000000) -
                                             DOUBLE_803e4ac0) / FLOAT_803e4a8c));
      }
      *(float *)(iVar4 + 0x24) =
           (float)((double)CONCAT44(0x43300000,(int)param_10[0xd] ^ 0x80000000) - DOUBLE_803e4ac0);
      *(short *)(iVar4 + 0x38) = param_10[0x10];
      uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x38));
      if (uVar3 == 0) {
        return;
      }
      *(float *)(iVar4 + 0x24) = *(float *)(iVar4 + 0x24) * FLOAT_803e4ad4;
      return;
    }
    if (sVar1 == 0x726) {
      *(code **)(param_9 + 0x5e) = FUN_8018dd40;
      *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
      return;
    }
    if (sVar1 < 0x726) {
      if (sVar1 != 0x71b) {
        return;
      }
      *(short *)(iVar4 + 0x36) = param_10[0xd];
      return;
    }
    if (sVar1 < 0x78b) {
      return;
    }
  }
  *param_9 = (short)((int)*(char *)(param_10 + 0xc) << 8);
  return;
}

