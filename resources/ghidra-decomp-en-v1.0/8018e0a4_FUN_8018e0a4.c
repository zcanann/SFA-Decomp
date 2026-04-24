// Function: FUN_8018e0a4
// Entry: 8018e0a4
// Size: 1560 bytes

void FUN_8018e0a4(undefined2 *param_1,short *param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  undefined2 uVar4;
  int iVar5;
  
  fVar2 = FLOAT_803e3dd8;
  sVar1 = *param_2;
  iVar5 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar5 + 0x2c) = FLOAT_803e3dd8;
  if (sVar1 == 0x4bf) {
    *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
    *(undefined *)((int)param_1 + 0xad) = *(undefined *)((int)param_2 + 0x19);
    *(short *)(iVar5 + 0x38) = param_2[0x10];
    iVar5 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x38));
    if (iVar5 == 0) {
      return;
    }
    *(float *)(param_1 + 8) = FLOAT_803e3dfc + *(float *)(param_2 + 6);
    return;
  }
  if (sVar1 < 0x4bf) {
    if (sVar1 != 0x1e6) {
      if (sVar1 < 0x1e6) {
        if (sVar1 == 0x125) {
          *param_1 = 0;
          param_1[1] = 0;
          param_1[2] = 0;
          *(float *)(param_1 + 4) = fVar2;
          *(undefined4 *)(param_1 + 0x7a) = 0;
          *(undefined4 *)(param_1 + 0x7c) = 0;
          *(float *)(iVar5 + 0x24) = FLOAT_803e3e40;
          *(float *)(iVar5 + 0x1c) = FLOAT_803e3dec;
          *(undefined2 *)(iVar5 + 0x32) = 0;
          uVar4 = FUN_800221a0(1000,5000);
          *(undefined2 *)(iVar5 + 0x34) = uVar4;
          *(undefined *)(iVar5 + 0x3f) = 1;
          *(code **)(param_1 + 0x5e) = FUN_8018d7c4;
          return;
        }
        if (sVar1 < 0x125) {
          if (sVar1 == 0xd7) {
            *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
            *(float *)(param_1 + 4) = fVar2;
            *(undefined *)(iVar5 + 0x3e) = 0;
            *(undefined4 *)(iVar5 + 4) = *(undefined4 *)(param_2 + 4);
            *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(param_2 + 6);
            *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(param_2 + 8);
            fVar2 = FLOAT_803e3e30;
            *(float *)(iVar5 + 0x18) = FLOAT_803e3e30;
            *(float *)(iVar5 + 0x14) = fVar2;
            *(float *)(iVar5 + 0x28) = fVar2;
            *(float *)(iVar5 + 0x20) = fVar2;
            *(float *)(iVar5 + 0x24) = fVar2;
            *(float *)(iVar5 + 0x1c) = fVar2;
            *(code **)(param_1 + 0x5e) = FUN_8018d7c4;
            return;
          }
          if (sVar1 < 0xd7) {
            if (sVar1 != 0x8e) {
              return;
            }
            *param_1 = 0;
            param_1[1] = 0;
            if (param_2[0xe] < 1000) {
              *(float *)(param_1 + 4) = FLOAT_803e3e34;
            }
            else {
              *(float *)(param_1 + 4) =
                   fVar2 / ((float)((double)CONCAT44(0x43300000,(int)param_2[0xe] ^ 0x80000000) -
                                   DOUBLE_803e3e28) / FLOAT_803e3df4);
            }
            *(undefined *)(iVar5 + 0x3e) = 0;
            *(undefined4 *)(iVar5 + 4) = *(undefined4 *)(param_2 + 4);
            *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(param_2 + 6);
            *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(param_2 + 8);
            fVar2 = FLOAT_803e3e30;
            *(float *)(iVar5 + 0x18) = FLOAT_803e3e30;
            *(float *)(iVar5 + 0x14) = fVar2;
            *(float *)(iVar5 + 0x28) = FLOAT_803e3df4;
            *(float *)(iVar5 + 0x20) = FLOAT_803e3e38;
            fVar2 = FLOAT_803e3dec;
            *(float *)(iVar5 + 0x24) = FLOAT_803e3dec;
            *(float *)(iVar5 + 0x1c) = fVar2;
            param_1[2] = 0;
            *(code **)(param_1 + 0x5e) = FUN_8018d7c4;
            return;
          }
          if (sVar1 != 0x10d) {
            return;
          }
          *(undefined4 *)(param_1 + 0x2a) = 0;
          if (param_2[0xd] == 0) {
            *(undefined **)(iVar5 + 0x44) = &DAT_803dbde8;
            *(undefined *)(iVar5 + 0x40) = 1;
          }
          *(short *)(iVar5 + 0x48) = param_2[0xe];
          *(undefined2 *)(iVar5 + 0x3c) = *(undefined2 *)(iVar5 + 0x48);
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
            *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
            param_1[1] = param_2[0xd];
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
          *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
          param_1[1] = param_2[0xd];
          param_1[2] = param_2[0xe];
          *(float *)(param_1 + 4) = fVar2;
          return;
        }
      }
    }
  }
  else {
    if (sVar1 == 0x708) {
      *(char *)((int)param_1 + 0xad) = (char)param_2[0xd];
      *(short *)(iVar5 + 0x38) = param_2[0x10];
      if ('\x02' < *(char *)((int)param_1 + 0xad)) {
        *(undefined *)((int)param_1 + 0xad) = 0;
      }
      FUN_8002b884(param_1,(int)*(char *)((int)param_1 + 0xad));
      return;
    }
    if (sVar1 < 0x708) {
      if (sVar1 == 0x6b4) {
        *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
        param_1[1] = param_2[0xd];
        FUN_80030334((double)FLOAT_803e3e30,param_1,0,0);
        return;
      }
      if (0x6b3 < sVar1) {
        if (sVar1 == 0x6bf) {
          *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
          param_1[1] = param_2[0xd];
          *(short *)(iVar5 + 0x3a) = param_2[0x10];
          return;
        }
        if (sVar1 < 0x6bf) {
          if (sVar1 < 0x6be) {
            return;
          }
          *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
          *(undefined *)(iVar5 + 0x3e) = 0;
          *(short *)(iVar5 + 0x3a) = param_2[0x10];
          return;
        }
        if (sVar1 != 0x6fc) {
          return;
        }
        *(short *)(iVar5 + 0x38) = param_2[0x10];
        return;
      }
      if (sVar1 == 0x66c) {
        *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
        *(short *)(iVar5 + 0x38) = param_2[0x10];
        return;
      }
      if (0x66b < sVar1) {
        return;
      }
      if (sVar1 != 0x622) {
        return;
      }
      *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
      *(short *)(iVar5 + 0x38) = param_2[0x10];
      return;
    }
    if (0x78c < sVar1) {
      if (sVar1 == 0x828) {
        *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
        *(undefined *)(iVar5 + 0x3e) = 0;
        *(short *)(iVar5 + 0x3a) = param_2[0x10];
        iVar3 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x3a));
        if (iVar3 == 0) {
          return;
        }
        if (*(char *)(iVar5 + 0x3e) != '\0') {
          return;
        }
        param_1[2] = 0x7fff;
        *(undefined *)(iVar5 + 0x3e) = 1;
        return;
      }
      if (0x827 < sVar1) {
        return;
      }
      if (sVar1 != 0x7de) {
        return;
      }
      *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
      param_1[1] = 0;
      if (param_2[0xe] < 1000) {
        *(float *)(param_1 + 4) = fVar2;
      }
      else {
        *(float *)(param_1 + 4) =
             fVar2 / ((float)((double)CONCAT44(0x43300000,(int)param_2[0xe] ^ 0x80000000) -
                             DOUBLE_803e3e28) / FLOAT_803e3df4);
      }
      *(float *)(iVar5 + 0x24) =
           (float)((double)CONCAT44(0x43300000,(int)param_2[0xd] ^ 0x80000000) - DOUBLE_803e3e28);
      *(short *)(iVar5 + 0x38) = param_2[0x10];
      iVar3 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x38));
      if (iVar3 == 0) {
        return;
      }
      *(float *)(iVar5 + 0x24) = *(float *)(iVar5 + 0x24) * FLOAT_803e3e3c;
      return;
    }
    if (sVar1 == 0x726) {
      *(code **)(param_1 + 0x5e) = FUN_8018d7c4;
      *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
      return;
    }
    if (sVar1 < 0x726) {
      if (sVar1 != 0x71b) {
        return;
      }
      *(short *)(iVar5 + 0x36) = param_2[0xd];
      return;
    }
    if (sVar1 < 0x78b) {
      return;
    }
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
  return;
}

