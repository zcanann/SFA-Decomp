// Function: FUN_80143dd4
// Entry: 80143dd4
// Size: 1004 bytes

undefined4 FUN_80143dd4(int param_1,byte **param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  iVar1 = FUN_8014460c();
  if (iVar1 == 0) {
    if (FLOAT_803e23dc < (float)param_2[0x1e7]) {
      FUN_8013a3f0((double)FLOAT_803e23ec,param_1,0x1b,0);
      *(undefined *)((int)param_2 + 10) = 2;
      param_2[0x1e7] = (byte *)FLOAT_803e23dc;
      uVar2 = 1;
    }
    else {
      if (*(char *)(param_2 + 0x1ca) < '\0') {
        param_2[0x1c9] = (byte *)FLOAT_803e2524;
        *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0x7f;
        *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0xbf | 0x40;
      }
      if ((*(byte *)(param_2 + 0x1ca) >> 6 & 1) == 0) {
        iVar1 = FUN_8000b578(param_1,0x10);
        if (iVar1 == 0) {
          iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
          if (iVar1 == 0) {
            param_2[0x15] = (byte *)((uint)param_2[0x15] & 0xdfffffff);
          }
          iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
          if ((iVar1 == 0) || (((uint)param_2[0x15] & 0x20000000) != 0)) {
            if (**param_2 < 4) {
              FUN_8013a3f0((double)FLOAT_803e2444,param_1,0x14,0);
              *(undefined *)((int)param_2 + 10) = 3;
              param_2[0x1ce] = (byte *)FLOAT_803e2440;
              uVar2 = 1;
            }
            else {
              param_2[0x1c9] = (byte *)((float)param_2[0x1c9] - FLOAT_803db414);
              if (FLOAT_803e23dc < (float)param_2[0x1c9]) {
                uVar2 = 0;
              }
              else {
                uVar3 = FUN_800221a0(200,500);
                param_2[0x1c9] =
                     (byte *)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                    DOUBLE_803e2460);
                if (**param_2 < 8) {
                  FUN_8013a3f0((double)FLOAT_803e2444,param_1,0x14,0);
                  *(undefined *)((int)param_2 + 10) = 3;
                  param_2[0x1ce] = (byte *)FLOAT_803e2440;
                  uVar2 = 1;
                }
                else {
                  if ((float)param_2[0x1c7] <= FLOAT_803e23dc) {
                    if (param_2[0x1ec] == (byte *)0x0) {
                      iVar1 = FUN_800221a0(0,6);
                      if ((iVar1 < 5) && (-1 < iVar1)) {
                        FUN_801444a4(param_1,param_2);
                      }
                      else {
                        FUN_801441c0(param_1,param_2);
                      }
                    }
                    else {
                      iVar1 = *(int *)(param_1 + 0xb8);
                      if ((((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
                          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)
                           ))) && (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)) {
                        FUN_800393f8(param_1,iVar1 + 0x3a8,0x357,0,0xffffffff,0);
                      }
                      FUN_8013a3f0((double)FLOAT_803e251c,param_1,0x26,0);
                      *(undefined *)((int)param_2 + 10) = 5;
                    }
                  }
                  else {
                    FUN_801444a4(param_1,param_2);
                  }
                  uVar2 = 1;
                }
              }
            }
          }
          else {
            param_2[0x15] = (byte *)((uint)param_2[0x15] | 0x20000000);
            iVar1 = *(int *)(param_1 + 0xb8);
            if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
                (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)))) {
              FUN_800393f8(param_1,iVar1 + 0x3a8,0x353,0x500,0xffffffff,0);
            }
            uVar2 = 0;
          }
        }
        else {
          uVar2 = 1;
        }
      }
      else {
        param_2[0x1c9] = (byte *)((float)param_2[0x1c9] - FLOAT_803db414);
        if ((float)param_2[0x1c9] <= FLOAT_803e23dc) {
          param_2[0x1c7] = (byte *)FLOAT_803e2438;
          uVar3 = FUN_800221a0(200,500);
          param_2[0x1c9] =
               (byte *)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2460);
          *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0xbf;
          *(undefined *)((int)param_2 + 10) = 1;
        }
        uVar2 = 0;
      }
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

