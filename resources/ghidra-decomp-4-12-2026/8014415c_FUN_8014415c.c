// Function: FUN_8014415c
// Entry: 8014415c
// Size: 1004 bytes

undefined4 FUN_8014415c(int param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  bool bVar4;
  
  iVar1 = FUN_80144994(param_1,param_2);
  if (iVar1 == 0) {
    if (FLOAT_803e306c < (float)param_2[0x1e7]) {
      FUN_8013a778((double)FLOAT_803e307c,param_1,0x1b,0);
      *(undefined *)((int)param_2 + 10) = 2;
      param_2[0x1e7] = (int)FLOAT_803e306c;
      uVar2 = 1;
    }
    else {
      if (*(char *)(param_2 + 0x1ca) < '\0') {
        param_2[0x1c9] = (int)FLOAT_803e31b4;
        *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0x7f;
        *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0xbf | 0x40;
      }
      if ((*(byte *)(param_2 + 0x1ca) >> 6 & 1) == 0) {
        bVar4 = FUN_8000b598(param_1,0x10);
        if (bVar4) {
          uVar2 = 1;
        }
        else {
          iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
          if (iVar1 == 0) {
            param_2[0x15] = param_2[0x15] & 0xdfffffff;
          }
          iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
          if ((iVar1 == 0) || ((param_2[0x15] & 0x20000000U) != 0)) {
            if (*(byte *)*param_2 < 4) {
              FUN_8013a778((double)FLOAT_803e30d4,param_1,0x14,0);
              *(undefined *)((int)param_2 + 10) = 3;
              param_2[0x1ce] = (int)FLOAT_803e30d0;
              uVar2 = 1;
            }
            else {
              param_2[0x1c9] = (int)((float)param_2[0x1c9] - FLOAT_803dc074);
              if (FLOAT_803e306c < (float)param_2[0x1c9]) {
                uVar2 = 0;
              }
              else {
                uVar3 = FUN_80022264(200,500);
                param_2[0x1c9] =
                     (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0)
                ;
                if (*(byte *)*param_2 < 8) {
                  FUN_8013a778((double)FLOAT_803e30d4,param_1,0x14,0);
                  *(undefined *)((int)param_2 + 10) = 3;
                  param_2[0x1ce] = (int)FLOAT_803e30d0;
                  uVar2 = 1;
                }
                else {
                  if ((float)param_2[0x1c7] <= FLOAT_803e306c) {
                    if (param_2[0x1ec] == 0) {
                      uVar3 = FUN_80022264(0,6);
                      if (((int)uVar3 < 5) && (-1 < (int)uVar3)) {
                        FUN_8014482c(param_1,(int)param_2);
                      }
                      else {
                        FUN_80144548();
                      }
                    }
                    else {
                      iVar1 = *(int *)(param_1 + 0xb8);
                      if ((((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
                          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)
                           ))) && (bVar4 = FUN_8000b598(param_1,0x10), !bVar4)) {
                        FUN_800394f0(param_1,iVar1 + 0x3a8,0x357,0,0xffffffff,0);
                      }
                      FUN_8013a778((double)FLOAT_803e31ac,param_1,0x26,0);
                      *(undefined *)((int)param_2 + 10) = 5;
                    }
                  }
                  else {
                    FUN_8014482c(param_1,(int)param_2);
                  }
                  uVar2 = 1;
                }
              }
            }
          }
          else {
            param_2[0x15] = param_2[0x15] | 0x20000000;
            iVar1 = *(int *)(param_1 + 0xb8);
            if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
                (bVar4 = FUN_8000b598(param_1,0x10), !bVar4)))) {
              FUN_800394f0(param_1,iVar1 + 0x3a8,0x353,0x500,0xffffffff,0);
            }
            uVar2 = 0;
          }
        }
      }
      else {
        param_2[0x1c9] = (int)((float)param_2[0x1c9] - FLOAT_803dc074);
        if ((float)param_2[0x1c9] <= FLOAT_803e306c) {
          param_2[0x1c7] = (int)FLOAT_803e30c8;
          uVar3 = FUN_80022264(200,500);
          param_2[0x1c9] =
               (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
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

