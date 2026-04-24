// Function: FUN_80174b14
// Entry: 80174b14
// Size: 1048 bytes

undefined4
FUN_80174b14(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  int *piVar8;
  float local_38 [2];
  undefined8 local_30;
  undefined8 local_28;
  
  bVar4 = false;
  local_38[0] = FLOAT_803e41d8;
  FUN_801758d4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  uVar5 = FUN_80020078((int)*(short *)(param_10 + 0xac));
  fVar2 = FLOAT_803e41dc;
  if (uVar5 == 0) {
    if (*(int *)(param_10 + 0xbc) == 0) {
      uVar6 = FUN_80036f50(0x11,param_9,local_38);
      *(undefined4 *)(param_10 + 0xbc) = uVar6;
    }
    if (*(int *)(param_10 + 0xbc) == 0) {
      uVar6 = 0;
    }
    else {
      if (*(float *)(param_10 + 0xd8) < FLOAT_803e41e8) {
        *(float *)(param_10 + 0xd8) = FLOAT_803e41e8;
      }
      fVar2 = *(float *)(*(int *)(param_10 + 0xbc) + 0x14) - *(float *)(param_9 + 0x14);
      if (fVar2 < FLOAT_803e41c0) {
        fVar2 = fVar2 * FLOAT_803e41ec;
      }
      fVar1 = *(float *)(param_10 + 0xf0);
      if (FLOAT_803e41f0 + fVar2 <= fVar1) {
        fVar3 = *(float *)(*(int *)(param_10 + 0xbc) + 0xc) - *(float *)(param_9 + 0xc);
        if (fVar3 < FLOAT_803e41c0) {
          fVar3 = fVar3 * FLOAT_803e41ec;
        }
        if (fVar3 <= FLOAT_803e41f4) {
          if ((FLOAT_803e41f0 + fVar2 <= fVar1) && (fVar1 <= FLOAT_803e41f8 + fVar2)) {
            bVar4 = true;
            FUN_800201ac(0x1c9,1);
          }
          iVar7 = FUN_800395a4(param_9,0);
          *(float *)(param_10 + 0xec) =
               *(float *)(param_10 + 0xe8) * FLOAT_803dc074 + *(float *)(param_10 + 0xec);
          if (*(float *)(param_10 + 0xec) < *(float *)(param_10 + 0xe4)) {
            if (*(float *)(param_10 + 0xec) < FLOAT_803e41c0) {
              uVar5 = FUN_80022264(0x19,0x4b);
              local_30 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
              *(float *)(param_10 + 0xe4) = FLOAT_803e41fc * (float)(local_30 - DOUBLE_803e4210);
              uVar5 = FUN_80022264(0x28,0x46);
              local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
              *(float *)(param_10 + 0xe8) =
                   *(float *)(param_10 + 0xe4) / (float)(local_28 - DOUBLE_803e4210);
              *(float *)(param_10 + 0xec) = FLOAT_803e41c0;
            }
          }
          else {
            *(float *)(param_10 + 0xe8) = *(float *)(param_10 + 0xe8) * FLOAT_803e41ec;
          }
          if (iVar7 != 0) {
            *(float *)(param_10 + 0xd8) = *(float *)(param_10 + 0xd8) + *(float *)(param_10 + 0xcc);
            if (*(float *)(param_10 + 0xd8) < FLOAT_803e4200) {
              *(float *)(param_10 + 0xdc) =
                   *(float *)(param_10 + 0xdc) + *(float *)(param_10 + 0xd0);
              if (*(float *)(param_10 + 0xdc) <= FLOAT_803e4204) {
                if (*(float *)(param_10 + 0xdc) < FLOAT_803e41c0) {
                  *(float *)(param_10 + 0xdc) = FLOAT_803e4204;
                }
              }
              else {
                *(float *)(param_10 + 0xdc) = FLOAT_803e4204;
              }
              *(float *)(param_10 + 0xe0) =
                   *(float *)(param_10 + 0xe0) + *(float *)(param_10 + 0xd4);
              if (*(float *)(param_10 + 0xe0) <= FLOAT_803e4204) {
                if (*(float *)(param_10 + 0xe0) < FLOAT_803e41c0) {
                  *(float *)(param_10 + 0xe0) = FLOAT_803e4204;
                }
              }
              else {
                *(float *)(param_10 + 0xe0) = FLOAT_803e4204;
              }
              fVar2 = *(float *)(param_10 + 0xdc);
              fVar3 = FLOAT_803e4208 + *(float *)(param_10 + 0xec);
              fVar1 = *(float *)(param_10 + 0xe0);
              *(char *)(iVar7 + 0xc) = (char)(int)*(float *)(param_10 + 0xd8);
              *(char *)(iVar7 + 0xd) = (char)(int)(fVar2 * fVar3);
              *(char *)(iVar7 + 0xe) = (char)(int)(fVar1 * fVar3);
            }
            else {
              FUN_800201ac((int)*(short *)(param_10 + 0xac),1);
              if (bVar4) {
                FUN_800201ac(0x1c9,0);
              }
              piVar8 = (int *)FUN_80013ee8(0x5b);
              (**(code **)(*piVar8 + 4))(param_9,0x14,0,2,0xffffffff,0);
              (**(code **)(*piVar8 + 4))(param_9,0x14,0,2,0xffffffff,0);
              FUN_80013e4c((undefined *)piVar8);
              FUN_8000bb38(param_9,0x65);
            }
          }
          uVar6 = 0;
        }
        else {
          uVar6 = 0;
        }
      }
      else {
        uVar6 = 0;
      }
    }
  }
  else {
    if (FLOAT_803e41dc < *(float *)(param_9 + 8)) {
      *(float *)(param_9 + 8) = -(FLOAT_803e41e0 * FLOAT_803dc074 - *(float *)(param_9 + 8));
      if (*(float *)(param_9 + 8) <= fVar2) {
        *(float *)(param_9 + 8) = FLOAT_803e41c0;
        *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x10) - FLOAT_803e41e4;
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    uVar6 = 1;
  }
  return uVar6;
}

