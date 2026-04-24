// Function: FUN_80174668
// Entry: 80174668
// Size: 1048 bytes

undefined4 FUN_80174668(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int *piVar8;
  float local_38 [2];
  double local_30;
  double local_28;
  
  bVar4 = false;
  local_38[0] = FLOAT_803e3540;
  FUN_80175428(param_1,0);
  iVar5 = FUN_8001ffb4((int)*(short *)(param_2 + 0xac));
  fVar2 = FLOAT_803e3544;
  if (iVar5 == 0) {
    if (*(int *)(param_2 + 0xbc) == 0) {
      uVar6 = FUN_80036e58(0x11,param_1,local_38);
      *(undefined4 *)(param_2 + 0xbc) = uVar6;
    }
    if (*(int *)(param_2 + 0xbc) == 0) {
      uVar6 = 0;
    }
    else {
      if (*(float *)(param_2 + 0xd8) < FLOAT_803e3550) {
        *(float *)(param_2 + 0xd8) = FLOAT_803e3550;
      }
      fVar2 = *(float *)(*(int *)(param_2 + 0xbc) + 0x14) - *(float *)(param_1 + 0x14);
      if (fVar2 < FLOAT_803e3528) {
        fVar2 = fVar2 * FLOAT_803e3554;
      }
      fVar1 = *(float *)(param_2 + 0xf0);
      if (FLOAT_803e3558 + fVar2 <= fVar1) {
        fVar3 = *(float *)(*(int *)(param_2 + 0xbc) + 0xc) - *(float *)(param_1 + 0xc);
        if (fVar3 < FLOAT_803e3528) {
          fVar3 = fVar3 * FLOAT_803e3554;
        }
        if (fVar3 <= FLOAT_803e355c) {
          if ((FLOAT_803e3558 + fVar2 <= fVar1) && (fVar1 <= FLOAT_803e3560 + fVar2)) {
            bVar4 = true;
            FUN_800200e8(0x1c9,1);
          }
          iVar5 = FUN_800394ac(param_1,0,0);
          *(float *)(param_2 + 0xec) =
               *(float *)(param_2 + 0xe8) * FLOAT_803db414 + *(float *)(param_2 + 0xec);
          if (*(float *)(param_2 + 0xec) < *(float *)(param_2 + 0xe4)) {
            if (*(float *)(param_2 + 0xec) < FLOAT_803e3528) {
              uVar7 = FUN_800221a0(0x19,0x4b);
              local_30 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(param_2 + 0xe4) = FLOAT_803e3564 * (float)(local_30 - DOUBLE_803e3578);
              uVar7 = FUN_800221a0(0x28,0x46);
              local_28 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(param_2 + 0xe8) =
                   *(float *)(param_2 + 0xe4) / (float)(local_28 - DOUBLE_803e3578);
              *(float *)(param_2 + 0xec) = FLOAT_803e3528;
            }
          }
          else {
            *(float *)(param_2 + 0xe8) = *(float *)(param_2 + 0xe8) * FLOAT_803e3554;
          }
          if (iVar5 != 0) {
            *(float *)(param_2 + 0xd8) = *(float *)(param_2 + 0xd8) + *(float *)(param_2 + 0xcc);
            if (*(float *)(param_2 + 0xd8) < FLOAT_803e3568) {
              *(float *)(param_2 + 0xdc) = *(float *)(param_2 + 0xdc) + *(float *)(param_2 + 0xd0);
              if (*(float *)(param_2 + 0xdc) <= FLOAT_803e356c) {
                if (*(float *)(param_2 + 0xdc) < FLOAT_803e3528) {
                  *(float *)(param_2 + 0xdc) = FLOAT_803e356c;
                }
              }
              else {
                *(float *)(param_2 + 0xdc) = FLOAT_803e356c;
              }
              *(float *)(param_2 + 0xe0) = *(float *)(param_2 + 0xe0) + *(float *)(param_2 + 0xd4);
              if (*(float *)(param_2 + 0xe0) <= FLOAT_803e356c) {
                if (*(float *)(param_2 + 0xe0) < FLOAT_803e3528) {
                  *(float *)(param_2 + 0xe0) = FLOAT_803e356c;
                }
              }
              else {
                *(float *)(param_2 + 0xe0) = FLOAT_803e356c;
              }
              fVar2 = *(float *)(param_2 + 0xdc);
              fVar3 = FLOAT_803e3570 + *(float *)(param_2 + 0xec);
              fVar1 = *(float *)(param_2 + 0xe0);
              *(char *)(iVar5 + 0xc) = (char)(int)*(float *)(param_2 + 0xd8);
              *(char *)(iVar5 + 0xd) = (char)(int)(fVar2 * fVar3);
              *(char *)(iVar5 + 0xe) = (char)(int)(fVar1 * fVar3);
            }
            else {
              FUN_800200e8((int)*(short *)(param_2 + 0xac),1);
              if (bVar4) {
                FUN_800200e8(0x1c9,0);
              }
              piVar8 = (int *)FUN_80013ec8(0x5b,1);
              (**(code **)(*piVar8 + 4))(param_1,0x14,0,2,0xffffffff,0);
              (**(code **)(*piVar8 + 4))(param_1,0x14,0,2,0xffffffff,0);
              FUN_80013e2c(piVar8);
              FUN_8000bb18(param_1,0x65);
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
    if ((FLOAT_803e3544 < *(float *)(param_1 + 8)) &&
       (*(float *)(param_1 + 8) = -(FLOAT_803e3548 * FLOAT_803db414 - *(float *)(param_1 + 8)),
       *(float *)(param_1 + 8) <= fVar2)) {
      *(float *)(param_1 + 8) = FLOAT_803e3528;
      *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e354c;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    uVar6 = 1;
  }
  return uVar6;
}

