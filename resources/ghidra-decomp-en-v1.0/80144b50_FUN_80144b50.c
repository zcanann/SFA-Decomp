// Function: FUN_80144b50
// Entry: 80144b50
// Size: 752 bytes

void FUN_80144b50(int param_1,int param_2)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int local_18 [3];
  
  *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x720) < FLOAT_803e23dc) {
    *(float *)(param_2 + 0x720) = FLOAT_803e23dc;
  }
  iVar3 = FUN_8003687c(param_1,local_18,0,0);
  if (((iVar3 != 0) && (*(int *)(local_18[0] + 0xc4) != 0)) &&
     (*(short *)(*(int *)(local_18[0] + 0xc4) + 0x44) == 1)) {
    fVar1 = *(float *)(param_2 + 0x720);
    if (FLOAT_803e23dc < fVar1) {
      *(float *)(param_2 + 0x720) = fVar1 + FLOAT_803e2440;
      if (*(char *)(param_2 + 10) != '\v') {
        if ((*(uint *)(param_2 + 0x54) & 0x10) == 0) {
          iVar3 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)) {
            FUN_800393f8(param_1,iVar3 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
          *(undefined *)(param_2 + 10) = 10;
          *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x10;
        }
        else if (*(float *)(param_2 + 0x720) <= FLOAT_803e2534) {
          iVar3 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)) {
            FUN_800393f8(param_1,iVar3 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
        else {
          *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) * FLOAT_803e24a8;
          iVar3 = FUN_8001ffb4(0x245);
          if (iVar3 != 0) {
            if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
              bVar2 = false;
            }
            else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
              bVar2 = true;
            }
            else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
              bVar2 = false;
            }
            else {
              bVar2 = true;
            }
            if (!bVar2) {
              *(undefined *)(param_2 + 10) = 0xb;
              return;
            }
          }
          iVar3 = *(int *)(param_1 + 0xb8);
          if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
              (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)))) {
            FUN_800393f8(param_1,iVar3 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
      }
    }
    else {
      *(float *)(param_2 + 0x720) = fVar1 + FLOAT_803e24ec;
      iVar3 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)) {
        FUN_800393f8(param_1,iVar3 + 0x3a8,0x34f,0x500,0xffffffff,0);
      }
    }
  }
  return;
}

