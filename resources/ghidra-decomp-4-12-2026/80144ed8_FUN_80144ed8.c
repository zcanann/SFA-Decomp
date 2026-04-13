// Function: FUN_80144ed8
// Entry: 80144ed8
// Size: 752 bytes

void FUN_80144ed8(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  bool bVar4;
  uint uVar3;
  int local_18 [3];
  
  *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x720) < FLOAT_803e306c) {
    *(float *)(param_2 + 0x720) = FLOAT_803e306c;
  }
  iVar2 = FUN_80036974(param_1,local_18,(int *)0x0,(uint *)0x0);
  if (((iVar2 != 0) && (*(int *)(local_18[0] + 0xc4) != 0)) &&
     (*(short *)(*(int *)(local_18[0] + 0xc4) + 0x44) == 1)) {
    fVar1 = *(float *)(param_2 + 0x720);
    if (FLOAT_803e306c < fVar1) {
      *(float *)(param_2 + 0x720) = fVar1 + FLOAT_803e30d0;
      if (*(char *)(param_2 + 10) != '\v') {
        if ((*(uint *)(param_2 + 0x54) & 0x10) == 0) {
          iVar2 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (bVar4 = FUN_8000b598(param_1,0x10), !bVar4)) {
            FUN_800394f0(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
          *(undefined *)(param_2 + 10) = 10;
          *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x10;
        }
        else if (*(float *)(param_2 + 0x720) <= FLOAT_803e31c4) {
          iVar2 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (bVar4 = FUN_8000b598(param_1,0x10), !bVar4)) {
            FUN_800394f0(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
        else {
          *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) * FLOAT_803e3138;
          uVar3 = FUN_80020078(0x245);
          if (uVar3 != 0) {
            if (FLOAT_803e306c == *(float *)(param_2 + 0x2ac)) {
              bVar4 = false;
            }
            else if (FLOAT_803e30a0 == *(float *)(param_2 + 0x2b0)) {
              bVar4 = true;
            }
            else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e30a4) {
              bVar4 = false;
            }
            else {
              bVar4 = true;
            }
            if (!bVar4) {
              *(undefined *)(param_2 + 10) = 0xb;
              return;
            }
          }
          iVar2 = *(int *)(param_1 + 0xb8);
          if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
              (bVar4 = FUN_8000b598(param_1,0x10), !bVar4)))) {
            FUN_800394f0(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
      }
    }
    else {
      *(float *)(param_2 + 0x720) = fVar1 + FLOAT_803e317c;
      iVar2 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (bVar4 = FUN_8000b598(param_1,0x10), !bVar4)) {
        FUN_800394f0(param_1,iVar2 + 0x3a8,0x34f,0x500,0xffffffff,0);
      }
    }
  }
  return;
}

