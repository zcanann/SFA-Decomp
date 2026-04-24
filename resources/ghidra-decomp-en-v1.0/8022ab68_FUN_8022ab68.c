// Function: FUN_8022ab68
// Entry: 8022ab68
// Size: 692 bytes

void FUN_8022ab68(int param_1,int param_2)

{
  float fVar1;
  double dVar2;
  uint uVar3;
  int iVar4;
  double local_10;
  
  dVar2 = DOUBLE_803e6ee0;
  *(int *)(param_2 + 0x398) =
       (int)(FLOAT_803db414 * *(float *)(param_2 + 0x3a0) * *(float *)(param_2 + 0x3a8) +
            (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x398) ^ 0x80000000) -
                   DOUBLE_803e6ee0));
  *(short *)(param_1 + 4) =
       (short)(int)(FLOAT_803db414 * *(float *)(param_2 + 0x3a0) * *(float *)(param_2 + 0x3a8) +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000) -
                          dVar2));
  fVar1 = FLOAT_803e6ecc;
  if (*(float *)(param_2 + 0x3a0) <= FLOAT_803e6ecc) {
    uVar3 = *(uint *)(param_2 + 0x380);
    iVar4 = *(int *)(param_2 + 0x398);
    if (iVar4 < (int)(uVar3 - 0xffff)) {
      *(undefined *)(param_2 + 0x478) = 0;
      *(int *)(param_2 + 0x380) = *(int *)(param_2 + 0x398) + 0xffff;
      *(float *)(param_2 + 0x38c) = fVar1;
      *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x54) / *(float *)(param_2 + 0x3ac);
      *(float *)(param_2 + 0x60) = *(float *)(param_2 + 0x60) / *(float *)(param_2 + 0x3b0);
      FUN_8022f148(*(undefined4 *)(param_2 + 0x10),0,0);
    }
    else if ((int)(uVar3 - 0x8000) < iVar4) {
      uVar3 = iVar4 - (uVar3 & 0xffff);
      if (0x8000 < (int)uVar3) {
        uVar3 = uVar3 - 0xffff;
      }
      if ((int)uVar3 < -0x8000) {
        uVar3 = uVar3 + 0xffff;
      }
      if ((int)uVar3 < 0) {
        uVar3 = -uVar3;
      }
      local_10 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      *(float *)(param_2 + 0x3a8) =
           (float)(local_10 - DOUBLE_803e6ee0) / *(float *)(param_2 + 0x3a4);
      if (FLOAT_803e6ef8 <= *(float *)(param_2 + 0x3a8)) {
        if (FLOAT_803e6ed0 < *(float *)(param_2 + 0x3a8)) {
          *(float *)(param_2 + 0x3a8) = FLOAT_803e6ed0;
        }
      }
      else {
        *(float *)(param_2 + 0x3a8) = FLOAT_803e6ef8;
      }
    }
  }
  else {
    uVar3 = *(uint *)(param_2 + 0x380);
    iVar4 = *(int *)(param_2 + 0x398);
    if ((int)(uVar3 + 0xffff) < iVar4) {
      *(undefined *)(param_2 + 0x478) = 0;
      *(int *)(param_2 + 0x380) = *(int *)(param_2 + 0x398) + -0xffff;
      *(float *)(param_2 + 0x38c) = fVar1;
      *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x54) / *(float *)(param_2 + 0x3ac);
      *(float *)(param_2 + 0x60) = *(float *)(param_2 + 0x60) / *(float *)(param_2 + 0x3b0);
      FUN_8022f148(*(undefined4 *)(param_2 + 0x10),0,0);
    }
    else if ((int)(uVar3 + 0x8000) < iVar4) {
      uVar3 = iVar4 - (uVar3 & 0xffff);
      if (0x8000 < (int)uVar3) {
        uVar3 = uVar3 - 0xffff;
      }
      if ((int)uVar3 < -0x8000) {
        uVar3 = uVar3 + 0xffff;
      }
      if ((int)uVar3 < 0) {
        uVar3 = -uVar3;
      }
      local_10 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      *(float *)(param_2 + 0x3a8) =
           (float)(local_10 - DOUBLE_803e6ee0) / *(float *)(param_2 + 0x3a4);
      if (FLOAT_803e6ef8 <= *(float *)(param_2 + 0x3a8)) {
        if (FLOAT_803e6ed0 < *(float *)(param_2 + 0x3a8)) {
          *(float *)(param_2 + 0x3a8) = FLOAT_803e6ed0;
        }
      }
      else {
        *(float *)(param_2 + 0x3a8) = FLOAT_803e6ef8;
      }
    }
  }
  return;
}

