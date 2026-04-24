// Function: FUN_801437d4
// Entry: 801437d4
// Size: 816 bytes

undefined4 FUN_801437d4(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char cVar6;
  undefined4 uVar5;
  char local_28 [28];
  
  iVar3 = FUN_8014460c();
  if (iVar3 == 0) {
    iVar3 = FUN_8012ebc8();
    if (iVar3 == 0xc1) {
      *(undefined *)(param_2 + 10) = 0;
    }
    else {
      *(float *)(param_2 + 0x738) = *(float *)(param_2 + 0x738) - FLOAT_803db414;
      if (*(float *)(param_2 + 0x738) < FLOAT_803e23dc) {
        iVar3 = *(int *)(param_1 + 0xb8);
        if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
            (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)))) {
          FUN_800393f8(param_1,iVar3 + 0x3a8,0x29a,0x100,0xffffffff,0);
        }
        *(float *)(param_2 + 0x738) = FLOAT_803e2440;
      }
      if ((*(int *)(param_2 + 0x7b8) == 0) && (cVar6 = FUN_8002e04c(), cVar6 != '\0')) {
        uVar5 = FUN_8002bdf4(0x20,0x17b);
        local_28[0] = -1;
        local_28[1] = -1;
        local_28[2] = -1;
        if (*(int *)(param_2 + 0x7a8) != 0) {
          local_28[*(byte *)(param_2 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(param_2 + 0x7b0) != 0) {
          local_28[*(byte *)(param_2 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(param_2 + 0x7b8) != 0) {
          local_28[*(byte *)(param_2 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_28[0] == -1) {
          uVar2 = 0;
        }
        else if (local_28[1] == -1) {
          uVar2 = 1;
        }
        else if (local_28[2] == -1) {
          uVar2 = 2;
        }
        else if (local_28[3] == -1) {
          uVar2 = 3;
        }
        else {
          uVar2 = 0xffffffff;
        }
        *(byte *)(param_2 + 0x7bc) =
             (byte)((uVar2 & 0xff) << 2) & 0xc | *(byte *)(param_2 + 0x7bc) & 0xf3;
        uVar5 = FUN_8002df90(uVar5,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x30));
        *(undefined4 *)(param_2 + 0x7b8) = uVar5;
        FUN_80037d2c(param_1,*(undefined4 *)(param_2 + 0x7b8),*(byte *)(param_2 + 0x7bc) >> 2 & 3);
        fVar1 = FLOAT_803e23dc;
        *(float *)(param_2 + 0x7c0) = FLOAT_803e23dc;
        *(float *)(param_2 + 0x7c4) = fVar1;
        *(float *)(param_2 + 0x7c8) = fVar1;
      }
      iVar3 = (**(code **)(*DAT_803dca58 + 0x24))(0);
      if (((iVar3 != 0) && (*(float *)(param_2 + 0x71c) <= FLOAT_803e23dc)) &&
         (iVar3 = FUN_8001ffb4(0xdd), iVar3 != 0)) {
        FUN_8013a3f0((double)FLOAT_803e2444,param_1,0x29,0);
        iVar3 = *(int *)(param_1 + 0xb8);
        if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
            (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)))) {
          FUN_800393f8(param_1,iVar3 + 0x3a8,0x354,0x1000,0xffffffff,0);
        }
        *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x10;
        *(undefined *)(param_2 + 10) = 4;
        uVar2 = FUN_800221a0(0x78,0xf0);
        *(float *)(param_2 + 0x73c) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2460);
      }
    }
  }
  else {
    *(undefined *)(param_2 + 10) = 0;
  }
  return 1;
}

