// Function: FUN_8029a5e4
// Entry: 8029a5e4
// Size: 392 bytes

int FUN_8029a5e4(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_802ac7dc(param_1,param_2,iVar4);
  if (iVar2 == 0) {
    FUN_8011f3ec(6);
    FUN_8011f3c8(10);
    if (*(char *)(param_2 + 0x27a) != '\0') {
      iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
      sVar1 = *(short *)(iVar2 + 4);
      if (sVar1 < 0) {
        sVar1 = 0;
      }
      else if (*(short *)(iVar2 + 6) < sVar1) {
        sVar1 = *(short *)(iVar2 + 6);
      }
      *(short *)(iVar2 + 4) = sVar1;
      FLOAT_803de45c = FLOAT_803e7f30;
    }
    if (((FLOAT_803e7f30 == FLOAT_803de45c) || (FLOAT_803e7fa0 == FLOAT_803de45c)) ||
       (FLOAT_803e7fa4 == FLOAT_803de45c)) {
      uVar3 = FUN_800221a0(0xffffff38,200);
      FUN_802aa2b0((double)*(float *)(iVar4 + 0x7bc),
                   (double)((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                   DOUBLE_803e7ec0) / FLOAT_803e7f5c),param_1,param_2);
    }
    FLOAT_803de45c = FLOAT_803de45c - FLOAT_803e7ee0;
    if (FLOAT_803e7ea4 <= FLOAT_803de45c) {
      if ((*(int *)(param_2 + 0x2d0) == 0) &&
         (((*(ushort *)(iVar4 + 0x6e2) & 0x200) != 0 || (*(char *)(iVar4 + 0x8c8) != 'R')))) {
        *(code **)(param_2 + 0x308) = FUN_8029a420;
        iVar2 = 0x2c;
      }
      else {
        iVar2 = 0;
      }
    }
    else {
      *(code **)(param_2 + 0x308) = FUN_8029a4a8;
      iVar2 = 0x2d;
    }
  }
  return iVar2;
}

