// Function: FUN_80155948
// Entry: 80155948
// Size: 356 bytes

void FUN_80155948(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  ushort local_18 [2];
  undefined auStack20 [12];
  
  if (*(char *)(param_2 + 0x33a) == '\0') {
    FUN_801554b4();
  }
  else if ((*(short *)(*(int *)(param_2 + 0x29c) + 0x44) == 1) &&
          (iVar2 = FUN_80295cbc(), iVar2 != 0)) {
    FUN_80035df4(param_1,10,1,0);
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 3) {
      FUN_80154fb4((double)FLOAT_803e2a00,param_1,param_2,0x19);
    }
    else if ((sVar1 == 0) || (sVar1 == 1)) {
      FUN_80154fb4((double)FLOAT_803e2a30,param_1,param_2,0x19);
    }
    FUN_80154d0c(param_1,param_2,local_18,auStack20);
    if (((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) ||
       ((local_18[0] < 0x5dc && (*(short *)(param_1 + 0xa0) != 1)))) {
      if (local_18[0] < 0x5dc) {
        FUN_8000bb18(param_1,0x251);
        FUN_8014d08c((double)FLOAT_803e2a30,param_1,param_2,1,0,0);
      }
      else {
        FUN_8014d08c((double)FLOAT_803e2a30,param_1,param_2,3,0,0);
      }
    }
  }
  else {
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
  }
  return;
}

