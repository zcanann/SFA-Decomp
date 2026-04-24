// Function: FUN_80216b90
// Entry: 80216b90
// Size: 264 bytes

void FUN_80216b90(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(iVar3 + 4);
  sVar1 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1a));
  if ((sVar1 < 1) && (iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1c)), iVar4 == 0)) {
    if (iVar2 != 0) {
      FUN_8001db6c((double)FLOAT_803e68c0,iVar2,0);
    }
  }
  else {
    if (sVar1 == 0) {
      sVar1 = 0x10;
    }
    if (iVar2 != 0) {
      FUN_8001db6c((double)FLOAT_803e68c0,iVar2,1);
      FUN_8001daf0(iVar2,100,0x6e,0xff,0xff);
      FUN_8001dc38((double)(float)((double)CONCAT44(0x43300000,sVar1 * 0x1a ^ 0x80000000) -
                                  DOUBLE_803e68c8),
                   (double)(float)((double)CONCAT44(0x43300000,sVar1 * 0x1a + 0x14U ^ 0x80000000) -
                                  DOUBLE_803e68c8),*(undefined4 *)(iVar3 + 4));
    }
  }
  return;
}

