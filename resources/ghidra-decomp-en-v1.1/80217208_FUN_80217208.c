// Function: FUN_80217208
// Entry: 80217208
// Size: 264 bytes

void FUN_80217208(int param_1)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(iVar4 + 4);
  uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1a));
  sVar2 = (short)uVar1;
  if ((sVar2 < 1) && (uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1c)), uVar1 == 0)) {
    if (iVar3 != 0) {
      FUN_8001dc30((double)FLOAT_803e7558,iVar3,'\0');
    }
  }
  else {
    if (sVar2 == 0) {
      sVar2 = 0x10;
    }
    if (iVar3 != 0) {
      FUN_8001dc30((double)FLOAT_803e7558,iVar3,'\x01');
      FUN_8001dbb4(iVar3,100,0x6e,0xff,0xff);
      FUN_8001dcfc((double)(float)((double)CONCAT44(0x43300000,sVar2 * 0x1a ^ 0x80000000) -
                                  DOUBLE_803e7560),
                   (double)(float)((double)CONCAT44(0x43300000,sVar2 * 0x1a + 0x14U ^ 0x80000000) -
                                  DOUBLE_803e7560),*(int *)(iVar4 + 4));
    }
  }
  return;
}

