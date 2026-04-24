// Function: FUN_8016b0a4
// Entry: 8016b0a4
// Size: 388 bytes

void FUN_8016b0a4(int param_1,int param_2)

{
  bool bVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;
  
  puVar5 = *(undefined4 **)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x19) == '\x01') {
    puVar5[2] = FLOAT_803e3198;
  }
  else {
    uVar3 = FUN_800221a0(0xb4,300);
    puVar5[2] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3190);
  }
  bVar2 = *(byte *)(param_2 + 0x19);
  if ((char)bVar2 < '\0') {
    bVar2 = 0;
  }
  else if (5 < bVar2) {
    bVar2 = 5;
  }
  *(byte *)(param_2 + 0x19) = bVar2;
  puVar5[7] = (&PTR_DAT_8032059c)[*(char *)(param_2 + 0x19)];
  if ((int)*(short *)puVar5[7] != 0) {
    FUN_8000b4d0(param_1,(int)*(short *)puVar5[7] & 0xffff,3);
  }
  iVar4 = 4;
  do {
    (**(code **)(*DAT_803dca88 + 8))(param_1,(int)*(short *)(puVar5[7] + 6),0,1,0xffffffff,0);
    bVar1 = iVar4 != 0;
    iVar4 = iVar4 + -1;
  } while (bVar1);
  if ((*(byte *)(puVar5[7] + 0x12) >> 6 & 1) == 0) {
    puVar5[2] = FLOAT_803e319c;
  }
  FUN_80035960(param_1,4);
  puVar5[6] = 0;
  puVar5[1] = *(undefined4 *)(puVar5[7] + 0xc);
  *puVar5 = 0;
  FUN_80080178(puVar5 + 9,0xe10);
  FUN_8008016c(puVar5 + 8);
  return;
}

