// Function: FUN_80181204
// Entry: 80181204
// Size: 284 bytes

void FUN_80181204(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  uVar1 = FUN_80022264(0,0x32);
  *(short *)(pfVar3 + 2) = (short)uVar1;
  *pfVar3 = FLOAT_803e4578;
  *(undefined2 *)((int)pfVar3 + 0xe) = *(undefined2 *)(param_2 + 0x24);
  if (*(short *)((int)pfVar3 + 0xe) < 0x6fe) {
    uVar1 = FUN_80020078((int)*(short *)((int)pfVar3 + 0xe));
    *(char *)((int)pfVar3 + 0x1b) = (char)uVar1;
    *(short *)(pfVar3 + 3) = *(short *)((int)pfVar3 + 0xe) + 100;
  }
  else {
    *(undefined *)((int)pfVar3 + 0x1b) = 1;
    *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)((int)pfVar3 + 0xe);
  }
  uVar1 = FUN_80020078((int)*(short *)(pfVar3 + 3));
  *(char *)(pfVar3 + 7) = (char)uVar1;
  iVar2 = *(int *)(param_1 + 0x54);
  if ((iVar2 != 0) && (*(char *)((int)pfVar3 + 0x1b) == '\0')) {
    *(ushort *)(iVar2 + 0x60) = *(ushort *)(iVar2 + 0x60) | 1;
  }
  if (((*(char *)(pfVar3 + 7) != '\0') || (*(char *)((int)pfVar3 + 0x1b) == '\0')) &&
     (*(int *)(param_1 + 0x54) != 0)) {
    FUN_80035ff8(param_1);
  }
  FUN_80037a5c(param_1,1);
  *(undefined **)(param_1 + 0xbc) = &LAB_80180a20;
  return;
}

