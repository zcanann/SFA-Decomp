// Function: FUN_80180cac
// Entry: 80180cac
// Size: 284 bytes

void FUN_80180cac(int param_1,int param_2)

{
  undefined2 uVar2;
  undefined uVar3;
  int iVar1;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  uVar2 = FUN_800221a0(0,0x32);
  *(undefined2 *)(pfVar4 + 2) = uVar2;
  *pfVar4 = FLOAT_803e38e0;
  *(undefined2 *)((int)pfVar4 + 0xe) = *(undefined2 *)(param_2 + 0x24);
  if (*(short *)((int)pfVar4 + 0xe) < 0x6fe) {
    uVar3 = FUN_8001ffb4();
    *(undefined *)((int)pfVar4 + 0x1b) = uVar3;
    *(short *)(pfVar4 + 3) = *(short *)((int)pfVar4 + 0xe) + 100;
  }
  else {
    *(undefined *)((int)pfVar4 + 0x1b) = 1;
    *(undefined2 *)(pfVar4 + 3) = *(undefined2 *)((int)pfVar4 + 0xe);
  }
  uVar3 = FUN_8001ffb4((int)*(short *)(pfVar4 + 3));
  *(undefined *)(pfVar4 + 7) = uVar3;
  iVar1 = *(int *)(param_1 + 0x54);
  if ((iVar1 != 0) && (*(char *)((int)pfVar4 + 0x1b) == '\0')) {
    *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) | 1;
  }
  if (((*(char *)(pfVar4 + 7) != '\0') || (*(char *)((int)pfVar4 + 0x1b) == '\0')) &&
     (*(int *)(param_1 + 0x54) != 0)) {
    FUN_80035f00(param_1);
  }
  FUN_80037964(param_1,1);
  *(undefined **)(param_1 + 0xbc) = &LAB_801804c8;
  return;
}

