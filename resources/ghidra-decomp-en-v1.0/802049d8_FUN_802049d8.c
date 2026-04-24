// Function: FUN_802049d8
// Entry: 802049d8
// Size: 284 bytes

void FUN_802049d8(int param_1)

{
  char cVar2;
  int iVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(param_1 + 0xb8);
  cVar2 = FUN_8002e04c();
  if ((((cVar2 != '\0') && (*(short *)(iVar4 + 0x1a) == 7)) &&
      (*(short *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) - (short)(int)FLOAT_803db414,
      *(short *)(iVar3 + 0x10) < 1)) &&
     (iVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0xc)), iVar1 != 0)) {
    *(undefined2 *)(iVar3 + 0x10) = *(undefined2 *)(iVar3 + 0xe);
    iVar3 = FUN_8002bdf4(0x24,0x71b);
    *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x10);
    *(undefined *)(iVar3 + 4) = *(undefined *)(iVar4 + 4);
    *(undefined *)(iVar3 + 5) = *(undefined *)(iVar4 + 5);
    *(undefined *)(iVar3 + 6) = *(undefined *)(iVar4 + 6);
    *(undefined *)(iVar3 + 7) = *(undefined *)(iVar4 + 7);
    *(undefined2 *)(iVar3 + 0x1e) = 0xffff;
    *(undefined2 *)(iVar3 + 0x20) = 0xffff;
    *(undefined2 *)(iVar3 + 0x1a) = 0xdc;
    iVar3 = FUN_8002df90(iVar3,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                         *(undefined4 *)(param_1 + 0x30));
    *(int *)(iVar3 + 0xf4) = (int)*(char *)(iVar4 + 0x1e);
  }
  return;
}

