// Function: FUN_80142a14
// Entry: 80142a14
// Size: 344 bytes

undefined4 FUN_80142a14(int param_1,int param_2)

{
  int iVar1;
  char cVar4;
  undefined2 uVar3;
  int iVar2;
  double dVar5;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  FUN_80039510(*(undefined4 *)(param_2 + 0x24),0,&local_28);
  dVar5 = (double)FUN_8002166c(&local_28,param_2 + 0x72c);
  if ((double)FLOAT_803e2424 < dVar5) {
    *(undefined4 *)(param_2 + 0x72c) = local_28;
    *(undefined4 *)(param_2 + 0x730) = local_24;
    *(undefined4 *)(param_2 + 0x734) = local_20;
  }
  if ((*(byte *)(param_2 + 0x728) >> 5 & 1) == 0) {
    cVar4 = FUN_8013b368((double)FLOAT_803e24c8,param_1,param_2);
    if (cVar4 != '\x01') {
      *(byte *)(param_2 + 0x728) = *(byte *)(param_2 + 0x728) & 0xdf | 0x20;
      uVar3 = FUN_800221a0(0x35e,0x35f);
      iVar1 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (iVar2 = FUN_8000b578(param_1,0x10), iVar2 == 0)))) {
        FUN_800393f8(param_1,iVar1 + 0x3a8,uVar3,0x500,0xffffffff,0);
      }
      return 0;
    }
  }
  else {
    iVar1 = FUN_8000b578(param_1,0x10);
    if (iVar1 != 0) {
      return 0;
    }
    FUN_801444a4(param_1,param_2);
  }
  return 1;
}

