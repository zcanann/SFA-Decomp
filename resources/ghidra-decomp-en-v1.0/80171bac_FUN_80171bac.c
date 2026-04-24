// Function: FUN_80171bac
// Entry: 80171bac
// Size: 204 bytes

void FUN_80171bac(int param_1)

{
  char cVar3;
  int iVar1;
  short *psVar2;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  cVar3 = FUN_8002e04c();
  if ((((cVar3 != '\0') && (iVar1 = FUN_8002b9ec(), iVar1 != 0)) &&
      (iVar1 = FUN_8002b9ac(), iVar1 == 0)) &&
     (iVar1 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x18)), iVar1 != 0)) {
    iVar1 = FUN_8002bdf4(0x18,0x24);
    *(undefined *)(iVar1 + 4) = 2;
    *(undefined *)(iVar1 + 5) = 4;
    *(undefined *)(iVar1 + 7) = 0xff;
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    psVar2 = (short *)FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    *psVar2 = (ushort)*(byte *)(iVar4 + 0x1a) << 8;
  }
  return;
}

