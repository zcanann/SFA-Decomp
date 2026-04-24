// Function: FUN_802a96d8
// Entry: 802a96d8
// Size: 248 bytes

void FUN_802a96d8(void)

{
  char cVar2;
  int iVar1;
  short sVar3;
  int *piVar4;
  
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    piVar4 = &DAT_80332ed4;
    sVar3 = 0;
    for (cVar2 = '\0'; cVar2 < '\a'; cVar2 = cVar2 + '\x01') {
      if (*piVar4 == 0) {
        iVar1 = FUN_8002bdf4(0x24,0x4ec);
        FUN_8003842c(DAT_803de44c,0,iVar1 + 8,iVar1 + 0xc,iVar1 + 0x10,0);
        *(undefined *)(iVar1 + 4) = 2;
        *(undefined *)(iVar1 + 5) = 1;
        *(undefined *)(iVar1 + 6) = 0xff;
        *(undefined *)(iVar1 + 7) = 0xff;
        *(short *)(iVar1 + 0x1a) = sVar3;
        *(undefined2 *)(iVar1 + 0x1c) = 0;
        iVar1 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
        *piVar4 = iVar1;
      }
      piVar4 = piVar4 + 1;
      sVar3 = sVar3 + 3;
    }
  }
  return;
}

