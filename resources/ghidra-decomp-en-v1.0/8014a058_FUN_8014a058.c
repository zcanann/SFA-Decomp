// Function: FUN_8014a058
// Entry: 8014a058
// Size: 248 bytes

void FUN_8014a058(int param_1,int param_2)

{
  char cVar2;
  undefined4 uVar1;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((*(short *)(param_2 + 0x2b4) != *(short *)(param_2 + 0x2b6)) &&
     (*(char *)(param_1 + 0x36) != '\0')) {
    iVar4 = *(int *)(param_1 + 200);
    if (iVar4 != 0) {
      FUN_80037cb0(param_1,iVar4);
      FUN_8002cbc4(iVar4);
    }
    cVar2 = FUN_8002e04c();
    if (cVar2 == '\0') {
      *(undefined2 *)(param_2 + 0x2b4) = 0;
    }
    else if (0 < *(short *)(param_2 + 0x2b6)) {
      iVar4 = FUN_8002bdf4(0x20);
      *(byte *)(iVar4 + 5) = *(byte *)(iVar4 + 5) | *(byte *)(iVar3 + 5) & 0x18;
      uVar1 = FUN_8002df90(iVar4,4,(int)*(char *)(param_1 + 0xac),0xffffffff,
                           *(undefined4 *)(param_1 + 0x30));
      FUN_80037d2c(param_1,uVar1,0);
      *(undefined2 *)(param_2 + 0x2b4) = *(undefined2 *)(param_2 + 0x2b6);
    }
  }
  return;
}

