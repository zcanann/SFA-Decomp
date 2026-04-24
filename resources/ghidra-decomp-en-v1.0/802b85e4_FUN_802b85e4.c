// Function: FUN_802b85e4
// Entry: 802b85e4
// Size: 212 bytes

void FUN_802b85e4(int param_1,int param_2)

{
  char cVar2;
  undefined4 uVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_2 + 0x40c);
  if ((*(short *)(iVar4 + 0x26) != *(short *)(iVar4 + 0x28)) && (*(char *)(param_1 + 0x36) != '\0'))
  {
    iVar3 = *(int *)(param_1 + 200);
    if (iVar3 != 0) {
      FUN_80037cb0(param_1,iVar3);
      FUN_8002cbc4(iVar3);
    }
    cVar2 = FUN_8002e04c();
    if (cVar2 == '\0') {
      *(undefined2 *)(iVar4 + 0x26) = 0;
    }
    else if (0 < *(short *)(iVar4 + 0x28)) {
      uVar1 = FUN_8002bdf4(0x20);
      uVar1 = FUN_8002df90(uVar1,4,(int)*(char *)(param_1 + 0xac),0xffffffff,
                           *(undefined4 *)(param_1 + 0x30));
      FUN_80037d2c(param_1,uVar1,0);
      *(undefined2 *)(iVar4 + 0x26) = *(undefined2 *)(iVar4 + 0x28);
    }
  }
  return;
}

