// Function: FUN_8002c36c
// Entry: 8002c36c
// Size: 228 bytes

void FUN_8002c36c(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  uVar5 = 0;
  iVar1 = FUN_80048f10(0x38);
  if (iVar1 + -4 >> 2 < iVar3) {
    uVar5 = 0;
  }
  else {
    piVar2 = (int *)FUN_80023cc8(0x10,0x1a,0);
    FUN_80048f48(0x38,piVar2,iVar3 << 2,8);
    iVar3 = *piVar2;
    uVar4 = piVar2[1] - iVar3;
    if (0 < (int)uVar4) {
      uVar5 = FUN_80023cc8(uVar4,5,0);
      FUN_80048f48(0x37,uVar5,iVar3,uVar4);
    }
    FUN_80023800(piVar2);
    *(undefined2 *)uVar6 = (short)(uVar4 / 0x14);
  }
  FUN_80286128(uVar5);
  return;
}

