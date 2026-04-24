// Function: FUN_8028e78c
// Entry: 8028e78c
// Size: 112 bytes

int FUN_8028e78c(uint param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  
  iVar2 = 0x20;
  uVar5 = 0xffff;
  uVar3 = 0x10;
  iVar1 = 0;
  iVar4 = 0x10;
  do {
    if (iVar2 == 0) {
      return iVar1;
    }
    if ((param_1 & uVar5) == 0) {
      iVar1 = iVar1 + iVar4;
      param_1 = param_1 >> iVar4;
      iVar2 = iVar2 - iVar4;
    }
    else if (uVar5 == 1) {
      return iVar1;
    }
    if (1 < uVar3) {
      uVar3 = (int)uVar3 >> 1;
    }
    if (1 < uVar5) {
      uVar5 = uVar5 >> uVar3;
      iVar4 = iVar4 - uVar3;
    }
  } while( true );
}

