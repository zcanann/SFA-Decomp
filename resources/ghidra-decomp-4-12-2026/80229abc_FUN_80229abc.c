// Function: FUN_80229abc
// Entry: 80229abc
// Size: 212 bytes

void FUN_80229abc(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  iVar1 = FUN_8005b478((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10));
  iVar1 = FUN_8005b068(iVar1);
  if (iVar1 != 0) {
    uVar4 = 1;
    do {
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar3 = iVar3 + 1) {
        iVar2 = FUN_80060888(iVar1,iVar3);
        if (*(byte *)(iVar2 + 0x29) == uVar4) {
          if (((uint)uVar5 & 0xff & 1 << uVar4 - 1) == 0) {
            FUN_80056be8(uVar4,*(int *)(iVar2 + 0x24),0);
          }
          else {
            FUN_80056be8(uVar4,*(int *)(iVar2 + 0x24),0x100);
          }
        }
      }
      uVar4 = uVar4 + 1;
    } while ((int)uVar4 < 4);
  }
  FUN_8028688c();
  return;
}

