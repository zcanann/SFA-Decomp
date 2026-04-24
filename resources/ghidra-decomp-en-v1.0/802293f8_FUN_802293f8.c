// Function: FUN_802293f8
// Entry: 802293f8
// Size: 212 bytes

void FUN_802293f8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  FUN_8005b2fc((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10),
               (double)*(float *)(iVar1 + 0x14));
  iVar1 = FUN_8005aeec();
  if (iVar1 != 0) {
    uVar4 = 1;
    do {
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar3 = iVar3 + 1) {
        iVar2 = FUN_8006070c(iVar1,iVar3);
        if (*(byte *)(iVar2 + 0x29) == uVar4) {
          if (((uint)uVar5 & 0xff & 1 << uVar4 - 1) == 0) {
            FUN_80056a6c(uVar4,*(undefined4 *)(iVar2 + 0x24),0);
          }
          else {
            FUN_80056a6c(uVar4,*(undefined4 *)(iVar2 + 0x24),0x100);
          }
        }
      }
      uVar4 = uVar4 + 1;
    } while ((int)uVar4 < 4);
  }
  FUN_80286128();
  return;
}

