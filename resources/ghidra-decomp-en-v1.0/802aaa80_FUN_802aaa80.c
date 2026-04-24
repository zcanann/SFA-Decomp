// Function: FUN_802aaa80
// Entry: 802aaa80
// Size: 356 bytes

void FUN_802aaa80(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  FUN_800206e8(1);
  FUN_80020628(0xff);
  FUN_8005cf68(1);
  if (param_1 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (uint)(-(int)*(char *)(param_1 + 0xad) | (int)*(char *)(param_1 + 0xad)) >> 0x1f;
  }
  if (uVar1 == 0) {
    iVar2 = FUN_8002bdf4(0x20,0x887);
  }
  else {
    iVar2 = FUN_8002bdf4(0x20,0x882);
  }
  *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
  uVar3 = FUN_8002df90(iVar2,5,0xffffffff,0xffffffff,0);
  *(undefined4 *)(iVar5 + 0x46c) = uVar3;
  *(byte *)(iVar5 + 0x3f3) = *(byte *)(iVar5 + 0x3f3) & 0xfb;
  *(byte *)(iVar5 + 0x3f3) = *(byte *)(iVar5 + 0x3f3) & 0xfd | 2;
  DAT_803de42c = 0;
  iVar2 = 0;
  piVar4 = &DAT_80332ed4;
  do {
    if (*piVar4 != 0) {
      FUN_8002cbc4();
      *piVar4 = 0;
    }
    piVar4 = piVar4 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 7);
  if (DAT_803de454 != 0) {
    FUN_80013e2c();
    DAT_803de454 = 0;
  }
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) & 0xfffffbff;
  FUN_8000d01c();
  FUN_8000d200(0x51e0,FUN_8000d138);
  return;
}

