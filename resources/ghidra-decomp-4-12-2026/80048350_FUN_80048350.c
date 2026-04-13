// Function: FUN_80048350
// Entry: 80048350
// Size: 340 bytes

void FUN_80048350(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  undefined8 uVar5;
  
  uVar2 = FUN_80014e9c(2);
  if ((uVar2 & 0x100) != 0) {
    iVar1 = 7;
    do {
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    FUN_80022e1c();
  }
  uVar2 = FUN_80014e9c(2);
  if ((uVar2 & 0x200) != 0) {
    FUN_80041f34();
  }
  if (DAT_803dd8f8 != 0) {
    if (DAT_803dd8f8 == 1) {
      FUN_80041f34();
    }
    DAT_803dd8f8 = DAT_803dd8f8 + -1;
  }
  iVar1 = 0;
  piVar4 = &DAT_8035fba8;
  do {
    if (*piVar4 != -1) {
      FUN_801378a8(0,0xff,0,0xff);
      FUN_80137cd0();
      uVar5 = FUN_801378a8(0xff,0xff,0xff,0xff);
      DAT_803dd8f0 = 1;
      iVar3 = FUN_80044548(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (iVar3 != 0) {
        *piVar4 = -1;
        FUN_80022e1c();
      }
      DAT_803dd8f0 = 0;
    }
    piVar4 = piVar4 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x58);
  FUN_800431d8();
  return;
}

