// Function: FUN_80083bf0
// Entry: 80083bf0
// Size: 528 bytes

undefined4 FUN_80083bf0(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack24 [20];
  
  uVar2 = 0;
  switch(param_1) {
  default:
    uVar2 = 1;
    break;
  case 1:
    if (*(short *)(param_2 + 0x60) < 1) {
      uVar2 = 1;
    }
    break;
  case 2:
    if (0 < *(short *)(param_2 + 0x60)) {
      uVar2 = 1;
    }
    break;
  case 3:
    iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(auStack24);
    if (iVar1 == 0) {
      uVar2 = 1;
    }
    break;
  case 4:
    iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(auStack24);
    if (iVar1 != 0) {
      uVar2 = 1;
    }
    break;
  case 5:
    if ((&DAT_8039a45c)[*(char *)(param_2 + 0x57)] == '\0') {
      uVar2 = 1;
    }
    break;
  case 6:
    if ((&DAT_8039a45c)[*(char *)(param_2 + 0x57)] == '\x01') {
      uVar2 = 1;
    }
    break;
  case 7:
    if ((&DAT_8039a4b4)[*(char *)(param_2 + 0x57)] == '\0') {
      uVar2 = 1;
    }
    break;
  case 8:
    if ((&DAT_8039a4b4)[*(char *)(param_2 + 0x57)] != '\0') {
      uVar2 = 1;
    }
    break;
  case 9:
    if (DAT_803dd06c < 1) {
      uVar2 = 1;
    }
    break;
  case 10:
    if (0 < DAT_803dd06c) {
      uVar2 = 1;
    }
    break;
  case 0xb:
    if (DAT_803dd06e < 1) {
      uVar2 = 1;
    }
    break;
  case 0xc:
    if (0 < DAT_803dd06e) {
      uVar2 = 1;
    }
    break;
  case 0xd:
    iVar1 = FUN_80014670();
    if (iVar1 != 0) {
      uVar2 = 1;
    }
    break;
  case 0xe:
    iVar1 = FUN_80014670();
    if (iVar1 == 0) {
      uVar2 = 1;
    }
    break;
  case 0x10:
    if (DAT_803dd080 != '\0') {
      uVar2 = 1;
    }
    break;
  case 0x11:
    if (DAT_803dd080 == '\0') {
      uVar2 = 1;
    }
  }
  return uVar2;
}

