// Function: FUN_80083e7c
// Entry: 80083e7c
// Size: 528 bytes

undefined4 FUN_80083e7c(undefined4 param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  undefined4 uVar3;
  undefined auStack_18 [20];
  
  uVar3 = 0;
  switch(param_1) {
  default:
    uVar3 = 1;
    break;
  case 1:
    if (*(short *)(param_2 + 0x60) < 1) {
      uVar3 = 1;
    }
    break;
  case 2:
    if (0 < *(short *)(param_2 + 0x60)) {
      uVar3 = 1;
    }
    break;
  case 3:
    iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_18);
    if (iVar1 == 0) {
      uVar3 = 1;
    }
    break;
  case 4:
    iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_18);
    if (iVar1 != 0) {
      uVar3 = 1;
    }
    break;
  case 5:
    if ((&DAT_8039b0bc)[*(char *)(param_2 + 0x57)] == '\0') {
      uVar3 = 1;
    }
    break;
  case 6:
    if ((&DAT_8039b0bc)[*(char *)(param_2 + 0x57)] == '\x01') {
      uVar3 = 1;
    }
    break;
  case 7:
    if ((&DAT_8039b114)[*(char *)(param_2 + 0x57)] == '\0') {
      uVar3 = 1;
    }
    break;
  case 8:
    if ((&DAT_8039b114)[*(char *)(param_2 + 0x57)] != '\0') {
      uVar3 = 1;
    }
    break;
  case 9:
    if (DAT_803ddcec < 1) {
      uVar3 = 1;
    }
    break;
  case 10:
    if (0 < DAT_803ddcec) {
      uVar3 = 1;
    }
    break;
  case 0xb:
    if (DAT_803ddcee < 1) {
      uVar3 = 1;
    }
    break;
  case 0xc:
    if (0 < DAT_803ddcee) {
      uVar3 = 1;
    }
    break;
  case 0xd:
    bVar2 = FUN_8001469c();
    if (bVar2 != 0) {
      uVar3 = 1;
    }
    break;
  case 0xe:
    bVar2 = FUN_8001469c();
    if (bVar2 == 0) {
      uVar3 = 1;
    }
    break;
  case 0x10:
    if (DAT_803ddd00 != '\0') {
      uVar3 = 1;
    }
    break;
  case 0x11:
    if (DAT_803ddd00 == '\0') {
      uVar3 = 1;
    }
  }
  return uVar3;
}

