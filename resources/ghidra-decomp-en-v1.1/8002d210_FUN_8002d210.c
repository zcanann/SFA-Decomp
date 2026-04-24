// Function: FUN_8002d210
// Entry: 8002d210
// Size: 500 bytes

void FUN_8002d210(int param_1,int param_2,undefined4 param_3,uint param_4)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  code *pcVar4;
  int iVar5;
  uint uVar6;
  
  iVar5 = *(char *)(param_2 + 0x55) * 4 + 0x10c;
  sVar1 = *(short *)(param_1 + 0x46);
  if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
    iVar2 = 0x8e0;
  }
  else if ((*(int **)(param_1 + 0x68) == (int *)0x0) ||
          (pcVar4 = *(code **)(**(int **)(param_1 + 0x68) + 0x1c), pcVar4 == (code *)0x0)) {
    iVar2 = 0;
  }
  else {
    iVar2 = (*pcVar4)(param_1,iVar5);
  }
  uVar6 = iVar5 + iVar2;
  if (((param_4 & 0x40) != 0) || ((*(uint *)(param_2 + 0x44) & 0x400000) != 0)) {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = FUN_80022f00(uVar6 + 8);
    uVar6 = uVar6 + 0x50;
  }
  if ((param_4 & 0x100) != 0) {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = FUN_80022f00(uVar6 + 8);
    uVar6 = uVar6 + 0x800;
  }
  if (((param_4 & 2) != 0) && (*(short *)(param_2 + 0x48) != 0)) {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = uVar6 + 0x44;
  }
  if (*(char *)(param_2 + 0x61) != '\0') {
    uVar3 = FUN_80022ee8(uVar6);
    uVar6 = uVar3 + 0xb8;
    if ((*(byte *)(param_2 + 0x65) & 8) != 0) {
      uVar6 = uVar3 + 0x1c8;
    }
  }
  if (*(char *)(param_2 + 0x5a) != '\0') {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = uVar6 + (uint)*(byte *)(param_2 + 0x5a) * 0x12;
  }
  if (*(char *)(param_2 + 0x59) != '\0') {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = uVar6 + (uint)*(byte *)(param_2 + 0x59) * 0x10;
  }
  if (*(char *)(param_2 + 0x72) != '\0') {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = uVar6 + (uint)*(byte *)(param_2 + 0x72) * 0x18;
  }
  if ((*(char *)(param_2 + 0x61) != '\0') && (*(char *)(param_2 + 0x66) != '\0')) {
    uVar6 = FUN_80022f00(uVar6);
    uVar6 = uVar6 + 300;
  }
  if (*(char *)(param_2 + 0x72) != '\0') {
    uVar6 = FUN_80022ee8(uVar6);
    uVar6 = uVar6 + (uint)*(byte *)(param_2 + 0x72) * 5;
  }
  FUN_80022f30(uVar6);
  return;
}

