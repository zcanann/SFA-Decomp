// Function: FUN_8002d118
// Entry: 8002d118
// Size: 500 bytes

void FUN_8002d118(int param_1,int param_2,undefined4 param_3,uint param_4)

{
  short sVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  
  iVar4 = *(char *)(param_2 + 0x55) * 4 + 0x10c;
  sVar1 = *(short *)(param_1 + 0x46);
  if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
    iVar2 = 0x8e0;
  }
  else if ((*(int **)(param_1 + 0x68) == (int *)0x0) ||
          (pcVar3 = *(code **)(**(int **)(param_1 + 0x68) + 0x1c), pcVar3 == (code *)0x0)) {
    iVar2 = 0;
  }
  else {
    iVar2 = (*pcVar3)(param_1,iVar4);
  }
  iVar4 = iVar4 + iVar2;
  if (((param_4 & 0x40) != 0) || ((*(uint *)(param_2 + 0x44) & 0x400000) != 0)) {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = FUN_80022e3c(iVar4 + 8);
    iVar4 = iVar4 + 0x50;
  }
  if ((param_4 & 0x100) != 0) {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = FUN_80022e3c(iVar4 + 8);
    iVar4 = iVar4 + 0x800;
  }
  if (((param_4 & 2) != 0) && (*(short *)(param_2 + 0x48) != 0)) {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = iVar4 + 0x44;
  }
  if (*(char *)(param_2 + 0x61) != '\0') {
    iVar2 = FUN_80022e24(iVar4);
    iVar4 = iVar2 + 0xb8;
    if ((*(byte *)(param_2 + 0x65) & 8) != 0) {
      iVar4 = iVar2 + 0x1c8;
    }
  }
  if (*(char *)(param_2 + 0x5a) != '\0') {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = iVar4 + (uint)*(byte *)(param_2 + 0x5a) * 0x12;
  }
  if (*(char *)(param_2 + 0x59) != '\0') {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = iVar4 + (uint)*(byte *)(param_2 + 0x59) * 0x10;
  }
  if (*(char *)(param_2 + 0x72) != '\0') {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = iVar4 + (uint)*(byte *)(param_2 + 0x72) * 0x18;
  }
  if ((*(char *)(param_2 + 0x61) != '\0') && (*(char *)(param_2 + 0x66) != '\0')) {
    iVar4 = FUN_80022e3c(iVar4);
    iVar4 = iVar4 + 300;
  }
  if (*(char *)(param_2 + 0x72) != '\0') {
    iVar4 = FUN_80022e24(iVar4);
    iVar4 = iVar4 + (uint)*(byte *)(param_2 + 0x72) * 5;
  }
  FUN_80022e6c(iVar4);
  return;
}

