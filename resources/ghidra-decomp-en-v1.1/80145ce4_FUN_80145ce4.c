// Function: FUN_80145ce4
// Entry: 80145ce4
// Size: 260 bytes

void FUN_80145ce4(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) | 0x10000;
  }
  else if (*(char *)(iVar4 + 8) == '\x05') {
    if (*(char *)(iVar4 + 10) != '\0') {
      *(int *)(iVar4 + 0x24) = param_3;
    }
  }
  else if ((*(uint *)(iVar4 + 0x54) & 0x10) == 0) {
    uVar1 = FUN_800db36c(param_3 + 0x18,0xffffffff,3);
    *(undefined4 *)(iVar4 + 0x700) = uVar1;
    uVar2 = FUN_80022264(0x168,0x28);
    *(float *)(iVar4 + 0x710) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e30f0);
    *(undefined *)(iVar4 + 8) = 5;
    *(int *)(iVar4 + 0x24) = param_3;
    iVar3 = *(int *)(iVar4 + 0x700) + 8;
    if (*(int *)(iVar4 + 0x28) != iVar3) {
      *(int *)(iVar4 + 0x28) = iVar3;
      *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) & 0xfffffbff;
      *(undefined2 *)(iVar4 + 0xd2) = 0;
    }
    *(undefined *)(iVar4 + 10) = 0;
  }
  return;
}

