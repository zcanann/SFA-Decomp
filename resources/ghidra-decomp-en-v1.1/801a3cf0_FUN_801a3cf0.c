// Function: FUN_801a3cf0
// Entry: 801a3cf0
// Size: 632 bytes

void FUN_801a3cf0(undefined2 *param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  FUN_800372f8((int)param_1,0x21);
  iVar5 = *(int *)(param_1 + 0x5c);
  cVar1 = *(char *)(param_2 + 0x18);
  if (cVar1 == '\0') {
    cVar1 = '\x01';
  }
  *(char *)(iVar5 + 0x6d4) = cVar1;
  *(undefined4 *)(iVar5 + 0x6cc) = 0;
  *(undefined4 *)(iVar5 + 0x690) = 0;
  *(undefined4 *)(iVar5 + 0x694) = 0;
  *(undefined4 *)(iVar5 + 0x698) = 0;
  *(undefined4 *)(iVar5 + 0x69c) = 0;
  *(undefined4 *)(iVar5 + 0x6a0) = 0;
  *(undefined4 *)(iVar5 + 0x6a4) = 0;
  *(undefined4 *)(iVar5 + 0x6a8) = 0;
  *(undefined4 *)(iVar5 + 0x6ac) = 0;
  *(undefined4 *)(iVar5 + 0x6b0) = 0;
  *(undefined4 *)(iVar5 + 0x6b4) = 0;
  *(undefined4 *)(iVar5 + 0x6b8) = 0;
  *(undefined4 *)(iVar5 + 0x6bc) = 0;
  *(undefined4 *)(iVar5 + 0x6c0) = 0;
  *(undefined4 *)(iVar5 + 0x6c4) = 0;
  *(undefined4 *)(iVar5 + 0x6c8) = 0;
  *param_1 = *(undefined2 *)(param_2 + 0x1a);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  param_1[2] = *(undefined2 *)(param_2 + 0x1e);
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x3e));
  if (uVar2 != 0) {
    *(undefined *)(iVar5 + 0x6e4) = 2;
  }
  cVar1 = '\0';
  piVar4 = &DAT_803239f0;
  iVar6 = 2;
  do {
    iVar3 = (int)(short)param_1[0x23];
    if (iVar3 == *piVar4) {
      *(char *)(iVar5 + 0x6e5) = cVar1;
      break;
    }
    if (iVar3 == piVar4[4]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x01';
      break;
    }
    if (iVar3 == piVar4[8]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x02';
      break;
    }
    if (iVar3 == piVar4[0xc]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x03';
      break;
    }
    if (iVar3 == piVar4[0x10]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x04';
      break;
    }
    if (iVar3 == piVar4[0x14]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x05';
      break;
    }
    if (iVar3 == piVar4[0x18]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x06';
      break;
    }
    if (iVar3 == piVar4[0x1c]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\a';
      break;
    }
    piVar4 = piVar4 + 0x20;
    cVar1 = cVar1 + '\b';
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  if (*(char *)(param_2 + 0x3d) == '\0') {
    *(undefined *)(param_2 + 0x3d) = 0x14;
  }
  *(float *)(param_1 + 4) =
       (*(float *)(*(int *)(param_1 + 0x28) + 4) *
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x3d) ^ 0x80000000) -
              DOUBLE_803e5020)) / FLOAT_803e4ff4;
  if (((&DAT_803239fd)[(uint)*(byte *)(iVar5 + 0x6e5) * 0x10] & 1) != 0) {
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  return;
}

