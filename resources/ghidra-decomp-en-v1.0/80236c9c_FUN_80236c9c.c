// Function: FUN_80236c9c
// Entry: 80236c9c
// Size: 232 bytes

void FUN_80236c9c(int param_1)

{
  float fVar1;
  char cVar2;
  undefined uVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar5 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar5 + 0x24) = 0;
  if ((*(byte *)(iVar4 + 0x2a) & 0x30) != 0) {
    uVar3 = FUN_8003687c(param_1,0,0,0);
    *(undefined *)(iVar5 + 0x24) = uVar3;
    if (*(char *)(iVar5 + 0x24) == '\x10') {
      *(char *)(iVar5 + 0x26) = *(char *)(iVar5 + 0x26) + -1;
      *(float *)(iVar5 + 0x1c) = FLOAT_803e7384;
    }
    fVar1 = FLOAT_803e7360;
    if ((*(float *)(iVar5 + 0x1c) != FLOAT_803e7360) &&
       (*(float *)(iVar5 + 0x1c) = *(float *)(iVar5 + 0x1c) - FLOAT_803db414,
       *(float *)(iVar5 + 0x1c) <= fVar1)) {
      *(char *)(iVar5 + 0x26) = *(char *)(iVar5 + 0x26) + '\x01';
      *(float *)(iVar5 + 0x1c) = FLOAT_803e7384;
    }
    cVar2 = *(char *)(iVar5 + 0x26);
    if (cVar2 < '\0') {
      cVar2 = '\0';
    }
    else if ('\x0f' < cVar2) {
      cVar2 = '\x0f';
    }
    *(char *)(iVar5 + 0x26) = cVar2;
  }
  return;
}

