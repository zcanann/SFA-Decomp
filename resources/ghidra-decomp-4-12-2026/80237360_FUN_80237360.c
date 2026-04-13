// Function: FUN_80237360
// Entry: 80237360
// Size: 232 bytes

void FUN_80237360(int param_1)

{
  float fVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar4 + 0x24) = 0;
  if ((*(byte *)(iVar3 + 0x2a) & 0x30) != 0) {
    iVar3 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    *(char *)(iVar4 + 0x24) = (char)iVar3;
    if (*(char *)(iVar4 + 0x24) == '\x10') {
      *(char *)(iVar4 + 0x26) = *(char *)(iVar4 + 0x26) + -1;
      *(float *)(iVar4 + 0x1c) = FLOAT_803e801c;
    }
    fVar1 = FLOAT_803e7ff8;
    if (*(float *)(iVar4 + 0x1c) != FLOAT_803e7ff8) {
      *(float *)(iVar4 + 0x1c) = *(float *)(iVar4 + 0x1c) - FLOAT_803dc074;
      if (*(float *)(iVar4 + 0x1c) <= fVar1) {
        *(char *)(iVar4 + 0x26) = *(char *)(iVar4 + 0x26) + '\x01';
        *(float *)(iVar4 + 0x1c) = FLOAT_803e801c;
      }
    }
    cVar2 = *(char *)(iVar4 + 0x26);
    if (cVar2 < '\0') {
      cVar2 = '\0';
    }
    else if ('\x0f' < cVar2) {
      cVar2 = '\x0f';
    }
    *(char *)(iVar4 + 0x26) = cVar2;
  }
  return;
}

