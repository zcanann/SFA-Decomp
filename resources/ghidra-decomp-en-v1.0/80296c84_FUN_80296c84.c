// Function: FUN_80296c84
// Entry: 80296c84
// Size: 156 bytes

void FUN_80296c84(int param_1)

{
  char cVar1;
  char cVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  cVar2 = *(char *)(*(int *)(iVar3 + 0x35c) + 1);
  if (cVar2 < '\0') {
    cVar2 = '\0';
  }
  else {
    cVar1 = *(char *)(*(int *)(iVar3 + 0x35c) + 1);
    if (cVar1 < cVar2) {
      cVar2 = cVar1;
    }
  }
  **(char **)(iVar3 + 0x35c) = cVar2;
  FUN_8002ac30(param_1,0x168,200,0,0,1);
  *(byte *)(iVar3 + 0x3f3) = *(byte *)(iVar3 + 0x3f3) & 0xfb | 4;
  *(float *)(iVar3 + 0x79c) = FLOAT_803e7ea4;
  *(undefined *)(iVar3 + 0x8a2) = 0xff;
  return;
}

