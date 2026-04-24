// Function: FUN_801a41d8
// Entry: 801a41d8
// Size: 192 bytes

void FUN_801a41d8(short *param_1,short **param_2)

{
  char cVar1;
  int iVar2;
  short sVar3;
  short *psVar4;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x26) + 0x19);
  psVar4 = param_1;
  if (((cVar1 != '\x01') && (psVar4 = (short *)0x0, '\0' < cVar1)) && (cVar1 < '\x03')) {
    iVar2 = FUN_8002b9ec();
    sVar3 = FUN_800217f4((int)(*(float *)(iVar2 + 0xc) - *(float *)(param_1 + 6)),
                         (int)(*(float *)(iVar2 + 0x14) - *(float *)(param_1 + 10)));
    *param_1 = sVar3 + -0x8000;
    psVar4 = param_1;
  }
  *param_2 = psVar4;
  return;
}

