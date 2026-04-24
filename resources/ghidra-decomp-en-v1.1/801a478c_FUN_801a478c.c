// Function: FUN_801a478c
// Entry: 801a478c
// Size: 192 bytes

void FUN_801a478c(short *param_1,undefined4 *param_2)

{
  char cVar1;
  int iVar2;
  short *psVar3;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x26) + 0x19);
  psVar3 = param_1;
  if (((cVar1 != '\x01') && (psVar3 = (short *)0x0, '\0' < cVar1)) && (cVar1 < '\x03')) {
    FUN_8002bac4();
    iVar2 = FUN_800218b8();
    *param_1 = (short)iVar2 + -0x8000;
    psVar3 = param_1;
  }
  *param_2 = psVar3;
  return;
}

