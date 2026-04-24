// Function: FUN_80013b7c
// Entry: 80013b7c
// Size: 148 bytes

undefined4 FUN_80013b7c(short **param_1,undefined4 param_2,int *param_3)

{
  int iVar1;
  short *psVar2;
  
  psVar2 = *param_1;
  while( true ) {
    if (param_1[1] <= psVar2) {
      return 0;
    }
    iVar1 = FUN_8028f228(psVar2 + 1,param_2,*(undefined *)(param_1 + 3));
    if (iVar1 == 0) break;
    psVar2 = psVar2 + *(byte *)((int)param_1 + 0xd);
  }
  *param_3 = (int)*psVar2;
  return 1;
}

