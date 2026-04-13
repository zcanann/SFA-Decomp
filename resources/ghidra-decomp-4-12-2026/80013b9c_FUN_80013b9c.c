// Function: FUN_80013b9c
// Entry: 80013b9c
// Size: 148 bytes

undefined4 FUN_80013b9c(undefined4 *param_1,int param_2,int *param_3)

{
  int iVar1;
  short *psVar2;
  
  psVar2 = (short *)*param_1;
  while( true ) {
    if ((short *)param_1[1] <= psVar2) {
      return 0;
    }
    iVar1 = FUN_8028f988((int)(psVar2 + 1),param_2,(uint)*(byte *)(param_1 + 3));
    if (iVar1 == 0) break;
    psVar2 = psVar2 + *(byte *)((int)param_1 + 0xd);
  }
  *param_3 = (int)*psVar2;
  return 1;
}

