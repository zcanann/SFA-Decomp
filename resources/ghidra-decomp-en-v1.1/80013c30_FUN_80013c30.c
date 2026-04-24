// Function: FUN_80013c30
// Entry: 80013c30
// Size: 104 bytes

undefined4 FUN_80013c30(undefined4 *param_1,int param_2,uint param_3)

{
  short *psVar1;
  
  psVar1 = (short *)*param_1;
  while( true ) {
    if ((short *)param_1[1] <= psVar1) {
      return 0;
    }
    if (*psVar1 == param_2) break;
    psVar1 = psVar1 + *(byte *)((int)param_1 + 0xd);
  }
  FUN_80003494(param_3,(uint)(psVar1 + 1),(uint)*(byte *)(param_1 + 3));
  return 1;
}

