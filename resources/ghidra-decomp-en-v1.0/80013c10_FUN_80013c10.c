// Function: FUN_80013c10
// Entry: 80013c10
// Size: 104 bytes

undefined4 FUN_80013c10(short **param_1,int param_2,undefined4 param_3)

{
  short *psVar1;
  
  psVar1 = *param_1;
  while( true ) {
    if (param_1[1] <= psVar1) {
      return 0;
    }
    if (*psVar1 == param_2) break;
    psVar1 = psVar1 + *(byte *)((int)param_1 + 0xd);
  }
  FUN_80003494(param_3,psVar1 + 1,*(undefined *)(param_1 + 3));
  return 1;
}

