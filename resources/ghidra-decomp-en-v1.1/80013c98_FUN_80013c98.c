// Function: FUN_80013c98
// Entry: 80013c98
// Size: 112 bytes

void FUN_80013c98(uint *param_1,int param_2)

{
  short *psVar1;
  
  psVar1 = (short *)*param_1;
  do {
    if ((short *)param_1[1] <= psVar1) {
LAB_80013ce8:
      while( true ) {
        if (param_1[1] <= *param_1) {
          return;
        }
        if (*(short *)(param_1[1] - 2) != -1) break;
        param_1[1] = param_1[1] + (uint)*(byte *)((int)param_1 + 0xd) * -2;
      }
      return;
    }
    if (*psVar1 == param_2) {
      *psVar1 = -1;
      goto LAB_80013ce8;
    }
    psVar1 = psVar1 + *(byte *)((int)param_1 + 0xd);
  } while( true );
}

