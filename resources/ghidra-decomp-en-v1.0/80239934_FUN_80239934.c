// Function: FUN_80239934
// Entry: 80239934
// Size: 996 bytes

undefined4 FUN_80239934(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  short *psVar2;
  int iVar3;
  int *piVar4;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_3 + iVar3 + 0x81)) {
    case 1:
      FUN_80089710(7,1,0);
      FUN_800895e0(7,0x96,200,0xf0,0,0);
      FUN_800894a8((double)FLOAT_803e7460,(double)FLOAT_803e7464,(double)FLOAT_803e7468,7);
      FUN_80008cbc(param_1,param_1,0x21f,0);
      break;
    case 2:
      FUN_80089710(7,1,0);
      FUN_800895e0(7,(int)FLOAT_803e7470,(int)FLOAT_803e7474,(int)FLOAT_803e7478,0,0);
      FUN_800894a8((double)FLOAT_803e7464,(double)FLOAT_803e747c,(double)FLOAT_803e7464,7);
      FUN_80008cbc(param_1,param_1,0x21d,0);
      break;
    case 3:
      FUN_80239858(param_1);
      if (*piVar4 != 0) {
        FUN_80233b0c(*piVar4,1);
      }
      break;
    case 4:
      FUN_80239858(param_1);
      if (*piVar4 != 0) {
        FUN_80233b0c(*piVar4,0);
      }
      break;
    case 5:
      FUN_80089710(7,1,0);
      FUN_800895e0(7,0x96,200,0xf0,0,0);
      FUN_800894a8((double)FLOAT_803e7480,(double)FLOAT_803e747c,(double)FLOAT_803e7464,7);
      FUN_80008cbc(param_1,param_1,0x21e,0);
      break;
    case 6:
      FUN_80042f78(0x29);
      break;
    case 7:
      FUN_8004350c(0,0,1);
      FUN_8004350c(0,1,1);
      uVar1 = FUN_800481b0(0xb);
      FUN_800437bc(uVar1,0x20000000);
      break;
    case 8:
      piVar4[3] = (int)FLOAT_803e746c;
      break;
    case 9:
      FUN_8004350c(0,0,1);
      FUN_80014948(4);
      FUN_800552e8(0x12,0);
      FUN_80134bc4();
      break;
    case 10:
      FUN_80089710(7,1,0);
      FUN_800895e0(7,0x96,200,0xf0,0,0);
      FUN_800894a8((double)FLOAT_803e7484,(double)FLOAT_803e747c,(double)FLOAT_803e7464,7);
      FUN_80008cbc(param_1,param_1,0x21f,0);
      break;
    case 0xb:
      FUN_80089710(7,1,0);
      FUN_800895e0(7,(int)FLOAT_803e7470,(int)FLOAT_803e7474,(int)FLOAT_803e7478,0,0);
      FUN_800894a8((double)FLOAT_803e7484,(double)FLOAT_803e747c,(double)FLOAT_803e7464,7);
      FUN_80008cbc(param_1,param_1,0x21d,0);
    }
  }
  if (FLOAT_803e7488 < (float)piVar4[3]) {
    FUN_80016870(0x476);
    piVar4[3] = (int)((float)piVar4[3] - FLOAT_803db414);
    if ((float)piVar4[3] < FLOAT_803e7488) {
      piVar4[3] = (int)FLOAT_803e7488;
    }
  }
  psVar2 = (short *)piVar4[1];
  if (psVar2 != (short *)0x0) {
    *psVar2 = *psVar2 + (short)(int)(FLOAT_803e748c * FLOAT_803db414);
  }
  psVar2 = (short *)piVar4[2];
  if (psVar2 != (short *)0x0) {
    *psVar2 = *psVar2 - (short)(int)(FLOAT_803e748c * FLOAT_803db414);
  }
  return 0;
}

