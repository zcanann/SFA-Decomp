// Function: FUN_801bb3e8
// Entry: 801bb3e8
// Size: 432 bytes

void FUN_801bb3e8(int param_1,char param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(*(int *)(param_1 + 0xb8) + 0x40c);
  if (*piVar2 == 0) {
    iVar1 = FUN_8001f4c8(0,1);
    *piVar2 = iVar1;
    if (*piVar2 != 0) {
      FUN_8001db2c(*piVar2,2);
      FUN_8001dd88((double)(float)piVar2[0x16],(double)(float)piVar2[0x17],
                   (double)(float)piVar2[0x18],*piVar2);
      if (param_2 == '\0') {
        FUN_8001daf0(*piVar2,0xff,0,0,0xff);
        FUN_8001da18(*piVar2,0xff,0,0,0xff);
        FUN_8001d730((double)FLOAT_803e4c2c,*piVar2,0,0xff,0,0,0xc0);
      }
      else {
        FUN_8001daf0(*piVar2,0,0xff,0,0xff);
        FUN_8001da18(*piVar2,0,0xff,0,0xff);
        FUN_8001d730((double)FLOAT_803e4c28,*piVar2,0,0,0xff,0,0xc0);
      }
      FUN_8001dc38((double)FLOAT_803e4c2c,(double)FLOAT_803e4c30,*piVar2);
      FUN_8001db54(*piVar2,1);
      FUN_8001db6c((double)FLOAT_803e4bd8,*piVar2,1);
      FUN_8001dab8(*piVar2,0x40,0,0,0x40);
      FUN_8001d9e0(*piVar2,0x40,0,0,0x40);
      FUN_8001d620(*piVar2,2,0x28);
      FUN_8001dd40(*piVar2,1);
      FUN_8001d714((double)FLOAT_803e4bbc,*piVar2);
    }
  }
  return;
}

