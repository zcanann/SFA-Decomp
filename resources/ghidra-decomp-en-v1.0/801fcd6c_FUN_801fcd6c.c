// Function: FUN_801fcd6c
// Entry: 801fcd6c
// Size: 720 bytes

void FUN_801fcd6c(int param_1)

{
  char cVar1;
  int iVar2;
  short sVar3;
  int iVar4;
  short *psVar5;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x4c) + 0x19);
  if (cVar1 == '\x02') {
    iVar4 = *(int *)(param_1 + 0xb8);
    DAT_803ddcc4 = DAT_803ddcc4 - (short)(int)FLOAT_803db414;
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 2));
    if (((iVar2 == 0) && (DAT_803ddcc4 < 0xc9)) &&
       ((*(char *)(iVar4 + 0xb) == DAT_803ddcc6 && (iVar2 = FUN_800221a0(0,2), iVar2 == 0)))) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x391,0,4,0xffffffff,0);
    }
  }
  else if (*(short *)(param_1 + 0x46) == 0x3c5) {
    iVar2 = *(int *)(param_1 + 0xb8);
    *(short *)(iVar2 + 6) = *(short *)(iVar2 + 6) - (short)(int)FLOAT_803db414;
    *(float *)(param_1 + 0xc) =
         *(float *)(param_1 + 0x24) * FLOAT_803db414 + *(float *)(param_1 + 0xc);
    *(float *)(param_1 + 0x10) =
         *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
    *(float *)(param_1 + 0x14) =
         *(float *)(param_1 + 0x2c) * FLOAT_803db414 + *(float *)(param_1 + 0x14);
    if (*(short *)(iVar2 + 6) < 1) {
      FUN_8002cbc4();
    }
  }
  else if (cVar1 == '\0') {
    iVar4 = *(int *)(param_1 + 0xb8);
    DAT_803ddcc4 = DAT_803ddcc4 - (short)(int)FLOAT_803db414;
    iVar2 = FUN_8001ffb4(0x522);
    if ((((iVar2 == 0) && (DAT_803ddcc4 < 0xc9)) && (*(char *)(iVar4 + 0xb) == DAT_803ddcc6)) &&
       (iVar2 = FUN_800221a0(0,2), iVar2 == 0)) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x391,0,4,0xffffffff,0);
    }
  }
  else if (cVar1 == '\x01') {
    psVar5 = *(short **)(param_1 + 0xb8);
    iVar2 = FUN_8001ffb4((int)*psVar5);
    if (iVar2 != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x390,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x390,0,4,0xffffffff,0);
      iVar2 = FUN_800221a0(0,1);
      if (iVar2 != 0) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x391,0,4,0xffffffff,0);
      }
    }
    sVar3 = FUN_8003687c(param_1,0,0,0);
    if (sVar3 != 0) {
      iVar2 = FUN_8001ffb4((int)*psVar5);
      FUN_800200e8((int)*psVar5,1 - iVar2);
    }
  }
  return;
}

