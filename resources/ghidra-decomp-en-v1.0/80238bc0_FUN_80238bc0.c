// Function: FUN_80238bc0
// Entry: 80238bc0
// Size: 424 bytes

void FUN_80238bc0(int param_1)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  piVar3 = *(int **)(param_1 + 0xb8);
  if ((((*piVar3 != 0) && (iVar1 = FUN_8003687c(param_1,0,0,local_28), iVar1 != 0)) &&
      (*(char *)(piVar3 + 2) != '\0')) && (iVar1 = FUN_8007fe74(piVar3[1]), iVar1 != -1)) {
    *piVar3 = *piVar3 - local_28[0];
    if (*(char *)(iVar4 + 0x19) == '\x02') {
      FUN_8002ac30(param_1,0x1e,200,0,0,1);
      FUN_8000bb18(param_1,0x496);
    }
    if (*piVar3 < 1) {
      iVar1 = *(int *)(param_1 + 0x4c);
      *piVar3 = 0;
      FUN_800200e8((int)*(short *)(iVar1 + 0x1e),1);
      if (*(char *)(iVar1 + 0x19) != '\0') {
        if (*(char *)(iVar1 + 0x19) == '\x02') {
          uVar2 = 0x50;
        }
        else {
          uVar2 = (uint)*(short *)(iVar1 + 0x1c);
        }
        iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
        if (((iVar1 != 0x470ea) && (iVar1 != 0x480f5)) && ((iVar1 != 0x46710 && (iVar1 != 0x49b43)))
           ) {
          uStack28 = uVar2 ^ 0x80000000;
          local_20 = 0x43300000;
          FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7438),
                       param_1,1,1,1,1,0,1,0);
        }
        if (*(char *)(iVar4 + 0x19) == '\x02') {
          FUN_8000bb18(param_1,0x497);
        }
      }
    }
    else {
      FUN_8000bb18(param_1,0x18);
    }
  }
  return;
}

