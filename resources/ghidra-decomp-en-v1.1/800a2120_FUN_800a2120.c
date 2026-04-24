// Function: FUN_800a2120
// Entry: 800a2120
// Size: 372 bytes

void FUN_800a2120(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  
  iVar3 = 0;
  piVar4 = &DAT_8039ce58;
  do {
    iVar1 = *piVar4;
    if ((iVar1 != 0) && (*(int *)(iVar1 + 4) == param_9)) {
      if ((*(uint *)(iVar1 + 0xa4) & 0x10000) == 0) {
        *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(*(int *)(iVar1 + 4) + 0x18);
        *(undefined4 *)(*piVar4 + 0x1c) = *(undefined4 *)(*(int *)(*piVar4 + 4) + 0x1c);
        *(undefined4 *)(*piVar4 + 0x20) = *(undefined4 *)(*(int *)(*piVar4 + 4) + 0x20);
        *(undefined4 *)(*piVar4 + 0x14) = *(undefined4 *)(*(int *)(*piVar4 + 4) + 8);
        *(undefined2 *)(*piVar4 + 0x10) = *(undefined2 *)(*(int *)(*piVar4 + 4) + 4);
        *(undefined2 *)(*piVar4 + 0xe) = *(undefined2 *)(*(int *)(*piVar4 + 4) + 2);
        *(undefined2 *)(*piVar4 + 0xc) = **(undefined2 **)(*piVar4 + 4);
        iVar1 = *piVar4;
        if ((*(uint *)(iVar1 + 0xa4) & 2) != 0) {
          *(float *)(iVar1 + 0x6c) =
               *(float *)(iVar1 + 0x6c) + *(float *)(*(int *)(iVar1 + 4) + 0x24);
          iVar1 = *piVar4;
          *(float *)(iVar1 + 0x70) =
               *(float *)(iVar1 + 0x70) + *(float *)(*(int *)(iVar1 + 4) + 0x28);
          iVar1 = *piVar4;
          param_1 = (double)*(float *)(iVar1 + 0x74);
          *(float *)(iVar1 + 0x74) =
               (float)(param_1 + (double)*(float *)(*(int *)(iVar1 + 4) + 0x2c));
        }
        uVar2 = *(uint *)(*piVar4 + 0xa4);
        if ((uVar2 & 0x200000) == 0) {
          *(uint *)(*piVar4 + 0xa4) = uVar2 | 0x200000;
        }
        *(undefined4 *)(*piVar4 + 4) = 0;
      }
      else {
        param_1 = (double)FUN_800a12cc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                                       param_8,*(short *)(iVar1 + 0x10c),0);
      }
    }
    piVar4 = piVar4 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x32);
  return;
}

