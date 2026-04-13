// Function: FUN_801d01b4
// Entry: 801d01b4
// Size: 352 bytes

void FUN_801d01b4(undefined2 *param_1)

{
  short *psVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  int *piVar5;
  float local_18;
  int local_14 [3];
  
  local_18 = FLOAT_803e5f08;
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    puVar2 = FUN_80037048(0x3d,local_14);
    iVar4 = 0;
    puVar3 = puVar2;
    if (0 < local_14[0]) {
      do {
        if ((param_1 != (undefined2 *)*puVar3) &&
           (*(char *)(*(int *)(param_1 + 0x26) + 0x1b) ==
            *(char *)(*(int *)((undefined2 *)*puVar3 + 0x26) + 0x1b))) {
          *piVar5 = puVar2[iVar4];
          return;
        }
        puVar3 = puVar3 + 1;
        iVar4 = iVar4 + 1;
        local_14[0] = local_14[0] + -1;
      } while (local_14[0] != 0);
    }
  }
  else {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*piVar5 + 0xc);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*piVar5 + 0x10);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*piVar5 + 0x14);
    *param_1 = *(undefined2 *)*piVar5;
    FUN_80036e58(0x3c,param_1,&local_18);
    if (*(byte *)(*piVar5 + 0x36) < 0xc0) {
      FUN_80035ff8((int)param_1);
      psVar1 = (short *)FUN_8002bac4();
      FUN_80297480(psVar1,(int)param_1);
    }
    else {
      FUN_80036018((int)param_1);
    }
    if ((*(byte *)(*piVar5 + 0x36) < 0xc0) || (local_18 < FLOAT_803e5f0c)) {
      param_1[0x58] = param_1[0x58] | 0x100;
    }
    else {
      param_1[0x58] = param_1[0x58] & 0xfeff;
    }
  }
  return;
}

