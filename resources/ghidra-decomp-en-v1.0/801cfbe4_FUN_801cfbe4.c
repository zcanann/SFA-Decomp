// Function: FUN_801cfbe4
// Entry: 801cfbe4
// Size: 352 bytes

void FUN_801cfbe4(undefined2 *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  int *piVar5;
  float local_18;
  int local_14 [3];
  
  local_18 = FLOAT_803e5270;
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    puVar2 = (undefined4 *)FUN_80036f50(0x3d,local_14);
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
    FUN_80036d60(0x3c,param_1,&local_18);
    if (*(byte *)(*piVar5 + 0x36) < 0xc0) {
      FUN_80035f00(param_1);
      uVar1 = FUN_8002b9ec();
      FUN_80296d20(uVar1,param_1);
    }
    else {
      FUN_80035f20(param_1);
    }
    if ((*(byte *)(*piVar5 + 0x36) < 0xc0) || (local_18 < FLOAT_803e5274)) {
      param_1[0x58] = param_1[0x58] | 0x100;
    }
    else {
      param_1[0x58] = param_1[0x58] & 0xfeff;
    }
  }
  return;
}

