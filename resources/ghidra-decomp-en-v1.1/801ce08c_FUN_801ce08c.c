// Function: FUN_801ce08c
// Entry: 801ce08c
// Size: 276 bytes

void FUN_801ce08c(int param_1)

{
  undefined4 uVar1;
  uint uVar2;
  short *psVar3;
  float local_18 [4];
  
  psVar3 = *(short **)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e5e94;
  if (*(char *)((int)psVar3 + 7) == '\0') {
    if (*(char *)(psVar3 + 3) == '\0') {
      if (psVar3[2] == 0) {
        uVar2 = FUN_80020078((int)*psVar3);
        if (uVar2 != 0) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar3[1],param_1,0xffffffff);
          *(undefined *)(psVar3 + 3) = 1;
        }
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x54))();
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar3[1],param_1,1);
        *(undefined *)(psVar3 + 3) = 1;
      }
    }
  }
  else {
    uVar1 = FUN_80036f50(4,param_1,local_18);
    *(undefined4 *)(psVar3 + 4) = uVar1;
    if (*(int *)(psVar3 + 4) == 0) {
      *(char *)((int)psVar3 + 7) = *(char *)((int)psVar3 + 7) + -1;
    }
    else {
      *(undefined *)((int)psVar3 + 7) = 0;
    }
  }
  return;
}

