// Function: FUN_8017a5e4
// Entry: 8017a5e4
// Size: 280 bytes

void FUN_8017a5e4(int param_1)

{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  char *pcVar4;
  undefined *puVar5;
  
  pcVar4 = *(char **)(param_1 + 0xb8);
  if (*pcVar4 == '\0') {
    iVar2 = FUN_8001ffb4((int)*(short *)(pcVar4 + 2));
    if (iVar2 != 0) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      puVar3 = (undefined4 *)FUN_800394ac(param_1,0,0);
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0x100;
      }
      *puVar5 = 1;
    }
  }
  else {
    iVar2 = FUN_8001ffb4((int)*(short *)(pcVar4 + 2));
    if (iVar2 == 0) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      puVar3 = (undefined4 *)FUN_800394ac(param_1,0,0);
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0;
      }
      *puVar5 = 0;
    }
  }
  fVar1 = FLOAT_803e3718;
  if (FLOAT_803e3718 < *(float *)(pcVar4 + 4)) {
    *(float *)(pcVar4 + 4) =
         *(float *)(pcVar4 + 4) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e3720);
    if (*(float *)(pcVar4 + 4) <= fVar1) {
      *(float *)(pcVar4 + 4) = fVar1;
      FUN_800200e8((int)*(short *)(pcVar4 + 2),0);
    }
  }
  return;
}

