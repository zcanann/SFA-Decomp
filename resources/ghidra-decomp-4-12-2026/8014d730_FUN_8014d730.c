// Function: FUN_8014d730
// Entry: 8014d730
// Size: 404 bytes

void FUN_8014d730(uint param_1)

{
  uint uVar1;
  int *piVar2;
  char in_r8;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b9ec(param_1);
    uVar1 = *(uint *)(iVar3 + 0x2e8);
    if ((uVar1 & 3) != 0) {
      if ((uVar1 & 1) != 0) {
        *(uint *)(iVar3 + 0x2e8) = uVar1 & 0xfffffffe;
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 2;
      }
      if (*(int *)(iVar3 + 0x368) == 0) {
        piVar2 = FUN_8001f58c(0,'\x01');
        *(int **)(iVar3 + 0x368) = piVar2;
      }
      FUN_8009a010((double)FLOAT_803e3200,(double)*(float *)(iVar3 + 0x30c),param_1,3,
                   *(int **)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 4) != 0) {
      if (*(int *)(iVar3 + 0x368) == 0) {
        piVar2 = FUN_8001f58c(0,'\x01');
        *(int **)(iVar3 + 0x368) = piVar2;
      }
      FUN_8009a010((double)FLOAT_803e3200,(double)*(float *)(iVar3 + 0x30c),param_1,4,
                   *(int **)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x40) != 0) {
      FUN_8000da78(param_1,0x9e);
      FUN_8009a010((double)FLOAT_803e3200,(double)*(float *)(iVar3 + 0x30c),param_1,5,(int *)0x0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x80) != 0) {
      FUN_8000da78(param_1,0x9e);
      FUN_8009a010((double)FLOAT_803e3290,(double)*(float *)(iVar3 + 0x30c),param_1,6,(int *)0x0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x100) != 0) {
      FUN_8009a010((double)FLOAT_803e3294,(double)*(float *)(iVar3 + 0x30c),param_1,7,(int *)0x0);
    }
  }
  return;
}

