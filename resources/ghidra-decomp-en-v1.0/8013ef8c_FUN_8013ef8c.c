// Function: FUN_8013ef8c
// Entry: 8013ef8c
// Size: 372 bytes

void FUN_8013ef8c(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  double dVar3;
  
  iVar1 = FUN_8002178c((double)(*(float *)(*(int *)(param_2 + 0x24) + 0x18) -
                               *(float *)(param_1 + 0x18)),
                       (double)(*(float *)(*(int *)(param_2 + 0x24) + 0x20) -
                               *(float *)(param_1 + 0x20)));
  if (*(char *)(param_2 + 10) == '\0') {
    uVar2 = FUN_800221a0(0,1);
    *(undefined4 *)(param_2 + 0x700) = uVar2;
    if (*(int *)(param_2 + 0x700) == 0) {
      *(undefined4 *)(param_2 + 0x700) = 0xffffffff;
    }
    *(int *)(param_2 + 0x704) = iVar1;
    *(undefined *)(param_2 + 10) = 1;
  }
  iVar1 = iVar1 - (*(uint *)(param_2 + 0x704) & 0xffff);
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  if (iVar1 < 0x2000) {
    *(int *)(param_2 + 0x704) = *(int *)(param_2 + 0x704) + *(int *)(param_2 + 0x700) * 0x800;
  }
  dVar3 = (double)FUN_80293464(*(uint *)(param_2 + 0x704) & 0xffff);
  *(float *)(param_2 + 0x708) =
       -(float)((double)FLOAT_803e24d4 * dVar3 - (double)*(float *)(*(int *)(param_2 + 0x24) + 0x18)
               );
  *(undefined4 *)(param_2 + 0x70c) = *(undefined4 *)(*(int *)(param_2 + 0x24) + 0x1c);
  dVar3 = (double)FUN_8029397c(*(uint *)(param_2 + 0x704) & 0xffff);
  *(float *)(param_2 + 0x710) =
       -(float)((double)FLOAT_803e24d4 * dVar3 - (double)*(float *)(*(int *)(param_2 + 0x24) + 0x20)
               );
  iVar1 = FUN_8013b368((double)FLOAT_803e2488,param_1,param_2);
  if (iVar1 == 0) {
    FUN_80148b78(s_error_tricky_should_never_stop_w_8031d8e0);
  }
  return;
}

