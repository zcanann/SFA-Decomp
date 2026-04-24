// Function: FUN_800233e8
// Entry: 800233e8
// Size: 260 bytes

void FUN_800233e8(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  uint *puVar5;
  
  DAT_803dcb34 = FUN_80246c68();
  iVar2 = 0;
  puVar3 = &DAT_803406a0;
  for (uVar1 = (uint)DAT_803dcb42; uVar1 != 0; uVar1 = uVar1 - 1) {
    if (((uint)puVar3[2] < param_1) && (param_1 < (uint)(puVar3[2] + puVar3[3]))) goto LAB_80023450;
    puVar3 = puVar3 + 5;
    iVar2 = iVar2 + 1;
  }
  iVar2 = -1;
LAB_80023450:
  if (iVar2 != -1) {
    iVar4 = 0;
    do {
      puVar5 = (uint *)((&DAT_803406a8)[iVar2 * 5] + iVar4 * 0x1c);
      if (*puVar5 == param_1) {
        if ((*(short *)(puVar5 + 2) != 1) && (*(short *)(puVar5 + 2) != 4)) {
          FUN_8007d6dc(s__5______mm_Error__________Can_t_f_802caa2c,param_1);
          return;
        }
        FUN_80023134();
        return;
      }
      iVar4 = (int)*(short *)(puVar5 + 3);
    } while (iVar4 != -1);
  }
  FUN_8007d6dc(s__6______mm_Error__________No_mat_802caa6c,param_1);
  return;
}

