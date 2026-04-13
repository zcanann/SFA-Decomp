// Function: FUN_80239f50
// Entry: 80239f50
// Size: 220 bytes

void FUN_80239f50(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int local_18;
  int local_14 [3];
  
  piVar4 = *(int **)(param_1 + 0xb8);
  *piVar4 = 0;
  piVar4[1] = 0;
  piVar4[2] = 0;
  iVar1 = FUN_8002e1f4(local_14,&local_18);
  for (; local_14[0] < local_18; local_14[0] = local_14[0] + 1) {
    iVar3 = *(int *)(iVar1 + local_14[0] * 4);
    if ((iVar3 != param_1) && (*(int *)(iVar3 + 0x4c) != 0)) {
      iVar2 = *(int *)(*(int *)(iVar3 + 0x4c) + 0x14);
      if (iVar2 == 0x4a946) {
        piVar4[1] = iVar3;
      }
      else if (iVar2 < 0x4a946) {
        if (iVar2 == 0x477e3) {
          *piVar4 = iVar3;
        }
      }
      else if (iVar2 < 0x4a948) {
        piVar4[2] = iVar3;
      }
    }
  }
  return;
}

