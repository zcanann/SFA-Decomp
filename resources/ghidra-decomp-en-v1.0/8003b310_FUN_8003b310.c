// Function: FUN_8003b310
// Entry: 8003b310
// Size: 496 bytes

/* WARNING: Removing unreachable block (ram,0x8003b408) */

void FUN_8003b310(int param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  piVar2 = (int *)0x0;
  iVar5 = *(int *)(param_1 + 0x50);
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar1 = (uint)*(byte *)(iVar5 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (*pcVar3 == '\x05') {
        piVar2 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  piVar4 = (int *)0x0;
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar1 = (uint)*(byte *)(iVar5 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (*pcVar3 == '\x04') {
        piVar4 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  if ((piVar2 != (int *)0x0) && (piVar4 != (int *)0x0)) {
    uVar1 = (int)*(char *)(param_2 + 0x1e) & 0xf;
    if (uVar1 == 1) {
      if (((int)*(char *)(param_2 + 0x1e) & 0x80U) == 0) {
        iVar5 = *piVar4 + (uint)DAT_803db410 * 0x60;
        if (0x200 < iVar5) {
          if (iVar5 + -0x200 < 0) {
            iVar5 = 0;
            *(undefined *)(param_2 + 0x1e) = 0;
          }
          else {
            iVar5 = 0x2ff;
            *(undefined *)(param_2 + 0x1e) = 0x81;
          }
          *(undefined *)(param_2 + 0x1f) = 0x28;
        }
      }
      else {
        iVar5 = *piVar4 + (uint)DAT_803db410 * -0x60;
        if (iVar5 < 0) {
          iVar5 = 0;
          *(undefined *)(param_2 + 0x1e) = 0;
          *(undefined *)(param_2 + 0x1f) = 0;
        }
      }
      *piVar2 = iVar5;
      *piVar4 = iVar5;
    }
    else if (uVar1 == 0) {
      if (*(char *)(param_2 + 0x1f) < '\x01') {
        iVar5 = FUN_800221a0(0,1000);
        if (0x3de < iVar5) {
          *(undefined *)(param_2 + 0x1e) = 1;
          *(undefined *)(param_2 + 0x1f) = 0;
        }
      }
      else {
        *(byte *)(param_2 + 0x1f) = *(char *)(param_2 + 0x1f) - DAT_803db410;
      }
    }
    FUN_80039654((double)FLOAT_803de9a4,param_1,param_2);
  }
  return;
}

