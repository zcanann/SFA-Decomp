// Function: FUN_8021b42c
// Entry: 8021b42c
// Size: 592 bytes

/* WARNING: Removing unreachable block (ram,0x8021b65c) */
/* WARNING: Removing unreachable block (ram,0x8021b654) */
/* WARNING: Removing unreachable block (ram,0x8021b444) */
/* WARNING: Removing unreachable block (ram,0x8021b43c) */

void FUN_8021b42c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float afStack_68 [3];
  float local_5c;
  float local_58;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar9 = FUN_80286824();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  piVar7 = *(int **)(iVar1 + 0xb8);
  iVar6 = *(int *)(iVar1 + 0x4c);
  if (*(char *)((int)piVar7 + 0x1a) < '\0') {
    piVar7[2] = *(int *)(iVar1 + 0xc);
    piVar7[3] = *(int *)(iVar1 + 0x10);
    piVar7[4] = *(int *)(iVar1 + 0x14);
    iVar8 = (int)*(char *)(*(int *)(*(int *)(iVar4 + 0x50) + 0x2c) + param_3 * 0x18 +
                           (int)*(char *)(iVar1 + 0xad) + 0x12);
    piVar3 = *(int **)(*(int *)(iVar4 + 0x7c) + *(char *)(iVar4 + 0xad) * 4);
    iVar5 = *piVar3;
    *(undefined2 *)(iVar1 + 4) = 0;
    *(undefined2 *)(iVar1 + 2) = 0;
    FUN_80028448(piVar3,iVar8,&local_5c);
    FUN_80028448(piVar3,(int)*(char *)(*(int *)(iVar5 + 0x3c) + iVar8 * 0x1c),afStack_68);
    FUN_80247eb8(afStack_68,&local_5c,&local_5c);
    if (*(short *)(iVar6 + 0x1c) == 0) {
      local_58 = FLOAT_803e76c0;
      FUN_80247f54(&local_5c);
      iVar6 = FUN_80021884();
      *(short *)(iVar1 + 4) = (short)DAT_803dcf58 + (short)iVar6;
      iVar6 = FUN_80021884();
      *(short *)(iVar1 + 2) = (short)DAT_803de9f0 + (short)iVar6;
      uVar2 = FUN_80038498(iVar4,param_3);
      FUN_800413cc(uVar2);
    }
    else {
      iVar5 = FUN_80021884();
      *(short *)(iVar1 + 4) = (short)((int)*(short *)(iVar6 + 0x1c) << 0xe) + (short)iVar5;
      iVar6 = FUN_80021884();
      *(short *)(iVar1 + 2) = (short)iVar6;
    }
    FUN_80038524(iVar4,param_3,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                 (float *)(iVar1 + 0x14),0);
    FUN_8003b9ec(iVar1);
    piVar3 = piVar7;
    for (iVar4 = 0; iVar4 < piVar7[5]; iVar4 = iVar4 + 1) {
      iVar6 = *piVar3;
      if (iVar6 != 0) {
        FUN_80038524(iVar1,(uint)*(byte *)((int)piVar7 + iVar4 + 0x1b),(float *)(iVar6 + 0xc),
                     (undefined4 *)(iVar6 + 0x10),(float *)(iVar6 + 0x14),0);
      }
      piVar3 = piVar3 + 1;
    }
  }
  FUN_80286870();
  return;
}

