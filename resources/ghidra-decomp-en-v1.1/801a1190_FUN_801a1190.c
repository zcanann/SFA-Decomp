// Function: FUN_801a1190
// Entry: 801a1190
// Size: 496 bytes

/* WARNING: Removing unreachable block (ram,0x801a1360) */
/* WARNING: Removing unreachable block (ram,0x801a1358) */
/* WARNING: Removing unreachable block (ram,0x801a1350) */
/* WARNING: Removing unreachable block (ram,0x801a11b0) */
/* WARNING: Removing unreachable block (ram,0x801a11a8) */
/* WARNING: Removing unreachable block (ram,0x801a11a0) */

void FUN_801a1190(void)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  ulonglong uVar11;
  int local_68;
  ushort local_64 [4];
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar11 = FUN_8028683c();
  uVar1 = (uint)(uVar11 >> 0x20);
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  iVar2 = *(int *)(iVar2 + 0xb8);
  *(float *)(iVar5 + 0x20) = FLOAT_803e4f58;
  if ((uVar11 & 0xff) == 0) {
    *(float *)(iVar5 + 0x24) = FLOAT_803e4f6c;
    *(float *)(iVar5 + 0x28) = FLOAT_803e4f70;
  }
  else {
    *(float *)(iVar5 + 0x24) = FLOAT_803e4f60 * *(float *)(iVar2 + 0x298) + FLOAT_803e4f5c;
    *(float *)(iVar5 + 0x28) = FLOAT_803e4f68 * *(float *)(iVar2 + 0x298) + FLOAT_803e4f64;
  }
  local_58 = FLOAT_803e4f58;
  local_54 = FLOAT_803e4f58;
  local_50 = FLOAT_803e4f58;
  local_5c = FLOAT_803e4f74;
  local_64[2] = 0;
  local_64[1] = 0;
  local_64[0] = *(ushort *)(iVar5 + 0x50);
  FUN_80021b8c(local_64,(float *)(iVar5 + 0x20));
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 1;
  FUN_8000bb38(uVar1,0xd3);
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 2;
  if ((*(byte *)(iVar5 + 0x48) >> 6 & 1) != 0) {
    iVar5 = *(int *)(uVar1 + 0x4c);
    iVar2 = 0;
    if (*(short *)(iVar5 + 0x1a) == 0) {
      iVar2 = FUN_80036f50(0x3a,uVar1,(float *)0x0);
    }
    else {
      piVar3 = FUN_80037048(0x3a,&local_68);
      piVar6 = piVar3;
      for (iVar7 = 0; iVar7 < local_68; iVar7 = iVar7 + 1) {
        iVar4 = FUN_80221cc0(*piVar6);
        if (*(short *)(iVar5 + 0x1a) == iVar4) {
          iVar2 = piVar3[iVar7];
          break;
        }
        piVar6 = piVar6 + 1;
      }
    }
    if (iVar2 != 0) {
      dVar10 = (double)*(float *)(uVar1 + 0xc);
      dVar9 = (double)*(float *)(uVar1 + 0x10);
      dVar8 = (double)*(float *)(uVar1 + 0x14);
      *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_800e85f4(uVar1);
      *(float *)(uVar1 + 0xc) = (float)dVar10;
      *(float *)(uVar1 + 0x10) = (float)dVar9;
      *(float *)(uVar1 + 0x14) = (float)dVar8;
    }
  }
  FUN_80286888();
  return;
}

