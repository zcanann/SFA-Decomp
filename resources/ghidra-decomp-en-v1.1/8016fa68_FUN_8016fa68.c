// Function: FUN_8016fa68
// Entry: 8016fa68
// Size: 568 bytes

/* WARNING: Removing unreachable block (ram,0x8016fc80) */
/* WARNING: Removing unreachable block (ram,0x8016fa78) */

void FUN_8016fa68(void)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  char in_r8;
  uint uVar6;
  byte bVar7;
  int *piVar8;
  double dVar9;
  
  iVar3 = FUN_8028682c();
  piVar8 = *(int **)(iVar3 + 0xb8);
  if (((in_r8 != '\0') && ((*(byte *)(piVar8 + 0x1c) & 8) == 0)) &&
     ((float)piVar8[0xf] == FLOAT_803e3fc8)) {
    *(undefined *)(iVar3 + 0xad) = 1;
    iVar4 = FUN_8002b660(iVar3);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = (&DAT_803dc9c0)[*(byte *)((int)piVar8 + 0x71)];
    uVar1 = *(undefined2 *)(iVar3 + 4);
    uVar2 = *(undefined2 *)(iVar3 + 2);
    dVar9 = (double)*(float *)(iVar3 + 8);
    *(float *)(iVar3 + 8) = FLOAT_803e3fe8;
    for (bVar7 = 0; bVar7 < 5; bVar7 = bVar7 + 1) {
      *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x48) =
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x48) +
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x52);
      *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c) =
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c) +
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x66);
      *(undefined2 *)(iVar3 + 4) = *(undefined2 *)((int)piVar8 + (uint)bVar7 * 2 + 0x48);
      *(undefined2 *)(iVar3 + 2) = *(undefined2 *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      FUN_8003b9ec(iVar3);
    }
    *(undefined2 *)(iVar3 + 4) = uVar1;
    *(undefined2 *)(iVar3 + 2) = uVar2;
    *(float *)(iVar3 + 8) = (float)dVar9;
    *(undefined *)(iVar3 + 0xad) = 0;
    iVar4 = FUN_8002b660(iVar3);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = (&DAT_803dc9c0)[*(byte *)((int)piVar8 + 0x71)];
    FUN_8003b9ec(iVar3);
    iVar3 = *piVar8;
    if (iVar3 != 0) {
      if ((*(char *)(iVar3 + 0x2f8) != '\0') && (*(char *)(iVar3 + 0x4c) != '\0')) {
        uVar6 = (uint)*(byte *)(iVar3 + 0x2f9) + (int)*(char *)(iVar3 + 0x2fa) & 0xffff;
        if (0xc < uVar6) {
          uVar5 = FUN_80022264(0xfffffff4,0xc);
          uVar6 = uVar6 + uVar5 & 0xffff;
          if (0xff < uVar6) {
            uVar6 = 0xff;
            *(undefined *)(*piVar8 + 0x2fa) = 0;
          }
        }
        *(char *)(*piVar8 + 0x2f9) = (char)uVar6;
      }
      iVar3 = *piVar8;
      if ((*(char *)(iVar3 + 0x2f8) != '\0') && (*(char *)(iVar3 + 0x4c) != '\0')) {
        FUN_80060630(iVar3);
      }
    }
  }
  FUN_80286878();
  return;
}

