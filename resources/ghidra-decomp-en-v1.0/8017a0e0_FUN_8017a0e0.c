// Function: FUN_8017a0e0
// Entry: 8017a0e0
// Size: 428 bytes

/* WARNING: Removing unreachable block (ram,0x8017a118) */

void FUN_8017a0e0(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar3 + 0x14);
  if (bVar1 == 2) {
    *(ushort *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) + (ushort)DAT_803db410;
    if (*(uint *)(iVar3 + 8) < (uint)(int)*(short *)(iVar3 + 0x10)) {
      *(undefined *)(iVar3 + 0x14) = 3;
    }
    dVar4 = (double)FUN_80293e80((double)((FLOAT_803e36e4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   *(short *)(iVar3 + 0x10) * 0x500
                                                                   ^ 0x80000000) - DOUBLE_803e36f8))
                                         / FLOAT_803e36e8));
    *(short *)(iVar3 + 0x12) = (short)(int)((double)FLOAT_803e36e0 * dVar4) + 0xdc;
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      iVar2 = FUN_8002b9ec();
      dVar4 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
      if (dVar4 < (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0xc)) -
                                 DOUBLE_803e36f0)) {
        if (*(short *)(iVar3 + 0xe) != -1) {
          FUN_800200e8((int)*(short *)(iVar3 + 0xe),1);
        }
        *(undefined *)(iVar3 + 0x14) = 1;
      }
    }
    else {
      *(ushort *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + (ushort)DAT_803db410 * 4;
      if (0xdc < *(short *)(iVar3 + 0x12)) {
        *(undefined2 *)(iVar3 + 0x12) = 0xdc;
        *(undefined *)(iVar3 + 0x14) = 2;
      }
    }
  }
  else if (((bVar1 != 4) && (bVar1 < 4)) &&
          (*(ushort *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + (ushort)DAT_803db410 * -4,
          *(short *)(iVar3 + 0x12) < 0)) {
    *(undefined2 *)(iVar3 + 0x12) = 0;
    *(undefined *)(iVar3 + 0x14) = 4;
  }
  return;
}

