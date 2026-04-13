// Function: FUN_8017a624
// Entry: 8017a624
// Size: 428 bytes

/* WARNING: Removing unreachable block (ram,0x8017a65c) */

void FUN_8017a624(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar3 + 0x14);
  if (bVar1 == 2) {
    *(ushort *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) + (ushort)DAT_803dc070;
    if (*(uint *)(iVar3 + 8) < (uint)(int)*(short *)(iVar3 + 0x10)) {
      *(undefined *)(iVar3 + 0x14) = 3;
    }
    dVar4 = (double)FUN_802945e0();
    *(short *)(iVar3 + 0x12) = (short)(int)((double)FLOAT_803e4378 * dVar4) + 0xdc;
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      iVar2 = FUN_8002bac4();
      dVar4 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (dVar4 < (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0xc)) -
                                 DOUBLE_803e4388)) {
        if ((int)*(short *)(iVar3 + 0xe) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar3 + 0xe),1);
        }
        *(undefined *)(iVar3 + 0x14) = 1;
      }
    }
    else {
      *(ushort *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + (ushort)DAT_803dc070 * 4;
      if (0xdc < *(short *)(iVar3 + 0x12)) {
        *(undefined2 *)(iVar3 + 0x12) = 0xdc;
        *(undefined *)(iVar3 + 0x14) = 2;
      }
    }
  }
  else if (((bVar1 != 4) && (bVar1 < 4)) &&
          (*(ushort *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + (ushort)DAT_803dc070 * -4,
          *(short *)(iVar3 + 0x12) < 0)) {
    *(undefined2 *)(iVar3 + 0x12) = 0;
    *(undefined *)(iVar3 + 0x14) = 4;
  }
  return;
}

