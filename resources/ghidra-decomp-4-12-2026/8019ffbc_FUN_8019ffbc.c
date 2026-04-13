// Function: FUN_8019ffbc
// Entry: 8019ffbc
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x801a012c) */
/* WARNING: Removing unreachable block (ram,0x8019ffcc) */

void FUN_8019ffbc(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar1 = FUN_80286840();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  iVar4 = *(int *)(iVar1 + 0x4c);
  if ((char)*(byte *)(iVar5 + 0x39) < '\0') {
    *(byte *)(iVar5 + 0x39) = *(byte *)(iVar5 + 0x39) & 0x7f;
  }
  uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e));
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0x44);
    dVar6 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
    if (*(char *)(iVar5 + 0x38) == '\x01') {
      FUN_80095980((double)FLOAT_803e4f00,(float *)(iVar1 + 0xc));
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
      *(undefined *)(iVar5 + 0x38) = 2;
    }
    if (((uVar3 == 0) &&
        (((*(char *)(iVar5 + 0x37) == '\x04' ||
          (dVar6 < (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                                  DOUBLE_803e4f10))) ||
         (iVar4 = FUN_80095980((double)FLOAT_803e4f00,(float *)(iVar1 + 0xc)), iVar4 != 0)))) &&
       (iVar2 = FUN_80297300(iVar2), iVar2 != 0x40)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,0xffffffff);
    }
  }
  else {
    *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
    FUN_80035ff8(iVar1);
    FUN_8002cf80(iVar1);
  }
  FUN_8028688c();
  return;
}

