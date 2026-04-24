// Function: FUN_800626c8
// Entry: 800626c8
// Size: 320 bytes

/* WARNING: Removing unreachable block (ram,0x800627f0) */

ushort FUN_800626c8(int param_1,int param_2)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_1 + 100);
  if ((*(uint *)(iVar3 + 0x30) & 0x1000) == 0) {
    if (((*(uint *)(iVar3 + 0x30) & 0x10000) == 0) &&
       (*(short *)(iVar3 + 0x36) = *(short *)(iVar3 + 0x36) + (short)(param_2 << 9),
       0x3fff < *(short *)(iVar3 + 0x36))) {
      *(undefined2 *)(iVar3 + 0x36) = 0x4000;
    }
  }
  else {
    *(short *)(iVar3 + 0x36) = *(short *)(iVar3 + 0x36) - (short)(param_2 << 9);
    if (*(short *)(iVar3 + 0x36) < 1) {
      *(undefined2 *)(iVar3 + 0x36) = 0;
    }
    if (*(short *)(iVar3 + 0x36) == 0) {
      *(undefined4 *)(iVar3 + 0xc) = 0;
      uVar1 = 0;
      goto LAB_800627f0;
    }
  }
  dVar5 = (double)(FLOAT_803db654 *
                  FLOAT_803dec90 *
                  (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x36) ^ 0x80000000) -
                         DOUBLE_803dec60));
  uVar2 = FUN_80062378(param_1,*(undefined *)(iVar3 + 0x3a));
  uVar1 = (ushort)(int)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                       DOUBLE_803dec60) * dVar5);
  if ((short)uVar1 < 0x100) {
    if ((short)uVar1 < 0) {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0xff;
  }
  uVar1 = uVar1 & 0xff;
LAB_800627f0:
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return uVar1;
}

