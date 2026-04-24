// Function: FUN_80062844
// Entry: 80062844
// Size: 320 bytes

/* WARNING: Removing unreachable block (ram,0x8006296c) */
/* WARNING: Removing unreachable block (ram,0x80062854) */

ushort FUN_80062844(int param_1,int param_2)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
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
      return 0;
    }
  }
  dVar4 = (double)(FLOAT_803dc2b4 *
                  FLOAT_803df910 *
                  (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x36) ^ 0x80000000) -
                         DOUBLE_803df8e0));
  uVar2 = FUN_800624f4(param_1,(uint)*(byte *)(iVar3 + 0x3a));
  uVar1 = (ushort)(int)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                       DOUBLE_803df8e0) * dVar4);
  if ((short)uVar1 < 0x100) {
    if ((short)uVar1 < 0) {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0xff;
  }
  return uVar1 & 0xff;
}

