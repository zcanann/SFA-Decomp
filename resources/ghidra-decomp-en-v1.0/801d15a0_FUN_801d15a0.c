// Function: FUN_801d15a0
// Entry: 801d15a0
// Size: 332 bytes

void FUN_801d15a0(int param_1)

{
  int iVar1;
  float **ppfVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  float **local_70;
  undefined auStack108 [80];
  char local_1c;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0) &&
     (((*(byte *)(iVar5 + 0x137) & 8) != 0 ||
      ((*(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 8) != 0)))) {
    iVar1 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,&local_70,0,0);
    iVar3 = 0;
    ppfVar2 = local_70;
    if (0 < iVar1) {
      do {
        if (**ppfVar2 < FLOAT_803e5294 + *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = *local_70[iVar3];
          break;
        }
        ppfVar2 = ppfVar2 + 1;
        iVar3 = iVar3 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar1 = FUN_800640cc((double)FLOAT_803e52dc,param_1 + 0x80,param_1 + 0xc,2,auStack108,param_1,8,
                         0xffffffff,0xff,0x14);
    if (((*(char *)(iVar4 + 0x18) == '\x04') && (iVar1 != 0)) && (local_1c == '\r')) {
      *(byte *)(iVar5 + 0x137) = *(byte *)(iVar5 + 0x137) | 4;
    }
  }
  return;
}

