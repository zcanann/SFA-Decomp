// Function: FUN_802b2158
// Entry: 802b2158
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x802b2268) */
/* WARNING: Removing unreachable block (ram,0x802b2168) */

void FUN_802b2158(double param_1,int param_2,int param_3)

{
  double dVar1;
  char cVar3;
  uint uVar2;
  
  *(undefined4 *)(param_3 + 0x6d0) = 0;
  *(undefined4 *)(param_3 + 0x6d4) = 0;
  *(undefined2 *)(param_3 + 0x6e0) = 0;
  *(undefined2 *)(param_3 + 0x6e2) = 0;
  *(undefined2 *)(param_3 + 0x6e4) = 0;
  if (((((*(uint *)(param_3 + 0x360) & 0x200000) == 0) && (*(short *)(param_3 + 0x81a) != -1)) &&
      (*(char *)(param_3 + 0x8c8) != 'D')) && (*(char *)(param_3 + 0x8c8) != 'N')) {
    cVar3 = FUN_80014cec(0);
    *(int *)(param_3 + 0x6d0) = (int)cVar3;
    cVar3 = FUN_80014c98(0);
    *(int *)(param_3 + 0x6d4) = (int)cVar3;
    uVar2 = FUN_80014f14(0);
    *(short *)(param_3 + 0x6e0) = (short)uVar2;
    uVar2 = FUN_80014e9c(0);
    *(short *)(param_3 + 0x6e2) = (short)uVar2;
    uVar2 = FUN_80014e40(0);
    *(short *)(param_3 + 0x6e4) = (short)uVar2;
  }
  dVar1 = DOUBLE_803e8b58;
  *(float *)(param_3 + 0x6dc) =
       (float)((double)CONCAT44(0x43300000,*(uint *)(param_3 + 0x6d0) ^ 0x80000000) -
              DOUBLE_803e8b58);
  *(float *)(param_3 + 0x6d8) =
       (float)((double)CONCAT44(0x43300000,*(uint *)(param_3 + 0x6d4) ^ 0x80000000) - dVar1);
  FUN_802b201c(param_1,param_2,param_3);
  return;
}

