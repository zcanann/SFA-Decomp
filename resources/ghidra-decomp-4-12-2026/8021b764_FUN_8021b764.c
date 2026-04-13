// Function: FUN_8021b764
// Entry: 8021b764
// Size: 188 bytes

void FUN_8021b764(uint param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  float afStack_28 [4];
  longlong local_18;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = FUN_8000b598(param_1,1);
  if ((!bVar1) && (*(char *)(iVar3 + 0x1a) < '\0')) {
    FUN_80247eb8((float *)(param_1 + 0xc),(float *)(iVar3 + 8),afStack_28);
    dVar4 = FUN_80247f54(afStack_28);
    local_18 = (longlong)(int)((double)FLOAT_803e76c8 * dVar4);
    uVar2 = 200 - (int)((double)FLOAT_803e76c8 * dVar4);
    if ((int)uVar2 < 1) {
      uVar2 = 1;
    }
    else if (200 < (int)uVar2) {
      uVar2 = 200;
    }
    uVar2 = FUN_80022264(0,uVar2);
    if (uVar2 == 0) {
      FUN_8000bb38(param_1,0x1b3);
    }
  }
  return;
}

