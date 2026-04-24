// Function: FUN_801ad440
// Entry: 801ad440
// Size: 236 bytes

undefined4 FUN_801ad440(int param_1)

{
  int iVar1;
  float *pfVar2;
  double dVar3;
  
  if (*(short *)(param_1 + 0x46) != 0x172) {
    pfVar2 = *(float **)(param_1 + 0xb8);
    iVar1 = FUN_8002b9ec();
    dVar3 = (double)FUN_80021704(iVar1 + 0x18,param_1 + 0x18);
    if (((double)*pfVar2 <= dVar3) || (*(char *)((int)pfVar2 + 0xb) != '\0')) {
      if (((double)(float)((double)FLOAT_803e4738 + (double)*pfVar2) < dVar3) &&
         (*(char *)((int)pfVar2 + 0xb) != '\0')) {
        *(undefined *)((int)pfVar2 + 0xb) = 0;
        FUN_800066e0(param_1,param_1,*(undefined2 *)(pfVar2 + 2),0,0,0);
      }
    }
    else {
      *(undefined *)((int)pfVar2 + 0xb) = 1;
      FUN_800066e0(param_1,param_1,*(undefined2 *)((int)pfVar2 + 6),0,0,0);
    }
  }
  return 0;
}

