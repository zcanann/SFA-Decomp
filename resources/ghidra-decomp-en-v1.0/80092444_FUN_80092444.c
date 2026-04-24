// Function: FUN_80092444
// Entry: 80092444
// Size: 216 bytes

void FUN_80092444(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  undefined4 local_18 [2];
  
  local_18[0] = DAT_803df198;
  dVar4 = (double)FLOAT_803df1a0;
  FUN_8025c2d4(dVar4,dVar4,dVar4,dVar4,0,local_18);
  iVar2 = 0;
  piVar3 = &DAT_8039a828;
  do {
    iVar1 = *piVar3;
    if ((iVar1 != 0) && (*(char *)(iVar1 + 0x144f) == '\0')) {
      FUN_80090274(param_1,*(undefined4 *)(iVar1 + 0x13f0));
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 8);
  if (DAT_803dd198 != '\0') {
    FUN_80079e64((double)FLOAT_803dd190,(double)FLOAT_803db764,(double)FLOAT_803db768,DAT_803dd198,
                 &DAT_8039a8f0,DAT_803dd199,DAT_803dd19a);
  }
  return;
}

