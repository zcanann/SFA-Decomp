// Function: FUN_80101ebc
// Entry: 80101ebc
// Size: 400 bytes

void FUN_80101ebc(void)

{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  
  if (DAT_803dd502 != '\0') {
    if ((int)DAT_803dd4fc < 2) {
      *(float *)(DAT_803dd524 + 0x7a) = FLOAT_803e1630;
      *(undefined *)((int)DAT_803dd524 + 0x13f) = 0;
    }
    else {
      fVar1 = FLOAT_803e162c /
              (float)((double)CONCAT44(0x43300000,DAT_803dd4fc ^ 0x80000000) - DOUBLE_803e1650);
      if ((fVar1 <= FLOAT_803e1630) || (FLOAT_803e162c < fVar1)) {
        fVar1 = FLOAT_803e162c;
      }
      *(float *)(DAT_803dd524 + 0x7a) = FLOAT_803e162c;
      *(float *)(DAT_803dd524 + 0x7c) = fVar1;
      *(undefined *)((int)DAT_803dd524 + 0x13f) = DAT_803dd4f8;
    }
    puVar2 = (undefined2 *)FUN_8000faac();
    if (FLOAT_803e162c == *(float *)(DAT_803dd524 + 0x7a)) {
      *(undefined4 *)(DAT_803dd524 + 0x86) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(DAT_803dd524 + 0x88) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(DAT_803dd524 + 0x8a) = *(undefined4 *)(puVar2 + 10);
      DAT_803dd524[0x83] = *puVar2;
      DAT_803dd524[0x84] = puVar2[1];
      DAT_803dd524[0x85] = puVar2[2];
      dVar3 = (double)FUN_8000fc34();
      *(float *)(DAT_803dd524 + 0x8c) = (float)dVar3;
    }
    else {
      *DAT_803dd524 = *puVar2;
      DAT_803dd524[1] = puVar2[1];
      DAT_803dd524[2] = puVar2[2];
      dVar3 = (double)FUN_8000fc34();
      *(float *)(DAT_803dd524 + 0x5a) = (float)dVar3;
    }
    DAT_803dd4f4 = DAT_803dd518;
    DAT_803dd4f0 = DAT_803dd50c;
    DAT_803dd4ec = DAT_803dd508;
    FUN_80101690(DAT_803dd510 & 0xffff,DAT_803dd504);
    DAT_803dd502 = '\0';
    if (DAT_803dd504 != 0) {
      FUN_80023800();
      DAT_803dd504 = 0;
    }
  }
  return;
}

