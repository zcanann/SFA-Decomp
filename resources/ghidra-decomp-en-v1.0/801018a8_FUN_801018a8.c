// Function: FUN_801018a8
// Entry: 801018a8
// Size: 204 bytes

void FUN_801018a8(uint param_1,undefined param_2)

{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  
  FUN_8000faac();
  fVar1 = FLOAT_803e162c;
  *(float *)(DAT_803dd524 + 0xf4) = FLOAT_803e162c;
  *(float *)(DAT_803dd524 + 0xf8) =
       fVar1 / (float)((double)CONCAT44(0x43300000,param_1 & 0xff) - DOUBLE_803e1660);
  *(undefined *)(DAT_803dd524 + 0x13f) = param_2;
  puVar2 = (undefined2 *)FUN_8000faac();
  *(undefined4 *)(DAT_803dd524 + 0x10c) = *(undefined4 *)(puVar2 + 6);
  *(undefined4 *)(DAT_803dd524 + 0x110) = *(undefined4 *)(puVar2 + 8);
  *(undefined4 *)(DAT_803dd524 + 0x114) = *(undefined4 *)(puVar2 + 10);
  *(undefined2 *)(DAT_803dd524 + 0x106) = *puVar2;
  *(undefined2 *)(DAT_803dd524 + 0x108) = puVar2[1];
  *(undefined2 *)(DAT_803dd524 + 0x10a) = puVar2[2];
  dVar3 = (double)FUN_8000fc34();
  *(float *)(DAT_803dd524 + 0x118) = (float)dVar3;
  return;
}

