// Function: FUN_8025ddbc
// Entry: 8025ddbc
// Size: 196 bytes

void FUN_8025ddbc(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  bool bVar1;
  short sVar2;
  short sVar3;
  
  sVar3 = *(short *)(DAT_803de0ac + 0x42);
  do {
    sVar2 = *(short *)(DAT_803de0ac + 0x42);
    bVar1 = sVar2 != sVar3;
    sVar3 = sVar2;
  } while (bVar1);
  *param_3 = CONCAT22(sVar2,*(undefined2 *)(DAT_803de0ac + 0x40));
  sVar3 = *(short *)(DAT_803de0ac + 0x46);
  do {
    sVar2 = *(short *)(DAT_803de0ac + 0x46);
    bVar1 = sVar2 != sVar3;
    sVar3 = sVar2;
  } while (bVar1);
  *param_4 = CONCAT22(sVar2,*(undefined2 *)(DAT_803de0ac + 0x44));
  sVar3 = *(short *)(DAT_803de0ac + 0x4a);
  do {
    sVar2 = *(short *)(DAT_803de0ac + 0x4a);
    bVar1 = sVar2 != sVar3;
    sVar3 = sVar2;
  } while (bVar1);
  *param_1 = CONCAT22(sVar2,*(undefined2 *)(DAT_803de0ac + 0x48));
  sVar3 = *(short *)(DAT_803de0ac + 0x4e);
  do {
    sVar2 = *(short *)(DAT_803de0ac + 0x4e);
    bVar1 = sVar2 != sVar3;
    sVar3 = sVar2;
  } while (bVar1);
  *param_2 = CONCAT22(sVar2,*(undefined2 *)(DAT_803de0ac + 0x4c));
  return;
}

