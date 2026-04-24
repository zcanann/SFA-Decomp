// Function: FUN_8028d200
// Entry: 8028d200
// Size: 224 bytes

void FUN_8028d200(int param_1)

{
  if (param_1 == 1) {
    FUN_8026bf4c();
    DAT_80332360 = &LAB_80285a48;
    DAT_80332364 = &LAB_80285ac0;
    DAT_80332368 = &LAB_80285b14;
    DAT_8033236c = &LAB_80285bb0;
    DAT_80332370 = &LAB_80285c3c;
    DAT_80332374 = &DAT_80285e9c;
    DAT_80332378 = &DAT_80285ea0;
  }
  else {
    FUN_8026bf44();
    DAT_80332360 = &DAT_8026bf1c;
    DAT_80332364 = &DAT_8026bf20;
    DAT_80332368 = &LAB_8026bf24;
    DAT_8033236c = &LAB_8026bf2c;
    DAT_80332370 = &LAB_8026bf34;
    DAT_80332374 = &DAT_8026bf3c;
    DAT_80332378 = &DAT_8026bf40;
  }
  return;
}

