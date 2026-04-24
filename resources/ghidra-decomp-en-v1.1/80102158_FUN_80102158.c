// Function: FUN_80102158
// Entry: 80102158
// Size: 400 bytes

void FUN_80102158(void)

{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  
  if (DAT_803de17a != '\0') {
    if ((int)DAT_803de174 < 2) {
      *(float *)(DAT_803de19c + 0x7a) = FLOAT_803e22b0;
      *(undefined *)((int)DAT_803de19c + 0x13f) = 0;
    }
    else {
      fVar1 = FLOAT_803e22ac /
              (float)((double)CONCAT44(0x43300000,DAT_803de174 ^ 0x80000000) - DOUBLE_803e22d0);
      if ((fVar1 <= FLOAT_803e22b0) || (FLOAT_803e22ac < fVar1)) {
        fVar1 = FLOAT_803e22ac;
      }
      *(float *)(DAT_803de19c + 0x7a) = FLOAT_803e22ac;
      *(float *)(DAT_803de19c + 0x7c) = fVar1;
      *(undefined *)((int)DAT_803de19c + 0x13f) = DAT_803de170;
    }
    puVar2 = FUN_8000facc();
    if (FLOAT_803e22ac == *(float *)(DAT_803de19c + 0x7a)) {
      *(undefined4 *)(DAT_803de19c + 0x86) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(DAT_803de19c + 0x88) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(DAT_803de19c + 0x8a) = *(undefined4 *)(puVar2 + 10);
      DAT_803de19c[0x83] = *puVar2;
      DAT_803de19c[0x84] = puVar2[1];
      DAT_803de19c[0x85] = puVar2[2];
      dVar3 = FUN_8000fc54();
      *(float *)(DAT_803de19c + 0x8c) = (float)dVar3;
    }
    else {
      *DAT_803de19c = *puVar2;
      DAT_803de19c[1] = puVar2[1];
      DAT_803de19c[2] = puVar2[2];
      dVar3 = FUN_8000fc54();
      *(float *)(DAT_803de19c + 0x5a) = (float)dVar3;
    }
    DAT_803de16c = DAT_803de190;
    DAT_803de168 = DAT_803de184;
    DAT_803de164 = DAT_803de180;
    FUN_8010192c(DAT_803de188 & 0xffff,DAT_803de17c);
    DAT_803de17a = '\0';
    if (DAT_803de17c != 0) {
      FUN_800238c4(DAT_803de17c);
      DAT_803de17c = 0;
    }
  }
  return;
}

