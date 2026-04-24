// Function: FUN_8001de4c
// Entry: 8001de4c
// Size: 812 bytes

int * FUN_8001de4c(int param_1)

{
  float fVar1;
  int *piVar2;
  undefined4 uVar3;
  double dVar4;
  float local_18;
  int local_14;
  float local_10;
  
  piVar2 = (int *)FUN_80023cc8(0x300,0x1a,0);
  if (piVar2 == (int *)0x0) {
    piVar2 = (int *)0x0;
  }
  else {
    FUN_800033a8(piVar2,0,0x300);
    *piVar2 = param_1;
    fVar1 = FLOAT_803de75c;
    if (*piVar2 == 0) {
      piVar2[4] = (int)FLOAT_803de75c;
      piVar2[5] = (int)fVar1;
      piVar2[6] = (int)fVar1;
    }
    else {
      piVar2[1] = (int)FLOAT_803de75c;
      piVar2[2] = (int)fVar1;
      piVar2[3] = (int)fVar1;
      FUN_8002b1e8(*piVar2,piVar2 + 1,piVar2 + 4,1);
    }
    uVar3 = FUN_8000f54c();
    if (piVar2[0x18] == 0) {
      local_18 = (float)piVar2[4] - FLOAT_803dcdd8;
      local_14 = piVar2[5];
      local_10 = (float)piVar2[6] - FLOAT_803dcddc;
      FUN_80247494(uVar3,&local_18,piVar2 + 7);
    }
    else {
      piVar2[7] = piVar2[4];
      piVar2[8] = piVar2[5];
      piVar2[9] = piVar2[6];
    }
    fVar1 = FLOAT_803de75c;
    if (*piVar2 == 0) {
      piVar2[0xd] = (int)FLOAT_803de75c;
      piVar2[0xe] = (int)fVar1;
      piVar2[0xf] = (int)FLOAT_803de760;
      FUN_80292c30(piVar2 + 0xd,piVar2 + 0xd);
    }
    else {
      piVar2[10] = (int)FLOAT_803de75c;
      piVar2[0xb] = (int)fVar1;
      piVar2[0xc] = (int)FLOAT_803de760;
      FUN_80292c30(piVar2 + 10,piVar2 + 10);
      FUN_8002b198(*piVar2,piVar2 + 10,piVar2 + 0xd);
    }
    uVar3 = FUN_8000f54c();
    if (piVar2[0x18] == 0) {
      FUN_80247574(uVar3,piVar2 + 0xd,piVar2 + 0x10);
    }
    else {
      piVar2[0x10] = piVar2[0xd];
      piVar2[0x11] = piVar2[0xe];
      piVar2[0x12] = piVar2[0xf];
    }
    FUN_8001db6c((double)FLOAT_803de75c,piVar2,1);
    piVar2[0x14] = 4;
    piVar2[0x15] = 1;
    piVar2[0x50] = (int)FLOAT_803de750;
    piVar2[0x51] = (int)FLOAT_803de754;
    FUN_80259848((double)(float)piVar2[0x50],(double)FLOAT_803de758,piVar2 + 0x1a,2);
    FUN_802596ac(piVar2 + 0x1a,piVar2 + 0x49,piVar2 + 0x4a,piVar2 + 0x4b);
    dVar4 = (double)FLOAT_803de75c;
    piVar2[0x51] = (int)FLOAT_803de75c;
    *(undefined *)(piVar2 + 0xbf) = 0x7f;
    piVar2[0x17] = 0;
    *(undefined *)(piVar2 + 0x19) = 1;
    piVar2[0x18] = 0;
    *(undefined *)((int)piVar2 + 0x4d) = 0;
    *(undefined *)(piVar2 + 0x2f) = 0;
    *(undefined *)(piVar2 + 0x2b) = 0xff;
    *(undefined *)(piVar2 + 0x2a) = 0xff;
    *(undefined *)((int)piVar2 + 0xad) = 0xff;
    *(undefined *)((int)piVar2 + 0xa9) = 0xff;
    *(undefined *)((int)piVar2 + 0xae) = 0xff;
    *(undefined *)((int)piVar2 + 0xaa) = 0xff;
    *(undefined *)((int)piVar2 + 0xaf) = 0xff;
    *(undefined *)((int)piVar2 + 0xab) = 0xff;
    piVar2[0x2d] = (int)FLOAT_803de79c;
    piVar2[0x2e] = 0;
    FUN_8025968c((double)FLOAT_803de760,dVar4,dVar4,piVar2 + 0x1a);
    *(undefined *)(piVar2 + 0x45) = 0;
    *(undefined *)(piVar2 + 0x41) = 0xff;
    *(undefined *)(piVar2 + 0x40) = 0xff;
    *(undefined *)((int)piVar2 + 0x105) = 0xff;
    *(undefined *)((int)piVar2 + 0x101) = 0xff;
    *(undefined *)((int)piVar2 + 0x106) = 0xff;
    *(undefined *)((int)piVar2 + 0x102) = 0xff;
    *(undefined *)((int)piVar2 + 0x107) = 0xff;
    *(undefined *)((int)piVar2 + 0x103) = 0xff;
    piVar2[0x43] = (int)FLOAT_803de7a0;
    piVar2[0x44] = (int)FLOAT_803de76c;
    dVar4 = (double)FLOAT_803de75c;
    FUN_80259670(dVar4,dVar4,(double)FLOAT_803de760,(double)((float)piVar2[0x43] * FLOAT_803de790),
                 dVar4,(double)(float)((double)FLOAT_803de760 -
                                      (double)((float)piVar2[0x43] * FLOAT_803de790)),piVar2 + 0x30)
    ;
    FUN_8001d620(piVar2,0,0);
    *(undefined *)(piVar2 + 0x2c) = 0xff;
    *(undefined *)((int)piVar2 + 0xb1) = 0xff;
    *(undefined *)((int)piVar2 + 0xb2) = 0xff;
    *(undefined *)((int)piVar2 + 0xb3) = 0xff;
    *(undefined *)(piVar2 + 0x42) = 0xff;
    *(undefined *)((int)piVar2 + 0x109) = 0xff;
    *(undefined *)((int)piVar2 + 0x10a) = 0xff;
    *(undefined *)((int)piVar2 + 0x10b) = 0xff;
    if (*piVar2 != 0) {
      FUN_8002b37c(*piVar2,piVar2 + 0x5c);
    }
    fVar1 = FLOAT_803de760;
    piVar2[0x4d] = (int)FLOAT_803de760;
    piVar2[0x49] = (int)fVar1;
    fVar1 = FLOAT_803de75c;
    piVar2[0x4a] = (int)FLOAT_803de75c;
    piVar2[0x4b] = (int)fVar1;
  }
  return piVar2;
}

