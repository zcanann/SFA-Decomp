// Function: FUN_8001df10
// Entry: 8001df10
// Size: 812 bytes

int * FUN_8001df10(int param_1)

{
  float fVar1;
  int *piVar2;
  float *pfVar3;
  double dVar4;
  float local_18;
  int local_14;
  float local_10;
  
  piVar2 = (int *)FUN_80023d8c(0x300,0x1a);
  if (piVar2 == (int *)0x0) {
    piVar2 = (int *)0x0;
  }
  else {
    FUN_800033a8((int)piVar2,0,0x300);
    *piVar2 = param_1;
    fVar1 = FLOAT_803df3dc;
    if (*piVar2 == 0) {
      piVar2[4] = (int)FLOAT_803df3dc;
      piVar2[5] = (int)fVar1;
      piVar2[6] = (int)fVar1;
    }
    else {
      piVar2[1] = (int)FLOAT_803df3dc;
      piVar2[2] = (int)fVar1;
      piVar2[3] = (int)fVar1;
      FUN_8002b2c0((ushort *)*piVar2,(float *)(piVar2 + 1),(float *)(piVar2 + 4),'\x01');
    }
    pfVar3 = (float *)FUN_8000f56c();
    if (piVar2[0x18] == 0) {
      local_18 = (float)piVar2[4] - FLOAT_803dda58;
      local_14 = piVar2[5];
      local_10 = (float)piVar2[6] - FLOAT_803dda5c;
      FUN_80247bf8(pfVar3,&local_18,(float *)(piVar2 + 7));
    }
    else {
      piVar2[7] = piVar2[4];
      piVar2[8] = piVar2[5];
      piVar2[9] = piVar2[6];
    }
    fVar1 = FLOAT_803df3dc;
    if (*piVar2 == 0) {
      piVar2[0xd] = (int)FLOAT_803df3dc;
      piVar2[0xe] = (int)fVar1;
      piVar2[0xf] = (int)FLOAT_803df3e0;
      FUN_80293390((float *)(piVar2 + 0xd),(float *)(piVar2 + 0xd));
    }
    else {
      piVar2[10] = (int)FLOAT_803df3dc;
      piVar2[0xb] = (int)fVar1;
      piVar2[0xc] = (int)FLOAT_803df3e0;
      FUN_80293390((float *)(piVar2 + 10),(float *)(piVar2 + 10));
      FUN_8002b270((ushort *)*piVar2,(float *)(piVar2 + 10),(float *)(piVar2 + 0xd));
    }
    pfVar3 = (float *)FUN_8000f56c();
    if (piVar2[0x18] == 0) {
      FUN_80247cd8(pfVar3,(float *)(piVar2 + 0xd),(float *)(piVar2 + 0x10));
    }
    else {
      piVar2[0x10] = piVar2[0xd];
      piVar2[0x11] = piVar2[0xe];
      piVar2[0x12] = piVar2[0xf];
    }
    FUN_8001dc30((double)FLOAT_803df3dc,(int)piVar2,'\x01');
    piVar2[0x14] = 4;
    piVar2[0x15] = 1;
    piVar2[0x50] = (int)FLOAT_803df3d0;
    piVar2[0x51] = (int)FLOAT_803df3d4;
    FUN_80259fac((double)(float)piVar2[0x50],(double)FLOAT_803df3d8,(int)(piVar2 + 0x1a),2);
    FUN_80259e10((int)(piVar2 + 0x1a),piVar2 + 0x49,piVar2 + 0x4a,piVar2 + 0x4b);
    dVar4 = (double)FLOAT_803df3dc;
    piVar2[0x51] = (int)FLOAT_803df3dc;
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
    piVar2[0x2d] = (int)FLOAT_803df41c;
    piVar2[0x2e] = 0;
    FUN_80259df0((double)FLOAT_803df3e0,dVar4,dVar4,(int)(piVar2 + 0x1a));
    *(undefined *)(piVar2 + 0x45) = 0;
    *(undefined *)(piVar2 + 0x41) = 0xff;
    *(undefined *)(piVar2 + 0x40) = 0xff;
    *(undefined *)((int)piVar2 + 0x105) = 0xff;
    *(undefined *)((int)piVar2 + 0x101) = 0xff;
    *(undefined *)((int)piVar2 + 0x106) = 0xff;
    *(undefined *)((int)piVar2 + 0x102) = 0xff;
    *(undefined *)((int)piVar2 + 0x107) = 0xff;
    *(undefined *)((int)piVar2 + 0x103) = 0xff;
    piVar2[0x43] = (int)FLOAT_803df420;
    piVar2[0x44] = (int)FLOAT_803df3ec;
    dVar4 = (double)FLOAT_803df3dc;
    FUN_80259dd4(dVar4,dVar4,(double)FLOAT_803df3e0,(double)((float)piVar2[0x43] * FLOAT_803df410),
                 dVar4,(double)(float)((double)FLOAT_803df3e0 -
                                      (double)((float)piVar2[0x43] * FLOAT_803df410)),
                 (int)(piVar2 + 0x30));
    FUN_8001d6e4((int)piVar2,0,0);
    *(undefined *)(piVar2 + 0x2c) = 0xff;
    *(undefined *)((int)piVar2 + 0xb1) = 0xff;
    *(undefined *)((int)piVar2 + 0xb2) = 0xff;
    *(undefined *)((int)piVar2 + 0xb3) = 0xff;
    *(undefined *)(piVar2 + 0x42) = 0xff;
    *(undefined *)((int)piVar2 + 0x109) = 0xff;
    *(undefined *)((int)piVar2 + 0x10a) = 0xff;
    *(undefined *)((int)piVar2 + 0x10b) = 0xff;
    if ((short *)*piVar2 != (short *)0x0) {
      FUN_8002b454((short *)*piVar2,piVar2 + 0x5c);
    }
    fVar1 = FLOAT_803df3e0;
    piVar2[0x4d] = (int)FLOAT_803df3e0;
    piVar2[0x49] = (int)fVar1;
    fVar1 = FLOAT_803df3dc;
    piVar2[0x4a] = (int)FLOAT_803df3dc;
    piVar2[0x4b] = (int)fVar1;
  }
  return piVar2;
}

