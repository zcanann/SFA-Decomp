// Function: FUN_8010335c
// Entry: 8010335c
// Size: 748 bytes

void FUN_8010335c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 uVar2;
  short *psVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_80134f70();
  psVar3 = *(short **)(DAT_803de19c + 0x52);
  if (psVar3 == (short *)0x0) {
    psVar3 = DAT_803de19c;
    psVar3[0x92] = 0;
    psVar3[0x93] = 0;
    psVar3 = DAT_803de19c;
    psVar3[0x8e] = 0;
    psVar3[0x8f] = 0;
  }
  else {
    FLOAT_803de160 = *(float *)(psVar3 + 6);
    FLOAT_803de15c = *(float *)(psVar3 + 8);
    FLOAT_803de158 = *(float *)(psVar3 + 10);
    FLOAT_803de154 = *(float *)(psVar3 + 0xc);
    FLOAT_803de150 = *(float *)(psVar3 + 0xe);
    FLOAT_803de14c = *(float *)(psVar3 + 0x10);
    FUN_80101844((int)DAT_803de19c,(int)psVar3);
    if (*(char *)((int)DAT_803de19c + 0x13d) != '\0') {
      *(undefined4 *)(psVar3 + 0xc) = *(undefined4 *)(DAT_803de19c + 0x6e);
      *(undefined4 *)(psVar3 + 0xe) = *(undefined4 *)(DAT_803de19c + 0x70);
      *(undefined4 *)(psVar3 + 0x10) = *(undefined4 *)(DAT_803de19c + 0x72);
      param_2 = (double)*(float *)(psVar3 + 0xe);
      param_3 = (double)*(float *)(psVar3 + 0x10);
      FUN_8000e054((double)*(float *)(psVar3 + 0xc),param_2,param_3,(float *)(psVar3 + 6),
                   (float *)(psVar3 + 8),(float *)(psVar3 + 10),*(int *)(psVar3 + 0x18));
      *(undefined *)((int)DAT_803de19c + 0x13d) = 0;
    }
    if (*(int *)(DAT_803de19c + 0x18) != *(int *)(psVar3 + 0x18)) {
      FUN_8000e0c0((double)*(float *)(DAT_803de19c + 6),(double)*(float *)(DAT_803de19c + 8),
                   (double)*(float *)(DAT_803de19c + 10),(float *)(DAT_803de19c + 0xc),
                   (float *)(DAT_803de19c + 0xe),(float *)(DAT_803de19c + 0x10),
                   *(int *)(DAT_803de19c + 0x18));
      FUN_8000e0c0((double)*(float *)(DAT_803de19c + 0x54),(double)*(float *)(DAT_803de19c + 0x56),
                   (double)*(float *)(DAT_803de19c + 0x58),(float *)(DAT_803de19c + 0x5c),
                   (float *)(DAT_803de19c + 0x5e),(float *)(DAT_803de19c + 0x60),
                   *(int *)(DAT_803de19c + 0x18));
      FUN_8000e054((double)*(float *)(DAT_803de19c + 0xc),(double)*(float *)(DAT_803de19c + 0xe),
                   (double)*(float *)(DAT_803de19c + 0x10),(float *)(DAT_803de19c + 6),
                   (float *)(DAT_803de19c + 8),(float *)(DAT_803de19c + 10),*(int *)(psVar3 + 0x18))
      ;
      param_2 = (double)*(float *)(DAT_803de19c + 0x5e);
      param_3 = (double)*(float *)(DAT_803de19c + 0x60);
      FUN_8000e054((double)*(float *)(DAT_803de19c + 0x5c),param_2,param_3,
                   (float *)(DAT_803de19c + 0x54),(float *)(DAT_803de19c + 0x56),
                   (float *)(DAT_803de19c + 0x58),*(int *)(psVar3 + 0x18));
      *(undefined4 *)(DAT_803de19c + 0x18) = *(undefined4 *)(psVar3 + 0x18);
    }
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 + **(short **)(psVar3 + 0x18);
    }
    FUN_80102158();
    if (DAT_803de194 != 0) {
      (**(code **)(**(int **)(DAT_803de194 + 4) + 8))(DAT_803de19c);
      param_2 = (double)*(float *)(DAT_803de19c + 8);
      param_3 = (double)*(float *)(DAT_803de19c + 10);
      FUN_8000e0c0((double)*(float *)(DAT_803de19c + 6),param_2,param_3,
                   (float *)(DAT_803de19c + 0xc),(float *)(DAT_803de19c + 0xe),
                   (float *)(DAT_803de19c + 0x10),*(int *)(DAT_803de19c + 0x18));
      FUN_80101c1c(DAT_803de19c);
    }
    uVar4 = FUN_80102158();
    if (iVar1 == 0) {
      if (*(int *)(DAT_803de19c + 0x8e) == 0) {
        uVar2 = FUN_80101350(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        *(undefined4 *)(DAT_803de19c + 0x92) = uVar2;
      }
      else {
        *(int *)(DAT_803de19c + 0x92) = *(int *)(DAT_803de19c + 0x8e);
      }
    }
    *(undefined4 *)(DAT_803de19c + 0x54) = *(undefined4 *)(DAT_803de19c + 6);
    *(undefined4 *)(DAT_803de19c + 0x56) = *(undefined4 *)(DAT_803de19c + 8);
    *(undefined4 *)(DAT_803de19c + 0x58) = *(undefined4 *)(DAT_803de19c + 10);
    *(undefined4 *)(DAT_803de19c + 0x5c) = *(undefined4 *)(DAT_803de19c + 0xc);
    *(undefined4 *)(DAT_803de19c + 0x5e) = *(undefined4 *)(DAT_803de19c + 0xe);
    *(undefined4 *)(DAT_803de19c + 0x60) = *(undefined4 *)(DAT_803de19c + 0x10);
    *(undefined *)(DAT_803de19c + 0xa0) = 0;
    *(float *)(psVar3 + 6) = FLOAT_803de160;
    *(float *)(psVar3 + 8) = FLOAT_803de15c;
    *(float *)(psVar3 + 10) = FLOAT_803de158;
    *(float *)(psVar3 + 0xc) = FLOAT_803de154;
    *(float *)(psVar3 + 0xe) = FLOAT_803de150;
    *(float *)(psVar3 + 0x10) = FLOAT_803de14c;
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 - **(short **)(psVar3 + 0x18);
    }
  }
  return;
}

