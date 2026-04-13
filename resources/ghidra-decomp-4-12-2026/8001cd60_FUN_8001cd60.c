// Function: FUN_8001cd60
// Entry: 8001cd60
// Size: 272 bytes

void FUN_8001cd60(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4,
                 uint param_5)

{
  int iVar1;
  undefined extraout_r4;
  uint uVar2;
  int *piVar3;
  
  iVar1 = FUN_80286840();
  if (DAT_803dd6b0 < 0x32) {
    piVar3 = FUN_8001df10(iVar1);
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      uVar2 = (uint)DAT_803dd6b0;
      DAT_803dd6b0 = DAT_803dd6b0 + 1;
      (&DAT_8033cb20)[uVar2] = piVar3;
    }
  }
  else {
    piVar3 = (int *)0x0;
  }
  if (piVar3 != (int *)0x0) {
    piVar3[0x14] = 2;
    *(undefined *)(piVar3 + 0x2b) = extraout_r4;
    *(undefined *)(piVar3 + 0x2a) = extraout_r4;
    *(undefined *)((int)piVar3 + 0xad) = param_3;
    *(undefined *)((int)piVar3 + 0xa9) = param_3;
    *(undefined *)((int)piVar3 + 0xae) = param_4;
    *(undefined *)((int)piVar3 + 0xaa) = param_4;
    *(undefined *)((int)piVar3 + 0xaf) = 0;
    *(undefined *)((int)piVar3 + 0xab) = 0;
    *(undefined *)(piVar3 + 0x2f) = 1;
    piVar3[0x50] = (int)FLOAT_803df3d0;
    piVar3[0x51] = (int)FLOAT_803df3d4;
    FUN_80259fac((double)(float)piVar3[0x50],(double)FLOAT_803df3d8,(int)(piVar3 + 0x1a),2);
    FUN_80259e10((int)(piVar3 + 0x1a),piVar3 + 0x49,piVar3 + 0x4a,piVar3 + 0x4b);
    if ((param_5 & 0xff) != 0) {
      *(undefined *)((int)piVar3 + 0x2fb) = 1;
    }
  }
  FUN_8028688c();
  return;
}

