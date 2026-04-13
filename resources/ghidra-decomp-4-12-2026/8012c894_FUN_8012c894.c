// Function: FUN_8012c894
// Entry: 8012c894
// Size: 340 bytes

void FUN_8012c894(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar7;
  int *piVar8;
  int iVar9;
  
  iVar3 = FUN_8002bac4();
  iVar9 = 0;
  piVar8 = &DAT_803aa070;
  puVar7 = &DAT_8031cbe0;
  do {
    if ((iVar9 < 4) && (*piVar8 == 0)) {
      puVar4 = FUN_8002becc(0x20,(short)*puVar7);
      iVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                           0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      *piVar8 = iVar5;
      fVar1 = FLOAT_803e2abc;
      param_1 = (double)FLOAT_803e2abc;
      *(float *)(*piVar8 + 0xc) = FLOAT_803e2abc;
      fVar2 = FLOAT_803e2adc;
      *(float *)(*piVar8 + 0x10) = FLOAT_803e2adc;
      *(float *)(*piVar8 + 0x14) = fVar2;
      *(undefined2 *)*piVar8 = 0x7447;
      *(float *)(*piVar8 + 8) = fVar1;
      if (0x90000000 < *(uint *)(*piVar8 + 0x4c)) {
        *(undefined4 *)(*piVar8 + 0x4c) = 0;
      }
    }
    piVar8 = piVar8 + 1;
    puVar7 = puVar7 + 1;
    iVar9 = iVar9 + 1;
  } while (iVar9 < 6);
  DAT_803de406 = 0;
  DAT_803de404 = 0;
  DAT_803de40c = 0;
  FUN_80014b44(0xf);
  if (iVar3 != 0) {
    uVar6 = FUN_8002bac4();
    FUN_8002ad08(uVar6,0,0,0,0,0);
  }
  FUN_8000a538((int *)0x23,1);
  FUN_8000bb38(0,0x3e5);
  FUN_8000bb38(0,0xff);
  return;
}

