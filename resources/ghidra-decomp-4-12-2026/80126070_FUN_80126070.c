// Function: FUN_80126070
// Entry: 80126070
// Size: 280 bytes

void FUN_80126070(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  iVar8 = 0;
  piVar7 = &DAT_803aa058;
  puVar6 = &DAT_8031cbe0;
  do {
    if (((iVar8 == 3) || (iVar8 == 2)) || (iVar8 == 1)) {
      if (*piVar7 == 0) {
        puVar2 = FUN_8002becc(0x20,(short)*puVar6);
        uVar4 = 0xffffffff;
        uVar5 = 0;
        iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *piVar7 = iVar3;
        fVar1 = FLOAT_803e2abc;
        *(float *)(*piVar7 + 0xc) = FLOAT_803e2abc;
        *(float *)(*piVar7 + 0x10) = fVar1;
        *(float *)(*piVar7 + 0x14) = FLOAT_803e2adc;
        *(undefined2 *)*piVar7 = 0x7447;
        *(float *)(*piVar7 + 8) = FLOAT_803e2cdc;
        if (0x90000000 < *(uint *)(*piVar7 + 0x4c)) {
          *(undefined4 *)(*piVar7 + 0x4c) = 0;
        }
        param_1 = FUN_8003042c((double)FLOAT_803e2abc,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,*piVar7,1,0,uVar4,uVar5,in_r8,in_r9,in_r10);
      }
    }
    else {
      *piVar7 = 0;
    }
    piVar7 = piVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 6);
  return;
}

