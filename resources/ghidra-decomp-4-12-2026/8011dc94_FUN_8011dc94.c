// Function: FUN_8011dc94
// Entry: 8011dc94
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x8011dff4) */
/* WARNING: Removing unreachable block (ram,0x8011dfec) */
/* WARNING: Removing unreachable block (ram,0x8011dfe4) */
/* WARNING: Removing unreachable block (ram,0x8011dcb4) */
/* WARNING: Removing unreachable block (ram,0x8011dcac) */
/* WARNING: Removing unreachable block (ram,0x8011dca4) */

void FUN_8011dc94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined2 *puVar1;
  int iVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar3;
  short sVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  undefined8 uVar8;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  double dVar9;
  double dVar10;
  double dVar11;
  
  uVar8 = FUN_80286838();
  if (DAT_803de445 == '\0') {
    sVar4 = 0;
    iVar5 = 0;
    piVar7 = &DAT_803aa04c;
    piVar6 = &DAT_803aa040;
    dVar9 = (double)FLOAT_803e2abc;
    dVar11 = (double)FLOAT_803e2ac0;
    dVar10 = (double)FLOAT_803e2ac4;
    do {
      puVar1 = FUN_8002becc(0x20,0x65e);
      iVar2 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1,4,
                           0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      *piVar7 = iVar2;
      *(float *)(*piVar7 + 0xc) = (float)dVar9;
      *(float *)(*piVar7 + 0x10) = (float)dVar11;
      *(float *)(*piVar7 + 0x14) = (float)dVar10;
      *(short *)*piVar7 = sVar4;
      *(char *)(*piVar7 + 0xad) = (char)iVar5;
      iVar2 = FUN_8002b660(*piVar7);
      uVar8 = FUN_80028600(iVar2,FUN_80124a78);
      puVar1 = FUN_8002becc(0x20,0x65f);
      iVar2 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1,4,
                           0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      *piVar6 = iVar2;
      *(float *)(*piVar6 + 0xc) = (float)dVar9;
      *(float *)(*piVar6 + 0x10) = (float)dVar11;
      *(float *)(*piVar6 + 0x14) = (float)dVar10;
      *(short *)*piVar6 = sVar4;
      iVar2 = FUN_8002b660(*piVar6);
      uVar8 = FUN_80028600(iVar2,FUN_80124b38);
      sVar4 = sVar4 + 0x5555;
      piVar7 = piVar7 + 1;
      piVar6 = piVar6 + 1;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
    puVar1 = FUN_8002becc(0x20,0x6e9);
    DAT_803de4e8 = (undefined2 *)
                   FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1
                                ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(float *)(DAT_803de4e8 + 6) = FLOAT_803e2abc;
    *(float *)(DAT_803de4e8 + 8) = FLOAT_803e2ac8;
    *(float *)(DAT_803de4e8 + 10) = FLOAT_803e2acc;
    *DAT_803de4e8 = 0x7447;
    *(float *)(DAT_803de4e8 + 4) = FLOAT_803e2ad0;
    uVar8 = extraout_f1;
    puVar1 = FUN_8002becc(0x20,0x602);
    puRam803de4ec =
         (undefined2 *)
         FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1,4,0xff,
                      0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(float *)(puRam803de4ec + 6) = FLOAT_803e2abc;
    *(float *)(puRam803de4ec + 8) = FLOAT_803e2ad4;
    *(float *)(puRam803de4ec + 10) = FLOAT_803e2acc;
    *puRam803de4ec = 0x7447;
    *(float *)(puRam803de4ec + 4) = FLOAT_803e2ad8;
    uVar8 = extraout_f1_00;
    puVar1 = FUN_8002becc(0x20,0x755);
    DAT_803de4e0 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1
                                ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    uVar8 = FUN_80028600(**(int **)(DAT_803de4e0 + 0x7c),FUN_8011e3bc);
    puVar1 = FUN_8002becc(0x20,0x756);
    iRam803de4e4 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1
                                ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    uVar8 = FUN_80028600(**(int **)(iRam803de4e4 + 0x7c),FUN_8011e3bc);
    iVar5 = 4;
    puVar3 = &DAT_8031cbf0;
    piVar6 = &DAT_803aa080;
    dVar9 = (double)FLOAT_803e2abc;
    dVar10 = (double)FLOAT_803e2adc;
    do {
      puVar1 = FUN_8002becc(0x20,(short)*puVar3);
      iVar2 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1,4,
                           0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      *piVar6 = iVar2;
      *(float *)(*piVar6 + 0xc) = (float)dVar9;
      *(float *)(*piVar6 + 0x10) = (float)dVar10;
      *(float *)(*piVar6 + 0x14) = (float)dVar10;
      *(undefined2 *)*piVar6 = 0x7447;
      *(float *)(*piVar6 + 8) = (float)dVar9;
      if (0x90000000 < *(uint *)(*piVar6 + 0x4c)) {
        *(undefined4 *)(*piVar6 + 0x4c) = 0;
      }
      puVar3 = puVar3 + 1;
      piVar6 = piVar6 + 1;
      iVar5 = iVar5 + 1;
      uVar8 = extraout_f1_01;
    } while (iVar5 < 6);
    puVar1 = FUN_8002becc(0x24,0x14b);
    puVar1[0xe] = 1;
    DAT_803de4dc = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1
                                ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    DAT_803de445 = '\x01';
  }
  FUN_80286884();
  return;
}

