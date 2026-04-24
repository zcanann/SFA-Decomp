// Function: FUN_80080ea4
// Entry: 80080ea4
// Size: 464 bytes

void FUN_80080ea4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int extraout_r4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  undefined4 uStack_a8;
  int local_a4;
  int local_a0 [40];
  
  uVar1 = FUN_80286840();
  uVar8 = extraout_f1;
  piVar2 = (int *)FUN_8002e1f4(&uStack_a8,&local_a4);
  iVar3 = 0;
  for (iVar7 = 0; iVar7 < local_a4; iVar7 = iVar7 + 1) {
    iVar4 = *piVar2;
    if ((int)*(short *)(iVar4 + 0xb4) == uVar1) {
      *(undefined2 *)(iVar4 + 0xb4) = 0xffff;
    }
    iVar6 = iVar3;
    if ((*(short *)(iVar4 + 0x44) == 0x10) &&
       (iVar5 = *(int *)(iVar4 + 0xb8), (int)*(char *)(iVar5 + 0x57) == uVar1)) {
      if (iVar4 == DAT_803ddd38) {
        DAT_803ddd38 = 0;
      }
      iVar6 = iVar3 + 1;
      local_a0[iVar3] = iVar4;
      if (*(code **)(iVar5 + 0xe8) != (code *)0x0) {
        param_11 = iVar5;
        uVar8 = (**(code **)(iVar5 + 0xe8))(*(undefined4 *)(iVar5 + 0x110));
        *(undefined4 *)(iVar5 + 0xe8) = 0;
        iVar4 = extraout_r4;
      }
      if (iVar6 == 0x10) {
        uVar8 = FUN_80137c30(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             s_endObjSequence__max_number_of_ob_8030fa94,iVar4,param_11,param_12,
                             param_13,param_14,param_15,param_16);
      }
    }
    piVar2 = piVar2 + 1;
    iVar3 = iVar6;
  }
  if (DAT_803ddd0c == uVar1) {
    DAT_803ddd0c = 0;
    uVar8 = FUN_80130118();
  }
  if (uVar1 == DAT_803dc380) {
    uVar8 = FUN_8000d0e0();
    DAT_803dc380 = 0xffffffff;
  }
  piVar2 = local_a0;
  for (iVar7 = 0; iVar7 < iVar3; iVar7 = iVar7 + 1) {
    uVar8 = FUN_8002cc9c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar2);
    piVar2 = piVar2 + 1;
  }
  if ((uVar1 == DAT_803ddce4) && (iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar3 == 0x4d)) {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,3,0,0,0,0);
    DAT_803ddce4 = 0;
    DAT_803ddd0c = 0;
    FUN_80130118();
  }
  DAT_803ddcfc = 0;
  (&DAT_8039b010)[uVar1] = 0;
  FUN_8028688c();
  return;
}

