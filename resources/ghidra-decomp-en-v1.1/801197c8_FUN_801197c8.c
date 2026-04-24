// Function: FUN_801197c8
// Entry: 801197c8
// Size: 248 bytes

void FUN_801197c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 *local_28 [10];
  
  uVar7 = FUN_8028683c();
  iVar6 = 0;
  iVar3 = DAT_803a6a74;
  uVar5 = DAT_803a6a70;
  do {
    FUN_80244820((int *)&DAT_803a7f30,local_28,1);
    puVar1 = local_28[0];
    iVar2 = FUN_80249700(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (undefined4 *)&DAT_803a69c0,*local_28[0],iVar3,uVar5,2,in_r8,in_r9,in_r10);
    if (iVar2 != iVar3) {
      if (iVar2 == -1) {
        DAT_803a6a60 = 0xffffffff;
      }
      if (iVar6 == 0) {
        uVar7 = FUN_80118e30(0);
      }
      FUN_80247054(-0x7fc58498);
    }
    puVar1[1] = iVar6;
    FUN_80244758((int *)&DAT_803a7f10,puVar1,1);
    uVar4 = uVar5 + iVar3;
    iVar3 = *(int *)*puVar1;
    uVar5 = uVar4;
    if (((iVar6 + DAT_803a6a78) - ((uint)(iVar6 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
         DAT_803a6a10 - 1) && (uVar5 = DAT_803a6a24, (DAT_803a6a5e & 1) == 0)) {
      FUN_80247054(-0x7fc58498);
      uVar5 = uVar4;
    }
    iVar6 = iVar6 + 1;
  } while( true );
}

