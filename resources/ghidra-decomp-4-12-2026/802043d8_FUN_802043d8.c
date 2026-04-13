// Function: FUN_802043d8
// Entry: 802043d8
// Size: 380 bytes

void FUN_802043d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  uint uVar2;
  undefined2 *puVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28 [10];
  
  uVar2 = FUN_8028683c();
  iVar7 = *(int *)(uVar2 + 0x4c);
  uVar8 = extraout_f1;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    if ((((*(char *)(param_11 + iVar6 + 0x81) == '\x01') &&
         (uVar4 = FUN_80020078((int)*(char *)(iVar7 + 0x19) + 0xa29), uVar4 == 0)) &&
        (uVar4 = FUN_8002e144(), (uVar4 & 0xff) != 0)) &&
       (uVar4 = FUN_8005b60c(0x4658a,(int *)0x0,(int *)0x0,(int *)0x0,(uint *)0x0), uVar4 != 0)) {
      puVar3 = FUN_8002becc(0x38,0x539);
      uVar8 = FUN_80003494((uint)puVar3,uVar4,0x38);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(uVar2 + 0xc);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(uVar2 + 0x10);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(uVar2 + 0x14);
      *(undefined4 *)(puVar3 + 10) = 0xffffffff;
      puVar3[0xd] = 0x95;
      FUN_8002b678(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,puVar3);
    }
  }
  uVar4 = FUN_80020078((int)*(short *)(iVar7 + 0x1e));
  if ((uVar4 != 0) || (DAT_803de960 != 0)) {
    piVar5 = FUN_80037048(0x24,local_28);
    FUN_800377d0(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,uVar2,0x11,0,
                 param_14,param_15,param_16);
    while (iVar6 = local_28[0] + -1, bVar1 = local_28[0] != 0, local_28[0] = iVar6, bVar1) {
      iVar6 = *piVar5;
      piVar5 = piVar5 + 1;
      FUN_8003709c(iVar6,0x24);
    }
  }
  FUN_80286888();
  return;
}

