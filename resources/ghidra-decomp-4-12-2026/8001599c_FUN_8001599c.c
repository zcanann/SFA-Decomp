// Function: FUN_8001599c
// Entry: 8001599c
// Size: 336 bytes

void FUN_8001599c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  undefined4 in_r6;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286838();
  piVar7 = (int *)uVar9;
  if (piVar7 != (int *)0x0) {
    *piVar7 = 0;
  }
  uVar8 = extraout_f1;
  FUN_8024bb7c(1);
  puVar2 = DAT_803dd5d4;
  if (DAT_803dd5d4 == (undefined4 *)0x0) {
    uVar1 = FUN_80022e00(0);
    puVar2 = (undefined4 *)FUN_80023d8c(0x3c,-0x5310113);
    FUN_80022e00(uVar1 & 0xff);
  }
  iVar3 = FUN_80249300(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (char *)((ulonglong)uVar9 >> 0x20),(int)puVar2);
  if (iVar3 == 0) {
    FUN_800238c4((uint)puVar2);
  }
  else {
    iVar3 = puVar2[0xd];
    uVar1 = iVar3 + 0x1fU & 0xffffffe0;
    uVar4 = FUN_80022e00(0);
    uVar5 = FUN_80023d8c(uVar1,0x7d7d7d7d);
    FUN_80022e00(uVar4 & 0xff);
    if (uVar5 == 0) {
      FUN_800238c4((uint)puVar2);
    }
    else {
      iVar6 = FUN_80249610(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                           uVar5,uVar1,0,in_r6,2,in_r9,in_r10);
      if (iVar6 == 0) {
        FUN_800238c4(uVar5);
        FUN_800238c4((uint)puVar2);
      }
      else if (piVar7 != (int *)0x0) {
        *piVar7 = iVar3;
      }
    }
  }
  FUN_80286884();
  return;
}

