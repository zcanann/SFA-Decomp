// Function: FUN_800e9fb8
// Entry: 800e9fb8
// Size: 356 bytes

void FUN_800e9fb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,int param_12)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined extraout_var;
  undefined8 uVar4;
  
  puVar2 = (undefined4 *)FUN_80286840();
  bVar1 = false;
  if (DAT_803de114 == 0) {
    DAT_803de114 = FUN_80023d8c(0x6ec,-0xff01);
    if (DAT_803de114 == 0) goto LAB_800ea104;
  }
  if (param_12 != 0) {
    uVar4 = FUN_800201ac(0x970,1);
    iVar3 = FUN_8002bac4();
    iVar3 = FUN_80297248(iVar3);
    if (1 < iVar3) {
      iVar3 = FUN_8002bac4();
      FUN_8029725c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,-1);
      bVar1 = true;
    }
  }
  FUN_80003494(DAT_803de114,0x803a3f08,0x6ec);
  *(undefined4 *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x684) = *puVar2;
  *(undefined4 *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x688) = puVar2[1];
  *(undefined4 *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x68c) = puVar2[2];
  *(undefined *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x690) = extraout_var;
  *(undefined *)(DAT_803de114 + (uint)DAT_803a3f28 * 0x10 + 0x691) = param_11;
  uVar4 = FUN_800201ac(0x970,0);
  if ((param_12 != 0) && (bVar1)) {
    iVar3 = FUN_8002bac4();
    FUN_8029725c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,1);
  }
LAB_800ea104:
  FUN_8028688c();
  return;
}

