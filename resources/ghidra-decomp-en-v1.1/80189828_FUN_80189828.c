// Function: FUN_80189828
// Entry: 80189828
// Size: 720 bytes

/* WARNING: Removing unreachable block (ram,0x8018992c) */

void FUN_80189828(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  undefined2 *puVar4;
  float fVar5;
  char cVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar7;
  int iVar8;
  undefined8 extraout_f1;
  
  pfVar7 = *(float **)(param_9 + 0xb8);
  iVar2 = FUN_8002bac4();
  if ((pfVar7[4] == 0.0) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
    puVar4 = FUN_8002becc(0x24,0x606);
    fVar5 = (float)FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar4,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    pfVar7[4] = fVar5;
    param_1 = extraout_f1;
    if (pfVar7[4] != 0.0) {
      FUN_80037e24(param_9,(int)pfVar7[4],0);
      param_1 = FUN_8022f934((int)pfVar7[4],0xaf);
      *(ushort *)((int)pfVar7[4] + 6) = *(ushort *)((int)pfVar7[4] + 6) | 0x4000;
    }
  }
  if (pfVar7[4] != 0.0) {
    param_1 = FUN_8022f940((int)pfVar7[4]);
  }
  if ((iVar2 == 0) || (iVar2 = FUN_80297a08(iVar2), iVar2 == 0)) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
  }
  bVar1 = *(byte *)((int)pfVar7 + 0x16);
  if (bVar1 == 1) {
    iVar2 = FUN_8003811c(param_9);
    if (iVar2 != 0) {
      *(undefined *)((int)pfVar7 + 0x16) = 2;
      FUN_8011e014(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    FUN_80037c38(param_9,8,0xb4,0xf0,0xff,0x6f,pfVar7);
  }
  else if (bVar1 == 0) {
    iVar2 = FUN_8003811c(param_9);
    if (iVar2 != 0) {
      iVar8 = *(int *)(param_9 + 0x4c);
      iVar2 = FUN_80036f50(0xf,param_9,(float *)0x0);
      if ((*(char *)(param_9 + 0xac) == '\r') && (uVar3 = FUN_80020078(0xc92), uVar3 != 0)) {
        *(float *)(iVar2 + 0x10) = *(float *)(iVar2 + 0x10) + FLOAT_803e4838;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar2,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar2,0xffffffff);
      }
      FUN_800201ac((int)*(short *)(iVar8 + 0x1c),0);
    }
  }
  else if (bVar1 < 3) {
    cVar6 = FUN_8012e0e0();
    if (cVar6 == '\0') {
      *(undefined *)((int)pfVar7 + 0x16) = 1;
    }
    else {
      iVar8 = *(int *)(param_9 + 0x4c);
      iVar2 = FUN_80036f50(0xf,param_9,(float *)0x0);
      if ((*(char *)(param_9 + 0xac) == '\r') && (uVar3 = FUN_80020078(0xc92), uVar3 != 0)) {
        *(float *)(iVar2 + 0x10) = *(float *)(iVar2 + 0x10) + FLOAT_803e4838;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar2,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar2,0xffffffff);
      }
      FUN_800201ac((int)*(short *)(iVar8 + 0x1c),0);
    }
  }
  return;
}

