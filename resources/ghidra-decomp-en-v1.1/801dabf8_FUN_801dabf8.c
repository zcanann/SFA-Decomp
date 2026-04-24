// Function: FUN_801dabf8
// Entry: 801dabf8
// Size: 700 bytes

/* WARNING: Removing unreachable block (ram,0x801dae8c) */
/* WARNING: Removing unreachable block (ram,0x801dac08) */

void FUN_801dabf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  int iVar6;
  char *pcVar7;
  double dVar8;
  double dVar9;
  
  pcVar7 = *(char **)(param_9 + 0xb8);
  iVar6 = *(int *)(param_9 + 0x4c);
  iVar1 = FUN_8002bac4();
  dVar8 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar1 + 0x18));
  if (*pcVar7 == '\0') {
    if ((iVar1 != 0) && (iVar2 = FUN_80296e2c(iVar1), iVar2 != 0)) {
      uVar3 = FUN_80020078(0x18b);
      if (uVar3 == 0) {
        FUN_80296454(iVar1,0);
        dVar8 = (double)FLOAT_803e6168;
        FUN_800303fc(dVar8,param_9);
        *(ushort *)(param_9 + 2) = (ushort)*(byte *)(iVar6 + 0x19) << 8;
        *(ushort *)(param_9 + 4) = (ushort)*(byte *)(iVar6 + 0x18) << 8;
        *(code **)(param_9 + 0xbc) = FUN_801da874;
        *pcVar7 = '\x01';
        uVar3 = FUN_8002e144();
        if ((uVar3 & 0xff) == 0) {
          iVar1 = 0;
        }
        else {
          puVar4 = FUN_8002becc(0x20,0x659);
          *(undefined *)(puVar4 + 2) = 2;
          *(undefined *)((int)puVar4 + 7) = 0xff;
          iVar1 = FUN_8002b678(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,puVar4);
        }
        *(int *)(pcVar7 + 0x38) = iVar1;
        *(float *)(pcVar7 + 0x70) = FLOAT_803e61a4;
      }
      else {
        FUN_801daa98(param_9,*(undefined **)(param_9 + 0xb8),0);
      }
    }
  }
  else if (*pcVar7 == '\x01') {
    dVar9 = dVar8;
    iVar1 = FUN_8003811c(param_9);
    if (iVar1 == 0) {
      if (dVar9 <= (double)FLOAT_803e61a8) {
        if ((dVar9 < (double)FLOAT_803e61ac) && (pcVar7[3] == '\0')) {
          pcVar7[3] = '\x01';
          FUN_80043070(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,8);
        }
      }
      else if (pcVar7[3] != '\0') {
        pcVar7[3] = '\0';
        FUN_80043938(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
    else {
      uVar5 = FUN_80036f50(0xf,param_9,(float *)0x0);
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar5,0xffffffff);
      *pcVar7 = '\x02';
      *(float *)(pcVar7 + 4) = FLOAT_803e6178;
      FUN_800201ac(0x18b,1);
    }
  }
  else if (pcVar7[3] != '\0') {
    pcVar7[3] = '\0';
    FUN_80043938(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_800201ac(0x3b8,1);
  }
  FUN_8011f670(0);
  *(float *)(pcVar7 + 0x6c) = FLOAT_803e6170 * FLOAT_803dc074 + *(float *)(pcVar7 + 0x6c);
  if (FLOAT_803e6168 < *(float *)(pcVar7 + 0x6c)) {
    *(float *)(pcVar7 + 0x6c) = FLOAT_803e616c;
  }
  *(float *)(pcVar7 + 0x70) = FLOAT_803e6170 * FLOAT_803dc074 + *(float *)(pcVar7 + 0x70);
  if ((FLOAT_803e6168 < *(float *)(pcVar7 + 0x70)) &&
     (*(float *)(pcVar7 + 0x70) = FLOAT_803e616c, *pcVar7 == '\x01')) {
    FUN_8000bb38(param_9,0x3fe);
  }
  return;
}

