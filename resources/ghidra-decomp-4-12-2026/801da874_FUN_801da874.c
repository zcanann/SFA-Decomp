// Function: FUN_801da874
// Entry: 801da874
// Size: 548 bytes

void FUN_801da874(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  iVar1 = FUN_8028683c();
  puVar6 = *(undefined **)(iVar1 + 0xb8);
  iVar5 = 0;
  puVar7 = puVar6;
  uVar8 = extraout_f1;
  do {
    if (puVar6[iVar5 + 0x60] != '\0') {
      uVar2 = FUN_8002e144();
      if ((uVar2 & 0xff) == 0) {
        iVar3 = 0;
      }
      else {
        puVar4 = FUN_8002becc(0x20,0x659);
        *(undefined *)(puVar4 + 2) = 2;
        *(undefined *)((int)puVar4 + 7) = 0xff;
        iVar3 = FUN_8002b678(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             puVar4);
      }
      *(int *)(puVar7 + 0x38) = iVar3;
      puVar6[iVar5 + 0x60] = 0;
    }
    puVar7 = puVar7 + 4;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 10);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    switch(*(undefined *)(param_11 + iVar5 + 0x81)) {
    case 2:
      *puVar6 = 3;
      break;
    case 3:
      puVar6[1] = 1;
      break;
    case 4:
      puVar6[1] = 0;
      break;
    case 5:
      FUN_801daa98(iVar1,puVar6,1);
      break;
    case 6:
      *puVar6 = 4;
      break;
    case 7:
      FUN_8011f670(1);
      break;
    case 8:
      puVar6[2] = puVar6[2] | 1;
      break;
    case 9:
      puVar6[2] = puVar6[2] | 4;
      break;
    case 10:
      puVar6[2] = puVar6[2] | 0x10;
      *(float *)(puVar6 + 4) = FLOAT_803e6178;
      break;
    case 0xb:
      puVar6[2] = puVar6[2] | 0x20;
      *(float *)(puVar6 + 4) = FLOAT_803e616c;
      break;
    case 0xc:
      puVar6[2] = puVar6[2] | 0x10;
      puVar6[2] = puVar6[2] | 10;
      *(float *)(puVar6 + 4) = FLOAT_803e61a0;
    }
  }
  if (puVar6[1] != '\0') {
    (**(code **)(*DAT_803dd6e8 + 0x34))((int)*(short *)(*(int *)(iVar1 + 0x50) + 0x7e),0xa0,0x8c);
  }
  *(float *)(puVar6 + 0x6c) = FLOAT_803e6170 * FLOAT_803dc074 + *(float *)(puVar6 + 0x6c);
  if (FLOAT_803e6168 < *(float *)(puVar6 + 0x6c)) {
    *(float *)(puVar6 + 0x6c) = FLOAT_803e616c;
  }
  FUN_80286888();
  return;
}

