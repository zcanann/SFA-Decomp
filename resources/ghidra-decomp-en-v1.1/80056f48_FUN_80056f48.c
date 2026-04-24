// Function: FUN_80056f48
// Entry: 80056f48
// Size: 432 bytes

void FUN_80056f48(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 int param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined2 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar13;
  
  uVar13 = FUN_8028683c();
  puVar7 = &DAT_80382f14;
  iVar11 = (&DAT_80382f14)[param_13];
  iVar12 = (int)((ulonglong)uVar13 >> 0x20) + (int)uVar13 * 0x10;
  puVar9 = (undefined2 *)((&DAT_80382f00)[param_13] + iVar12 * 0xc);
  iVar6 = param_13;
  uVar13 = FUN_800594d0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_11
                        ,param_12,puVar9,param_13);
  iVar8 = (int)(short)puVar9[3];
  iVar2 = FUN_80044510((int)*(char *)((int)puVar9 + 9));
  if (iVar2 == -1) {
    *(undefined *)(iVar11 + iVar12) = 0xff;
  }
  else {
    if (iVar8 < 0) {
      iVar8 = -1;
    }
    if (iVar8 < 0) {
      *(char *)(iVar11 + iVar12) = (char)iVar8;
    }
    else {
      *(undefined *)(iVar11 + iVar12) = 0xff;
      iVar2 = 0;
      psVar3 = DAT_803ddb14;
      for (uVar1 = (uint)DAT_803ddb18; uVar1 != 0; uVar1 = uVar1 - 1) {
        if (iVar8 == *psVar3) {
          *(char *)(DAT_803ddb0c + iVar2) = *(char *)(DAT_803ddb0c + iVar2) + '\x01';
          *(char *)(iVar11 + iVar12) = (char)iVar2;
          goto LAB_800570e0;
        }
        psVar3 = psVar3 + 1;
        iVar2 = iVar2 + 1;
      }
      puVar4 = (undefined4 *)
               FUN_80060bb4(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar8);
      if (puVar4 != (undefined4 *)0x0) {
        uVar13 = FUN_80060980((int)puVar4);
        iVar11 = 0;
        for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(puVar4 + 0x28); iVar10 = iVar10 + 1) {
          uVar5 = FUN_80054620(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          *(undefined4 *)(puVar4[0x15] + iVar11) = uVar5;
          iVar11 = iVar11 + 4;
          uVar13 = extraout_f1_00;
        }
        FUN_80060a70(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar4,
                     iVar8,iVar2,iVar6,puVar7,param_14,param_15,param_16);
        FUN_80060898();
        FUN_80056e68(puVar4,iVar8,iVar12,param_13);
        uVar5 = FUN_80060d0c();
        *puVar4 = uVar5;
        FUN_80242114((uint)puVar4,puVar4[2]);
      }
    }
  }
LAB_800570e0:
  FUN_80286888();
  return;
}

