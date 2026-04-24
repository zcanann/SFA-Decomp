// Function: FUN_80056dcc
// Entry: 80056dcc
// Size: 432 bytes

void FUN_80056dcc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)

{
  uint uVar1;
  undefined4 uVar2;
  short *psVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860d8();
  iVar7 = (&DAT_803822b4)[param_5];
  iVar8 = (int)((ulonglong)uVar9 >> 0x20) + (int)uVar9 * 0x10;
  iVar6 = (&DAT_803822a0)[param_5] + iVar8 * 0xc;
  FUN_80059354(param_3,param_4,iVar6,param_5);
  iVar5 = (int)*(short *)(iVar6 + 6);
  iVar6 = FUN_80044394((int)*(char *)(iVar6 + 9));
  if (iVar6 == -1) {
    *(undefined *)(iVar7 + iVar8) = 0xff;
    uVar2 = 0;
  }
  else {
    if (iVar5 < 0) {
      iVar5 = -1;
    }
    if (iVar5 < 0) {
      *(char *)(iVar7 + iVar8) = (char)iVar5;
      uVar2 = 0;
    }
    else {
      *(undefined *)(iVar7 + iVar8) = 0xff;
      iVar6 = 0;
      psVar3 = DAT_803dce94;
      for (uVar1 = (uint)DAT_803dce98; uVar1 != 0; uVar1 = uVar1 - 1) {
        if (iVar5 == *psVar3) {
          *(char *)(DAT_803dce8c + iVar6) = *(char *)(DAT_803dce8c + iVar6) + '\x01';
          *(char *)(iVar7 + iVar8) = (char)iVar6;
          uVar2 = 1;
          goto LAB_80056f64;
        }
        psVar3 = psVar3 + 1;
        iVar6 = iVar6 + 1;
      }
      puVar4 = (undefined4 *)FUN_80060a38(iVar5);
      if (puVar4 != (undefined4 *)0x0) {
        FUN_80060804();
        iVar6 = 0;
        for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(puVar4 + 0x28); iVar7 = iVar7 + 1) {
          uVar2 = FUN_800544a4(-(*(uint *)(puVar4[0x15] + iVar6) | 0x8000),0);
          *(undefined4 *)(puVar4[0x15] + iVar6) = uVar2;
          iVar6 = iVar6 + 4;
        }
        FUN_800608f4(puVar4,iVar5);
        FUN_8006071c(puVar4);
        FUN_80056cec(puVar4,iVar5,iVar8,param_5);
        uVar2 = FUN_80060b90(puVar4);
        *puVar4 = uVar2;
        FUN_80241a1c(puVar4,puVar4[2]);
      }
      uVar2 = 1;
    }
  }
LAB_80056f64:
  FUN_80286124(uVar2);
  return;
}

