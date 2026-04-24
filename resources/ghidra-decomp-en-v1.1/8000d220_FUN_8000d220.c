// Function: FUN_8000d220
// Entry: 8000d220
// Size: 860 bytes

void FUN_8000d220(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined *puVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  ushort *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  undefined8 uVar9;
  int aiStack_68 [16];
  undefined4 local_28;
  uint uStack_24;
  
  uVar9 = FUN_80286838();
  iVar2 = DAT_803dd4d4;
  puVar7 = DAT_803dd4d0;
  uVar3 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar6 = -1;
  if (uVar3 != 0x4cc) {
    uVar8 = extraout_f1;
    if (uVar3 == 0x526) {
      FUN_8000a538((int *)0xa8,0);
      FUN_8000a538((int *)0xf4,1);
    }
    uVar4 = FUN_8000a188(8);
    if (uVar4 == 0) {
      for (; iVar2 != 0; iVar2 = iVar2 + -1) {
        if (*puVar7 == uVar3) {
          iVar2 = ((int)puVar7 - (int)DAT_803dd4d0) / 0x16 +
                  ((int)puVar7 - (int)DAT_803dd4d0 >> 0x1f);
          iVar6 = (iVar2 - (iVar2 >> 0x1f)) + 1;
          break;
        }
        puVar7 = puVar7 + 0xb;
      }
      if ((iVar6 != -1) && (DAT_803dd4c9 == '\0')) {
        DAT_803dd4c9 = '\0';
        puVar5 = &DAT_803dbeb4;
        iVar2 = FUN_8000a220(aiStack_68,0x40,(int *)s__streams__802c6574,(int)(puVar7 + 3),
                             -0x7fc2414c);
        if ((iVar2 != 0) &&
           (iVar2 = FUN_80249300(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (char *)aiStack_68,-0x7fcc86d0), iVar2 != 0)) {
          if (DAT_803dd4e8 == 0) {
            DAT_803dd4c8 = '\0';
          }
          else {
            FUN_802501f4(0);
            FUN_80250220(0);
            iVar2 = FUN_8024b73c((undefined4 *)&DAT_803378a0,FUN_8000d004);
            if (iVar2 == 0) {
              FUN_8007d858();
              DAT_803dd4c8 = '\0';
            }
            DAT_803dd4f4 = 0;
            DAT_803dd4f0 = 0;
            DAT_803dd4e8 = 0;
            DAT_803dd4ec = 0;
            DAT_803dd448 = 0;
          }
          uStack_24 = (uint)puVar7[2];
          local_28 = 0x43300000;
          FLOAT_803dd4cc =
               (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df260) / FLOAT_803df254;
          if (FLOAT_803df250 == FLOAT_803dd4cc) {
            FLOAT_803dd4cc = FLOAT_803df258;
          }
          DAT_803dd4e0 = (uint)(*(int *)(&DAT_802c6538 + (uint)(*(byte *)(puVar7 + 1) >> 6) * 4) !=
                               0);
          DAT_803dd4dc = (uint)(*(int *)(&DAT_802c6538 + (*(byte *)(puVar7 + 1) >> 4 & 3) * 4) != 0)
          ;
          if ((*(byte *)(puVar7 + 1) >> 2 & 3) != 0) {
            FUN_8000b644();
          }
          if (*(char *)((int)puVar7 + 3) < '\0') {
            DAT_803dd448 = 4;
          }
          else {
            DAT_803dd448 = 0;
          }
          bVar1 = false;
          while (DAT_803dd4c8 != '\0') {
            uVar8 = FUN_80014f6c();
            FUN_80020390();
            if (bVar1) {
              FUN_800235b0();
              uVar8 = FUN_8004a9e4();
            }
            FUN_80015650(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar1) {
              FUN_80019c5c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar1 = true;
              DAT_803dd4c8 = '\0';
            }
          }
          uVar4 = (int)(((*(byte *)((int)puVar7 + 3) & 0x7f) + 1) * (uint)DAT_803dbeb3) >> 7;
          uVar3 = uVar4 & 0xff;
          DAT_803dbeb0 = (undefined)uVar4;
          DAT_803dbeb1 = DAT_803dbeb0;
          FUN_802501f4(uVar3);
          uVar8 = FUN_80250220(uVar3);
          DAT_803dd4c9 = '\x01';
          DAT_803dd4e4 = (int)uVar9;
          DAT_803dd4f0 = iVar6;
          FUN_8024983c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (undefined4 *)&DAT_80337930,0,0,FUN_8000d5fc,puVar5,in_r8,in_r9,in_r10);
          FUN_8024b7f8((undefined4 *)&DAT_80337900,0);
        }
      }
    }
  }
  FUN_80286884();
  return;
}

