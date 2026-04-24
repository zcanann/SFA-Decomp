// Function: FUN_801192a8
// Entry: 801192a8
// Size: 748 bytes

/* WARNING: Removing unreachable block (ram,0x80119474) */

void FUN_801192a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar2;
  uint uVar3;
  undefined *puVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286830();
  if ((DAT_803de2e0 != 0) && (DAT_803a6a58 == 0)) {
    uVar5 = extraout_f1;
    FUN_800033a8(-0x7fc595c0,0,8);
    FUN_800033a8(-0x7fc595b8,0,0xc);
    iVar1 = FUN_80249300(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (char *)((ulonglong)uVar6 >> 0x20),-0x7fc59640);
    if (iVar1 != 0) {
      iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           &DAT_803a69c0,&DAT_803a6980,0x40,0,in_r7,in_r8,in_r9,in_r10);
      if (iVar1 < 0) {
        FUN_802493c8((int *)&DAT_803a69c0);
      }
      else {
        uVar5 = FUN_80003494(0x803a69fc,0x803a6980,0x30);
        iVar1 = FUN_80291db4((uint *)&DAT_803a69fc,(uint *)&DAT_803dc648);
        uVar3 = DAT_803a6a1c;
        if (iVar1 == 0) {
          if (DAT_803a6a00 == 0x10000) {
            iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 &DAT_803a69c0,&DAT_803a6980,0x20,DAT_803a6a1c,in_r7,in_r8,in_r9,
                                 in_r10);
            if (iVar1 < 0) {
              FUN_802493c8((int *)&DAT_803a69c0);
            }
            else {
              uVar5 = FUN_80003494(0x803a6a2c,0x803a6980,0x14);
              uVar3 = uVar3 + 0x14;
              puVar4 = &DAT_803a69c0;
              DAT_803a6a5f = 0;
              for (uVar2 = 0; uVar2 < DAT_803a6a2c; uVar2 = uVar2 + 1) {
                if (puVar4[0x70] == '\x01') {
                  iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,&DAT_803a69c0,&DAT_803a6980,0x20,uVar3,in_r7,in_r8,in_r9,
                                       in_r10);
                  if (iVar1 < 0) {
                    FUN_802493c8((int *)&DAT_803a69c0);
                    goto LAB_8011957c;
                  }
                  uVar5 = FUN_80003494(0x803a6a48,0x803a6980,0xc);
                  DAT_803a6a5f = 1;
                  uVar3 = uVar3 + 0xc;
                }
                else {
                  if (puVar4[0x70] != '\0') goto LAB_8011957c;
                  iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,&DAT_803a69c0,&DAT_803a6980,0x20,uVar3,in_r7,in_r8,in_r9,
                                       in_r10);
                  if (iVar1 < 0) {
                    FUN_802493c8((int *)&DAT_803a69c0);
                    goto LAB_8011957c;
                  }
                  uVar5 = FUN_80003494(0x803a6a40,0x803a6980,8);
                  uVar3 = uVar3 + 8;
                }
                puVar4 = puVar4 + 1;
              }
              DAT_803a6a5d = 0;
              DAT_803a6a5c = 0;
              DAT_803a6a5e = 0;
              DAT_803a6a58 = 1;
              DAT_803a6a94 = FLOAT_803e29d4;
              DAT_803a6a98 = FLOAT_803e29d4;
              DAT_803a6aa0 = 0;
              DAT_803a6a68 = (int)uVar6;
            }
          }
          else {
            FUN_802493c8((int *)&DAT_803a69c0);
          }
        }
        else {
          FUN_802493c8((int *)&DAT_803a69c0);
        }
      }
    }
  }
LAB_8011957c:
  FUN_8028687c();
  return;
}

