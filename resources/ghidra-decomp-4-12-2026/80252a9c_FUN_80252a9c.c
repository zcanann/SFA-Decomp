// Function: FUN_80252a9c
// Entry: 80252a9c
// Size: 524 bytes

undefined4
FUN_80252a9c(uint param_1,undefined4 *param_2,int param_3,undefined4 param_4,int param_5,int param_6
            )

{
  undefined4 *puVar1;
  uint uVar2;
  byte bVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined *puVar7;
  undefined4 *puVar8;
  uint uVar9;
  undefined4 local_24;
  
  FUN_80243e74();
  if (DAT_8032ee98 == 0xffffffff) {
    uVar2 = DAT_cc006438;
    DAT_cc006438 = uVar2 & 0xf000000 >> ((param_1 & 7) << 3);
    uVar2 = param_3 + 3U >> 2;
    uVar6 = 0;
    DAT_8032ee98 = param_1;
    DAT_8032eea0 = param_5;
    DAT_8032eea4 = param_4;
    DAT_8032eea8 = param_6;
    if (uVar2 != 0) {
      if (8 < uVar2) {
        uVar9 = uVar2 - 1 >> 3;
        puVar7 = &DAT_cc006400;
        puVar8 = param_2;
        if (uVar2 != 8) {
          do {
            uVar6 = uVar6 + 8;
            *(undefined4 *)(puVar7 + 0x80) = *puVar8;
            *(undefined4 *)(puVar7 + 0x84) = puVar8[1];
            *(undefined4 *)(puVar7 + 0x88) = puVar8[2];
            *(undefined4 *)(puVar7 + 0x8c) = puVar8[3];
            *(undefined4 *)(puVar7 + 0x90) = puVar8[4];
            *(undefined4 *)(puVar7 + 0x94) = puVar8[5];
            *(undefined4 *)(puVar7 + 0x98) = puVar8[6];
            puVar1 = puVar8 + 7;
            puVar8 = puVar8 + 8;
            *(undefined4 *)(puVar7 + 0x9c) = *puVar1;
            puVar7 = puVar7 + 0x20;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
        }
      }
      puVar8 = param_2 + uVar6;
      puVar7 = &DAT_cc006400 + uVar6 * 4;
      iVar4 = uVar2 - uVar6;
      if (uVar6 < uVar2) {
        do {
          uVar5 = *puVar8;
          puVar8 = puVar8 + 1;
          *(undefined4 *)(puVar7 + 0x80) = uVar5;
          puVar7 = puVar7 + 4;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    uVar2 = DAT_cc006434;
    uVar2 = uVar2 & 0x7fffffff;
    if (param_3 == 0x80) {
      param_3 = 0;
    }
    local_24._1_1_ = (byte)(uVar2 >> 0x10);
    if (param_5 == 0x80) {
      param_5 = 0;
    }
    local_24._2_1_ = (byte)(uVar2 >> 8);
    bVar3 = local_24._2_1_ & 0x80;
    local_24._3_1_ = (byte)uVar2;
    local_24 = CONCAT22(CONCAT11((param_6 != 0) << 6 | (byte)(uVar2 >> 0x18) & 0xbf | 0x80,
                                 (byte)param_3 & 0x7f | local_24._1_1_ & 0x80),
                        CONCAT11((byte)param_5 & 0x7f | bVar3,(byte)local_24));
    local_24 = CONCAT31(local_24._0_3_,(byte)(param_1 << 1) & 6 | (byte)local_24 & 0xf9) &
               0xfffffffe | 1;
    DAT_cc006434 = local_24;
    FUN_80243e9c();
    uVar5 = 1;
  }
  else {
    FUN_80243e9c();
    uVar5 = 0;
  }
  return uVar5;
}

