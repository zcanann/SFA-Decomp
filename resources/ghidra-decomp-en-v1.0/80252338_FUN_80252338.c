// Function: FUN_80252338
// Entry: 80252338
// Size: 524 bytes

/* WARNING: Could not reconcile some variable overlaps */

undefined4
FUN_80252338(uint param_1,undefined4 *param_2,int param_3,undefined4 param_4,int param_5,int param_6
            )

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined *puVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 local_24;
  
  FUN_8024377c();
  if (DAT_8032e240 == 0xffffffff) {
    uVar2 = read_volatile_4(DAT_cc006438);
    write_volatile_4(DAT_cc006438,uVar2 & 0xf000000 >> ((param_1 & 7) << 3));
    uVar2 = param_3 + 3U >> 2;
    uVar5 = 0;
    DAT_8032e240 = param_1;
    DAT_8032e248 = param_5;
    DAT_8032e24c = param_4;
    DAT_8032e250 = param_6;
    if (uVar2 != 0) {
      if (8 < uVar2) {
        uVar8 = uVar2 - 1 >> 3;
        puVar6 = &DAT_cc006400;
        puVar7 = param_2;
        if (uVar2 != 8) {
          do {
            uVar5 = uVar5 + 8;
            *(undefined4 *)(puVar6 + 0x80) = *puVar7;
            *(undefined4 *)(puVar6 + 0x84) = puVar7[1];
            *(undefined4 *)(puVar6 + 0x88) = puVar7[2];
            *(undefined4 *)(puVar6 + 0x8c) = puVar7[3];
            *(undefined4 *)(puVar6 + 0x90) = puVar7[4];
            *(undefined4 *)(puVar6 + 0x94) = puVar7[5];
            *(undefined4 *)(puVar6 + 0x98) = puVar7[6];
            puVar1 = puVar7 + 7;
            puVar7 = puVar7 + 8;
            *(undefined4 *)(puVar6 + 0x9c) = *puVar1;
            puVar6 = puVar6 + 0x20;
            uVar8 = uVar8 - 1;
          } while (uVar8 != 0);
        }
      }
      param_2 = param_2 + uVar5;
      puVar6 = &DAT_cc006400 + uVar5 * 4;
      iVar3 = uVar2 - uVar5;
      if (uVar5 < uVar2) {
        do {
          uVar4 = *param_2;
          param_2 = param_2 + 1;
          *(undefined4 *)(puVar6 + 0x80) = uVar4;
          puVar6 = puVar6 + 4;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    uVar2 = read_volatile_4(DAT_cc006434);
    uVar5 = uVar2 & 0xffffff;
    if (param_3 == 0x80) {
      param_3 = 0;
    }
    local_24._1_1_ = (byte)(uVar5 >> 0x10);
    local_24._1_3_ = CONCAT12((byte)param_3 & 0x7f | local_24._1_1_ & 0x80,(short)uVar5);
    if (param_5 == 0x80) {
      param_5 = 0;
    }
    local_24._2_1_ = (byte)((uint)local_24._1_3_ >> 8);
    local_24 = (uint)(byte)((param_6 != 0) << 6 | (byte)(uVar2 >> 0x18) & 0x3f | 0x80) << 0x18 |
               local_24._1_3_ & 0xffff0000 |
               (uint)((byte)param_5 & 0x7f | local_24._2_1_ & 0x80) << 8 |
               ((byte)(param_1 << 1) & 6 | (byte)uVar5 & 0xf9) & 0xfffffffe | 1;
    write_volatile_4(DAT_cc006434,local_24);
    FUN_802437a4();
    uVar4 = 1;
  }
  else {
    FUN_802437a4();
    uVar4 = 0;
  }
  return uVar4;
}

