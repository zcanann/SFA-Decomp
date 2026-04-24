// Function: FUN_801311ec
// Entry: 801311ec
// Size: 640 bytes

void FUN_801311ec(undefined4 param_1,undefined4 param_2,undefined param_3,undefined *param_4,
                 undefined4 param_5,undefined4 param_6,undefined2 param_7,undefined2 param_8,
                 undefined2 param_9,undefined2 param_10,undefined2 param_11,undefined2 param_12)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined2 *puVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860c0();
  iVar6 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  if (iVar4 < 0x29) {
    DAT_803dd911 = (undefined)uVar8;
    DAT_803dd90e = 0xff;
    DAT_803dd910 = 0;
    DAT_803dd913 = 0;
    DAT_803dd912 = param_3;
    FUN_80003494(&DAT_803a9458,iVar6,iVar4 * 0x3c);
    puVar7 = &DAT_803a9458;
    for (iVar5 = 0; iVar5 < iVar4; iVar5 = iVar5 + 1) {
      cVar1 = *(char *)(puVar7 + 0xd);
      if ((cVar1 < -1) || (iVar4 <= cVar1)) {
        FUN_8007d6dc(s_UPLINK_overflow__d_8031c24c,(int)cVar1);
      }
      cVar1 = *(char *)((int)puVar7 + 0x1b);
      if ((cVar1 < -1) || (iVar4 <= cVar1)) {
        FUN_8007d6dc(s_DOWNLINK_overflow__d_8031c260,(int)cVar1);
      }
      cVar1 = *(char *)(puVar7 + 0xe);
      if ((cVar1 < -1) || (iVar4 <= cVar1)) {
        FUN_8007d6dc(s_LEFTLINK_overflow__d_8031c278,(int)cVar1);
      }
      cVar1 = *(char *)((int)puVar7 + 0x1d);
      if ((cVar1 < -1) || (iVar4 <= cVar1)) {
        FUN_8007d6dc(s_RIGHTLINK_overflow__d_8031c290,(int)cVar1);
      }
      if (*(int *)(iVar6 + 0x10) == -1) {
        *(undefined4 *)(puVar7 + 8) = 0;
      }
      else {
        uVar2 = FUN_80054d54();
        *(undefined4 *)(puVar7 + 8) = uVar2;
      }
      if ((puVar7[0xb] & 0x10) != 0) {
        puVar7[10] = 0;
        puVar7[4] = 0;
      }
      if ((puVar7[0xb] & 4) != 0) {
        FUN_80130144(puVar7);
      }
      iVar3 = (int)*(char *)(puVar7 + 0xe);
      if ((iVar3 != -1) && ((puVar7[0xb] & 8) != 0)) {
        puVar7[5] = (&DAT_803a9462)[iVar3 * 0x1e] + (&DAT_803a946c)[iVar3 * 0x1e];
        puVar7[2] = (&DAT_803a945c)[iVar3 * 0x1e] + (&DAT_803a946c)[iVar3 * 0x1e];
      }
      if ((puVar7[0xb] & 0x400) != 0) {
        puVar7[5] = puVar7[5] - (short)((int)(uint)(ushort)puVar7[10] >> 1);
        puVar7[2] = puVar7[5];
      }
      *(undefined *)(puVar7 + 0x1c) = 4;
      puVar7 = puVar7 + 0x1e;
      iVar6 = iVar6 + 0x3c;
    }
    DAT_803dd900 = param_9;
    DAT_803dd8fe = param_10;
    DAT_803dd8fc = param_11;
    DAT_803dd8fa = param_12;
    DAT_803dd902 = param_8;
    DAT_803dd904 = param_7;
    DAT_803dd908 = &DAT_8031c1a8;
    if (param_4 != (undefined *)0x0) {
      DAT_803dd908 = param_4;
    }
  }
  FUN_8028610c();
  return;
}

