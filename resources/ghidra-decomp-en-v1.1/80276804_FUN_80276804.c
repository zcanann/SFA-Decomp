// Function: FUN_80276804
// Entry: 80276804
// Size: 640 bytes

void FUN_80276804(int param_1,undefined4 *param_2)

{
  short sVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined4 uVar8;
  uint uVar9;
  uint uVar10;
  undefined8 local_30;
  undefined8 local_20;
  
  puVar7 = (undefined *)FUN_802757bc((short)((uint)*param_2 >> 8));
  if (puVar7 != (undefined *)0x0) {
    *(short *)(param_1 + 0x204) = (short)((int)(char)param_2[1] << 8);
    sVar1 = *(short *)(param_1 + 0x204);
    if (sVar1 < 0) {
      uVar4 = (uint)(short)(char)((uint)param_2[1] >> 8);
      uVar6 = uVar4 << 8;
      iVar5 = (int)uVar6 / 100 + ((int)(uVar6 | uVar4 >> 0x18) >> 0x1f);
      *(short *)(param_1 + 0x204) = sVar1 - ((short)iVar5 - (short)(iVar5 >> 0x1f));
    }
    else {
      uVar4 = (uint)(short)(char)((uint)param_2[1] >> 8);
      uVar6 = uVar4 << 8;
      iVar5 = (int)uVar6 / 100 + ((int)(uVar6 | uVar4 >> 0x18) >> 0x1f);
      *(short *)(param_1 + 0x204) = sVar1 + ((short)iVar5 - (short)(iVar5 >> 0x1f));
    }
    uVar2 = *(ushort *)(puVar7 + 8);
    uVar4 = CONCAT13(puVar7[0xf],CONCAT12(puVar7[0xe],CONCAT11(puVar7[0xd],puVar7[0xc])));
    uVar3 = *(ushort *)(puVar7 + 10);
    uVar6 = CONCAT13(puVar7[3],CONCAT12(puVar7[2],CONCAT11(puVar7[1],*puVar7)));
    uVar10 = CONCAT13(puVar7[7],CONCAT12(puVar7[6],CONCAT11(puVar7[5],puVar7[4])));
    uVar9 = CONCAT13(puVar7[0x13],CONCAT12(puVar7[0x12],CONCAT11(puVar7[0x11],puVar7[0x10])));
    if (uVar4 != 0x80000000) {
      local_20 = (double)CONCAT44(0x43300000,*(undefined4 *)(param_1 + 0x158));
      uVar6 = uVar6 + (int)(FLOAT_803e848c * (float)(local_20 - DOUBLE_803e8498) *
                           (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e84a0
                                  ));
    }
    if (uVar9 != 0x80000000) {
      local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x12f));
      uVar10 = uVar10 + (int)(FLOAT_803e8490 * (float)(local_30 - DOUBLE_803e8498) *
                             (float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) -
                                    DOUBLE_803e84a0));
    }
    *(undefined *)(param_1 + 0x1dc) = 1;
    *(undefined *)(param_1 + 0x202) = 0;
    uVar8 = FUN_8027ad70(uVar6);
    *(undefined4 *)(param_1 + 0x1f0) = uVar8;
    uVar8 = FUN_8027ad70(uVar10);
    uVar6 = (int)((uVar2 & 0xff) << 8 | (int)(uint)uVar2 >> 8) >> 2;
    *(undefined4 *)(param_1 + 500) = uVar8;
    if (0x3ff < uVar6) {
      uVar6 = 0x3ff;
    }
    *(ushort *)(param_1 + 0x1f8) = 0xc1 - (ushort)(byte)(&DAT_803303fc)[uVar6];
    *(uint *)(param_1 + 0x1fc) = (uVar3 & 0xff) << 8 | (int)(uint)uVar3 >> 8;
    FUN_8027b038((char *)(param_1 + 0x1dc));
    *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x200;
  }
  return;
}

