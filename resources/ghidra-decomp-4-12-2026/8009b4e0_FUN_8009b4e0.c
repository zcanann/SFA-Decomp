// Function: FUN_8009b4e0
// Entry: 8009b4e0
// Size: 360 bytes

void FUN_8009b4e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  short *psVar2;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  undefined *puVar7;
  uint *puVar8;
  uint *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  iVar5 = 0;
  puVar9 = &DAT_8039c9b8;
  puVar8 = &DAT_8039c878;
  puVar7 = &DAT_8039c828;
  puVar6 = &DAT_80310488;
  do {
    uVar3 = *puVar9;
    iVar4 = 0;
    do {
      if ((1 << iVar4 & *puVar8) != 0) {
        if (((&DAT_8039c140)[(uint)(*(byte *)(uVar3 + 0x8a) >> 1) * 4] != 0) &&
           ((&DAT_8039c140)[(uint)(*(byte *)(uVar3 + 0x8a) >> 1) * 4] != 0)) {
          DAT_803dded8 = 1;
          uVar10 = FUN_80054484();
          DAT_803dded8 = 0;
        }
        uVar1 = (uint)(*(byte *)(uVar3 + 0x8a) >> 1);
        psVar2 = &DAT_8039c144 + uVar1 * 8;
        if (*psVar2 == 0) {
          uVar10 = FUN_80137c30(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                s_expgfx_c__mismatch_in_add_remove_803107b0,psVar2,
                                &DAT_8039c138 + uVar1 * 4,in_r6,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          *psVar2 = *psVar2 + -1;
          if (*psVar2 == 0) {
            (&DAT_8039c140)[uVar1 * 4] = 0;
            (&DAT_8039c138)[uVar1 * 4] = 0;
          }
        }
        *(undefined2 *)(uVar3 + 0x26) = 0xffff;
        *puVar8 = *puVar8 & ~(1 << iVar4);
      }
      uVar3 = uVar3 + 0xa0;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x19);
    *puVar7 = 0;
    *puVar6 = 0xffff;
    FUN_802420e0(*puVar9,4000);
    puVar9 = puVar9 + 1;
    puVar8 = puVar8 + 1;
    puVar7 = puVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x50);
  FUN_8028687c();
  return;
}

