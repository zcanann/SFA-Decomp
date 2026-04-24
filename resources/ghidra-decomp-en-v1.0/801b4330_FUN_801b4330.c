// Function: FUN_801b4330
// Entry: 801b4330
// Size: 1236 bytes

/* WARNING: Removing unreachable block (ram,0x801b47e4) */

void FUN_801b4330(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined uVar2;
  int iVar1;
  undefined2 *puVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  float *pfVar11;
  uint uVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f31;
  undefined8 uVar15;
  uint local_188;
  uint local_184;
  uint local_180;
  uint local_17c;
  undefined auStack376 [48];
  undefined auStack328 [48];
  undefined auStack280 [48];
  undefined auStack232 [48];
  undefined auStack184 [48];
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar15 = FUN_802860c4();
  puVar3 = (undefined2 *)((ulonglong)uVar15 >> 0x20);
  local_17c = DAT_803e4928;
  local_180 = DAT_803e8468;
  pfVar9 = *(float **)(puVar3 + 0x5c);
  iVar4 = FUN_8002b588();
  if (param_6 != '\0') {
    FUN_802573f8();
    FUN_80256978(9,1);
    FUN_80256978(0xd,1);
    FUN_8025d124(0);
    pfVar11 = pfVar9;
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(pfVar9 + 0x296); iVar10 = iVar10 + 1) {
      if (*(char *)((int)pfVar11 + 0x2f) != '\0') {
        FUN_8002b47c(puVar3,auStack184,0);
        uStack132 = (int)*(short *)(pfVar11 + 10) ^ 0x80000000;
        local_88 = 0x43300000;
        FUN_802470c8((double)(float)((DOUBLE_803e4978 *
                                     ((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e4948)) /
                                    DOUBLE_803e4980),auStack376,0x7a);
        uStack124 = FUN_8000fa70();
        uStack124 = uStack124 & 0xffff;
        local_80 = 0x43300000;
        FUN_802470c8((double)(float)((DOUBLE_803e4978 *
                                     ((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e4990)) /
                                    DOUBLE_803e4980),auStack280,0x78);
        FUN_80246eb4(auStack280,auStack376,auStack280);
        uVar5 = FUN_8000fa90();
        uStack116 = 0x10000 - (uVar5 & 0xffff) ^ 0x80000000;
        local_78 = 0x43300000;
        FUN_802470c8((double)(float)((DOUBLE_803e4978 *
                                     ((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e4948)) /
                                    DOUBLE_803e4980),auStack328,0x79);
        FUN_80246eb4(auStack328,auStack280,auStack328);
        dVar14 = (double)pfVar11[3];
        FUN_80247318(dVar14,dVar14,dVar14,auStack232);
        FUN_80246eb4(auStack232,auStack328,auStack232);
        FUN_802472e4((double)(*pfVar11 - FLOAT_803dcdd8),(double)pfVar11[1],
                     (double)(pfVar11[2] - FLOAT_803dcddc),auStack184);
        FUN_80246eb4(auStack184,auStack232,auStack184);
        uVar6 = FUN_8000f54c();
        FUN_80246eb4(uVar6,auStack184,auStack184);
        FUN_8025d0a8(auStack184,0);
        local_17c = local_17c & 0xffffff00 | (uint)*(byte *)((int)pfVar11 + 0x2e);
        uStack108 = (uint)pfVar11[5] ^ 0x80000000;
        local_70 = 0x43300000;
        uStack100 = (uint)pfVar11[4] ^ 0x80000000;
        local_68 = 0x43300000;
        local_60 = 0x43300000;
        uStack92 = uStack108;
        dVar14 = (double)FUN_80291dd8((double)((FLOAT_803e4958 *
                                               ((float)((double)CONCAT44(0x43300000,uStack108) -
                                                       DOUBLE_803e4948) -
                                               (float)((double)CONCAT44(0x43300000,uStack100) -
                                                      DOUBLE_803e4948))) /
                                              (float)((double)CONCAT44(0x43300000,uStack108) -
                                                     DOUBLE_803e4948)));
        uVar5 = (uint)(FLOAT_803ddb68 * (float)((double)FLOAT_803e4938 * dVar14));
        local_58 = (longlong)(int)uVar5;
        uVar2 = (undefined)uVar5;
        local_180 = uVar5 & 0xff | (uint)CONCAT21(CONCAT11(uVar2,uVar2),uVar2) << 8;
        uStack76 = (uint)pfVar11[4] ^ 0x80000000;
        local_50 = 0x43300000;
        uStack68 = (uint)pfVar11[5] ^ 0x80000000;
        local_48 = 0x43300000;
        FUN_801b40b8((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e4948),
                     (double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e4948),
                     *(undefined *)((int)pfVar9 + 0xa5d),&local_17c);
        puVar7 = (undefined4 *)(&DAT_803ac960)[*(byte *)((int)pfVar9 + 0xa5d)];
        iVar8 = 0;
        uVar5 = (uint)*(byte *)(pfVar11 + 0xb);
        if (uVar5 != 0) {
          if ((8 < uVar5) && (uVar12 = uVar5 - 1 >> 3, 0 < (int)(uVar5 - 8))) {
            do {
              puVar7 = *(undefined4 **)**(undefined4 **)**(undefined4 **)**(undefined4 **)*puVar7;
              iVar8 = iVar8 + 8;
              uVar12 = uVar12 - 1;
            } while (uVar12 != 0);
          }
          iVar1 = uVar5 - iVar8;
          if (iVar8 < (int)uVar5) {
            do {
              puVar7 = (undefined4 *)*puVar7;
              iVar8 = iVar8 + 1;
              iVar1 = iVar1 + -1;
            } while (iVar1 != 0);
          }
        }
        local_188 = local_180;
        local_184 = local_17c;
        FUN_80073aac(puVar7,&local_184,&local_188,iVar8);
        FUN_8025889c(0x80,2,4);
        write_volatile_4(0xcc008000,FLOAT_803e4988);
        write_volatile_4(0xcc008000,FLOAT_803e4988);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e4988);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e4988);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e4960);
        write_volatile_4(0xcc008000,FLOAT_803e492c);
      }
      pfVar11 = pfVar11 + 0xc;
    }
    if (((int)pfVar9[0x293] < (int)pfVar9[0x294]) && (*(char *)((int)pfVar9 + 0xa59) != '\0')) {
      pfVar11 = pfVar9;
      dVar14 = DOUBLE_803e4948;
      for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)((int)pfVar9 + 0xa59); iVar10 = iVar10 + 1) {
        puVar3[1] = *(undefined2 *)(pfVar11 + 0x291);
        *puVar3 = *(undefined2 *)((int)pfVar11 + 0xa46);
        local_48 = 0x43300000;
        uStack68 = (int)param_6 ^ 0x80000000U;
        FUN_8003b8f4((double)(float)((double)CONCAT44(0x43300000,(int)param_6 ^ 0x80000000U) -
                                    dVar14),puVar3,(int)uVar15,param_3,param_4,param_5);
        if (iVar10 < (int)(*(byte *)((int)pfVar9 + 0xa59) - 1)) {
          *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
        }
        pfVar11 = pfVar11 + 1;
      }
    }
  }
  FUN_8003fc60();
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286110();
  return;
}

