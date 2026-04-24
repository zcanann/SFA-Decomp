// Function: FUN_8000c4d8
// Entry: 8000c4d8
// Size: 520 bytes

void FUN_8000c4d8(undefined4 param_1,undefined4 param_2,uint param_3,int param_4)

{
  float fVar1;
  uint uVar2;
  undefined2 uVar4;
  uint uVar3;
  byte extraout_r4;
  uint *puVar5;
  uint *puVar6;
  int iVar7;
  
  uVar4 = FUN_80286840();
  uVar3 = FUN_8000a188(4);
  if (uVar3 == 0) {
    puVar5 = &DAT_80336c60;
    iVar7 = 7;
    do {
      puVar6 = puVar5;
      if (((((*puVar5 == 0xffffffff) || (puVar6 = puVar5 + 0xe, *puVar6 == 0xffffffff)) ||
           (puVar6 = puVar5 + 0x1c, *puVar6 == 0xffffffff)) ||
          ((puVar6 = puVar5 + 0x2a, *puVar6 == 0xffffffff ||
           (puVar6 = puVar5 + 0x38, *puVar6 == 0xffffffff)))) ||
         ((puVar6 = puVar5 + 0x46, *puVar6 == 0xffffffff ||
          ((puVar6 = puVar5 + 0x54, *puVar6 == 0xffffffff ||
           (puVar6 = puVar5 + 0x62, puVar5[0x62] == 0xffffffff)))))) goto LAB_8000c5f4;
      puVar5 = puVar5 + 0x70;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    puVar6 = (uint *)0x0;
LAB_8000c5f4:
    if (puVar6 != (uint *)0x0) {
      uVar3 = FUN_8027300c(uVar4,extraout_r4,param_3,0);
      if (uVar3 == 0xffffffff) {
        *puVar6 = 0xffffffff;
      }
      else {
        if ((DAT_803dd4b8 != 0) && (param_4 == 0)) {
          FUN_80272f0c(uVar3,0x5b,DAT_803dd4b8);
        }
        puVar6[6] = 0;
        *(undefined2 *)(puVar6 + 7) = 0;
        *(undefined *)((int)puVar6 + 6) = 0;
        *(undefined *)(puVar6 + 1) = 0;
        *(undefined *)((int)puVar6 + 5) = 0;
        *puVar6 = uVar3;
        fVar1 = FLOAT_803df1f0;
        puVar6[3] = (uint)FLOAT_803df1f0;
        puVar6[4] = (uint)fVar1;
        puVar6[5] = (uint)fVar1;
        *(undefined2 *)(puVar6 + 2) = uVar4;
        *(undefined *)((int)puVar6 + 7) = 100;
        puVar6[8] = (uint)FLOAT_803df210;
        puVar6[9] = (uint)FLOAT_803df214;
        *(char *)(puVar6 + 10) = (char)param_4;
        uVar3 = DAT_803dd4c0;
        DAT_803dd4c0 = DAT_803dd4c0 + (0xfffffffe < DAT_803dd4c4);
        uVar2 = DAT_803dd4c4 + 1;
        puVar6[0xd] = DAT_803dd4c4;
        DAT_803dd4c4 = uVar2;
        puVar6[0xc] = uVar3;
      }
    }
  }
  FUN_8028688c();
  return;
}

