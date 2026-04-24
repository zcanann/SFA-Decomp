// Function: FUN_801dee90
// Entry: 801dee90
// Size: 548 bytes

void FUN_801dee90(undefined2 *param_1)

{
  bool bVar1;
  byte bVar2;
  short sVar3;
  float fVar4;
  int iVar5;
  char cVar7;
  undefined4 uVar6;
  undefined4 *puVar8;
  
  puVar8 = *(undefined4 **)(param_1 + 0x5c);
  FUN_8002b9ec();
  FUN_800200e8(0xf1d,0);
  cVar7 = (**(code **)(*DAT_803dcaac + 0x40))(0xe);
  if (cVar7 == '\x06') {
    if ((*(byte *)(puVar8 + 0xc) & 4) == 0) {
      if ((*(byte *)(puVar8 + 0xc) & 2) != 0) {
        sVar3 = *(short *)((int)puVar8 + 0x2e);
        if (sVar3 == 0) {
          *param_1 = 0xd700;
          puVar8[8] = 0xffffd700;
          puVar8[10] = puVar8[8];
          fVar4 = FLOAT_803e5678;
          puVar8[1] = FLOAT_803e5678;
          puVar8[2] = fVar4;
          *(undefined2 *)((int)puVar8 + 0x2e) = 1;
          *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xfe;
        }
        else if (sVar3 == 1) {
          FUN_800200e8(0xf1d,1);
          FUN_8011f38c(1);
          uVar6 = (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
          puVar8[9] = uVar6;
        }
        else if (sVar3 == 2) {
          *(undefined2 *)((int)puVar8 + 0x2e) = 0;
        }
        else if (sVar3 == 3) {
          *(undefined2 *)((int)puVar8 + 0x2e) = 0;
        }
      }
    }
    else {
      if (0 < (int)puVar8[9]) {
        (**(code **)(*DAT_803dca54 + 0x4c))();
        FUN_800882c8(puVar8[9]);
      }
      iVar5 = DAT_803ddc10 + -1;
      bVar1 = DAT_803ddc10 == 0;
      DAT_803ddc10 = iVar5;
      if (bVar1) {
        *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xfb;
        *(undefined4 *)(param_1 + 6) = puVar8[3];
        *(undefined4 *)(param_1 + 8) = puVar8[4];
        *(undefined4 *)(param_1 + 10) = puVar8[5];
        *puVar8 = 0;
        *param_1 = 0xd700;
        puVar8[8] = 0xffffd700;
        bVar2 = *(byte *)(puVar8 + 0xc);
        if ((bVar2 & 8) == 0) {
          if ((bVar2 & 0x10) != 0) {
            *(byte *)(puVar8 + 0xc) = bVar2 & 0xef;
            puVar8[9] = 0xffffffff;
            FUN_800200e8(0x786,1);
          }
        }
        else {
          FUN_800200e8(0x784,1);
          puVar8[9] = 0xffffffff;
          *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xfc;
          *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xf7;
        }
      }
    }
  }
  return;
}

