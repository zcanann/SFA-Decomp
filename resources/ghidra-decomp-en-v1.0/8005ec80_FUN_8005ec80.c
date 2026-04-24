// Function: FUN_8005ec80
// Entry: 8005ec80
// Size: 1376 bytes

void FUN_8005ec80(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int *param_5,
                 undefined4 param_6)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  char cVar6;
  uint uVar5;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  ulonglong uVar10;
  undefined local_70;
  undefined local_6f;
  undefined local_6e;
  undefined local_6d;
  undefined uStack108;
  undefined uStack107;
  undefined uStack106;
  undefined uStack105;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  int local_50;
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [68];
  
  uVar10 = FUN_802860bc();
  uVar5 = (uint)uVar10;
  uVar7 = param_5[4];
  uVar3 = *(undefined *)(*param_5 + ((int)uVar7 >> 3));
  iVar4 = *param_5 + ((int)uVar7 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_5[4] = uVar7 + 8;
  puVar9 = (undefined4 *)
           (*(int *)(param_3 + 0x68) +
           ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar7 & 7)) & 0xff) * 0x1c);
  if (((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 2) == 0)) &&
     (cVar6 = FUN_8005eaa4(puVar9,param_3,&DAT_8038793c,5,&local_54,&local_58,&local_5c,&local_60,
                           &local_64,&local_68), cVar6 != '\0')) {
    if ((uVar10 & 0xff00000000) == 0) {
      uVar5 = *(uint *)(param_4 + 0x3c);
      if ((uVar5 & 0x80000000) == 0) {
        if (((uVar5 & 0x40000000) != 0) || ((uVar5 & 0x2000) != 0)) {
          FUN_8005d3b4(puVar9,param_3,*(undefined *)(puVar9 + 6));
          (&DAT_8037e0cc)[DAT_803dce30 * 4] = 4;
          DAT_803dce30 = DAT_803dce30 + 1;
        }
      }
      else {
        FUN_8005d3b4(puVar9,param_3,*(undefined *)(puVar9 + 6));
        (&DAT_8037e0cc)[DAT_803dce30 * 4] = 5;
        DAT_803dce30 = DAT_803dce30 + 1;
      }
    }
    else {
      if (((param_4 != 0) && (uVar7 = *(uint *)(param_4 + 0x3c), (uVar7 & 0x80000000) == 0)) &&
         ((uVar7 & 0x20000) == 0)) {
        if ((param_4 == 0) || ((uVar7 & 0x80000) == 0)) {
          FUN_8001e928((double)(local_54 + FLOAT_803dcdd8),(double)local_58,
                       (double)(local_5c + FLOAT_803dcddc),(double)(local_60 + FLOAT_803dcdd8),
                       (double)local_64,(double)(local_68 + FLOAT_803dcddc),&DAT_803dce28,2,
                       &local_50);
        }
        else {
          local_50 = 0;
        }
        if ((param_4 == 0) ||
           (((*(uint *)(param_4 + 0x3c) & 0x800) == 0 && ((*(uint *)(param_4 + 0x3c) & 0x1000) == 0)
            ))) {
          puVar8 = &DAT_803dce28;
          for (iVar4 = 0; iVar4 < local_50; iVar4 = iVar4 + 1) {
            FUN_8001dacc(*puVar8,&uStack108,&uStack107,&uStack106,&uStack105);
            FUN_8001dd50(*puVar8,auStack76,auStack72,auStack68);
            FUN_8001dd48(*puVar8);
            FUN_8004fa30(&uStack108,auStack76);
            puVar8 = puVar8 + 1;
          }
        }
        else {
          FUN_80088730(&local_70);
          local_6d = 0;
          local_6e = 0;
          local_6f = 0;
          local_70 = 0;
          if (local_50 == 0) {
            if ((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 0x800) == 0)) {
              FUN_8004eecc(&local_70);
            }
            else {
              FUN_8004ef9c(&local_70);
            }
          }
          else {
            FUN_8001dacc(DAT_803dce28,&uStack108,&uStack107,&uStack106,&uStack105);
            FUN_8001dd50(DAT_803dce28,auStack76,auStack72,auStack68);
            FUN_8001dd48(DAT_803dce28);
            FUN_8004f6d8(&uStack108,auStack76,&local_70);
            puVar8 = (undefined4 *)0x803dce2c;
            for (iVar4 = 1; iVar4 < local_50; iVar4 = iVar4 + 1) {
              FUN_8001dacc(*puVar8,&uStack108,&uStack107,&uStack106,&uStack105);
              FUN_8001dd50(*puVar8,auStack76,auStack72,auStack68);
              FUN_8001dd48(*puVar8);
              FUN_8004f380(&uStack108,auStack76);
              puVar8 = puVar8 + 1;
            }
            if ((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 0x800) == 0)) {
              FUN_8004f080();
            }
            else {
              FUN_8004f2b0();
            }
          }
        }
        if ((param_4 != 0) && ((*(uint *)(param_4 + 0x3c) & 0x2000) != 0)) {
          if ((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 0x40000000) == 0)) {
            cVar6 = FUN_8005eaa4(puVar9,param_3,&DAT_803878d8,5,&local_54,&local_58,&local_5c,
                                 &local_60,&local_64,&local_68);
            if (((cVar6 == '\0') || ((uVar10 & 0xff) == 0)) &&
               ((cVar6 != '\0' || ((uVar10 & 0xff) != 0)))) {
              uVar5 = 0;
            }
            else {
              uVar5 = 1;
            }
            if ((uVar10 & 0xff) != 0) {
              FUN_8025c584(1,4,5,5);
              FUN_80070310(1,3,0);
              FUN_800702b8(1);
              FUN_8025bff0(7,0,0,7,0);
            }
          }
          if ((uVar5 & 0xff) == 0) goto LAB_8005f1c8;
          FUN_8004d230();
        }
        FUN_800528bc();
      }
      FUN_8025ced8(*puVar9,*(undefined2 *)(puVar9 + 1));
      uVar5 = *(uint *)(param_4 + 0x3c);
      if (((((uVar5 & 0x4000) != 0) || ((uVar5 & 0x8000) != 0)) || ((uVar5 & 0x10000) != 0)) &&
         (cVar6 = FUN_8005df5c(puVar9,param_6), cVar6 != '\0')) {
        FUN_8005d3b4(puVar9,param_3,0x17);
        (&DAT_8037e0cc)[DAT_803dce30 * 4] = 6;
        DAT_803dce30 = DAT_803dce30 + 1;
      }
    }
  }
LAB_8005f1c8:
  FUN_80286108();
  return;
}

