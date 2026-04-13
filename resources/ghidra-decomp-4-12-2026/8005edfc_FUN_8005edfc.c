// Function: FUN_8005edfc
// Entry: 8005edfc
// Size: 1376 bytes

void FUN_8005edfc(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int *param_5,
                 float *param_6)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  undefined4 *puVar8;
  double dVar9;
  ulonglong uVar10;
  undefined4 local_70;
  undefined4 uStack_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  int local_50;
  float fStack_4c;
  undefined4 uStack_48;
  undefined4 auStack_44 [17];
  
  uVar10 = FUN_80286820();
  uVar5 = (uint)uVar10;
  uVar6 = param_5[4];
  uVar3 = *(undefined *)(*param_5 + ((int)uVar6 >> 3));
  iVar4 = *param_5 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_5[4] = uVar6 + 8;
  puVar8 = (undefined4 *)
           (*(int *)(param_3 + 0x68) +
           ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7)) & 0xff) * 0x1c);
  if (((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 2) == 0)) &&
     (uVar6 = FUN_8005ec20((int)puVar8,param_3,(float *)&DAT_8038859c,5,&local_54,&local_58,
                           &local_5c,&local_60,&local_64,&local_68), (uVar6 & 0xff) != 0)) {
    if ((uVar10 & 0xff00000000) == 0) {
      uVar5 = *(uint *)(param_4 + 0x3c);
      if ((uVar5 & 0x80000000) == 0) {
        if (((uVar5 & 0x40000000) != 0) || ((uVar5 & 0x2000) != 0)) {
          FUN_8005d530((int)puVar8,param_3,(uint)*(byte *)(puVar8 + 6));
          (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 4;
          DAT_803ddab0 = DAT_803ddab0 + 1;
        }
      }
      else {
        FUN_8005d530((int)puVar8,param_3,(uint)*(byte *)(puVar8 + 6));
        (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 5;
        DAT_803ddab0 = DAT_803ddab0 + 1;
      }
    }
    else {
      if (((param_4 != 0) && (uVar6 = *(uint *)(param_4 + 0x3c), (uVar6 & 0x80000000) == 0)) &&
         ((uVar6 & 0x20000) == 0)) {
        if ((param_4 == 0) || ((uVar6 & 0x80000) == 0)) {
          FUN_8001e9ec((double)(local_54 + FLOAT_803dda58),(double)local_58,
                       (double)(local_5c + FLOAT_803dda5c),(double)(local_60 + FLOAT_803dda58),
                       (double)local_64,(double)(local_68 + FLOAT_803dda5c),&DAT_803ddaa8,2,
                       &local_50);
        }
        else {
          local_50 = 0;
        }
        if ((param_4 == 0) ||
           (((*(uint *)(param_4 + 0x3c) & 0x800) == 0 && ((*(uint *)(param_4 + 0x3c) & 0x1000) == 0)
            ))) {
          piVar7 = &DAT_803ddaa8;
          for (iVar4 = 0; iVar4 < local_50; iVar4 = iVar4 + 1) {
            FUN_8001db90(*piVar7,(undefined *)&uStack_6c,(undefined *)((int)&uStack_6c + 1),
                         (undefined *)((int)&uStack_6c + 2),(undefined *)((int)&uStack_6c + 3));
            FUN_8001de14(*piVar7,&fStack_4c,&uStack_48,auStack_44);
            dVar9 = FUN_8001de0c(*piVar7);
            FUN_8004fbac(dVar9,&uStack_6c,&fStack_4c);
            piVar7 = piVar7 + 1;
          }
        }
        else {
          FUN_800889bc((undefined *)&local_70);
          local_70._3_1_ = 0;
          local_70._2_1_ = 0;
          local_70._1_1_ = 0;
          local_70._0_1_ = 0;
          if (local_50 == 0) {
            if ((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 0x800) == 0)) {
              FUN_8004f048();
            }
            else {
              FUN_8004f118(&local_70);
            }
          }
          else {
            FUN_8001db90(DAT_803ddaa8,(undefined *)&uStack_6c,(undefined *)((int)&uStack_6c + 1),
                         (undefined *)((int)&uStack_6c + 2),(undefined *)((int)&uStack_6c + 3));
            FUN_8001de14(DAT_803ddaa8,&fStack_4c,&uStack_48,auStack_44);
            dVar9 = FUN_8001de0c(DAT_803ddaa8);
            FUN_8004f854(dVar9,&uStack_6c,&fStack_4c);
            piVar7 = (int *)0x803ddaac;
            for (iVar4 = 1; iVar4 < local_50; iVar4 = iVar4 + 1) {
              FUN_8001db90(*piVar7,(undefined *)&uStack_6c,(undefined *)((int)&uStack_6c + 1),
                           (undefined *)((int)&uStack_6c + 2),(undefined *)((int)&uStack_6c + 3));
              FUN_8001de14(*piVar7,&fStack_4c,&uStack_48,auStack_44);
              dVar9 = FUN_8001de0c(*piVar7);
              FUN_8004f4fc(dVar9,&uStack_6c,&fStack_4c);
              piVar7 = piVar7 + 1;
            }
            if ((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 0x800) == 0)) {
              FUN_8004f1fc();
            }
            else {
              FUN_8004f42c();
            }
          }
        }
        if ((param_4 != 0) && ((*(uint *)(param_4 + 0x3c) & 0x2000) != 0)) {
          if ((param_4 == 0) || ((*(uint *)(param_4 + 0x3c) & 0x40000000) == 0)) {
            uVar5 = FUN_8005ec20((int)puVar8,param_3,(float *)&DAT_80388538,5,&local_54,&local_58,
                                 &local_5c,&local_60,&local_64,&local_68);
            if ((((uVar5 & 0xff) == 0) || ((uVar10 & 0xff) == 0)) &&
               (((uVar5 & 0xff) != 0 || ((uVar10 & 0xff) != 0)))) {
              uVar5 = 0;
            }
            else {
              uVar5 = 1;
            }
            if ((uVar10 & 0xff) != 0) {
              FUN_8025cce8(1,4,5,5);
              FUN_8007048c(1,3,0);
              FUN_80070434(1);
              FUN_8025c754(7,0,0,7,0);
            }
          }
          if ((uVar5 & 0xff) == 0) goto LAB_8005f344;
          FUN_8004d3ac();
        }
        FUN_80052a38();
      }
      FUN_8025d63c(*puVar8,(uint)*(ushort *)(puVar8 + 1));
      uVar5 = *(uint *)(param_4 + 0x3c);
      if (((((uVar5 & 0x4000) != 0) || ((uVar5 & 0x8000) != 0)) || ((uVar5 & 0x10000) != 0)) &&
         (uVar5 = FUN_8005e0d8(puVar8,param_6), (uVar5 & 0xff) != 0)) {
        FUN_8005d530((int)puVar8,param_3,0x17);
        (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 6;
        DAT_803ddab0 = DAT_803ddab0 + 1;
      }
    }
  }
LAB_8005f344:
  FUN_8028686c();
  return;
}

