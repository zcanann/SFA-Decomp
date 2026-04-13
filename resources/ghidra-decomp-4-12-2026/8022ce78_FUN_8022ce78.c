// Function: FUN_8022ce78
// Entry: 8022ce78
// Size: 1592 bytes

undefined4
FUN_8022ce78(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,
            undefined4 param_10,uint param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  ushort uVar2;
  short *psVar3;
  uint uVar4;
  undefined2 *puVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 extraout_r4;
  uint uVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  
  iVar9 = *(int *)(param_9 + 0x5c);
  uVar8 = param_11;
  FUN_8000facc();
  *(undefined **)(param_11 + 0xe8) = &LAB_8022ce68;
  if ((*(byte *)(iVar9 + 0x477) & 1) == 0) {
    FUN_8022d4b0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,iVar9)
    ;
  }
  else {
    FUN_8022c9d0((uint)param_9,iVar9);
    dVar11 = (double)FUN_8022b08c(param_9,iVar9);
    if (*(int *)(iVar9 + 0x10) != 0) {
      uVar8 = 0;
      dVar11 = (double)FUN_8022f80c(*(int *)(iVar9 + 0x10),'\0','\0');
    }
    *(ushort *)(*(int *)(iVar9 + 0x418) + 6) = *(ushort *)(*(int *)(iVar9 + 0x418) + 6) | 0x4000;
    *(undefined *)(*(int *)(iVar9 + 0x418) + 0x36) = 0;
    *(ushort *)(*(int *)(iVar9 + 0x41c) + 6) = *(ushort *)(*(int *)(iVar9 + 0x41c) + 6) | 0x4000;
    *(undefined *)(*(int *)(iVar9 + 0x41c) + 0x36) = 0;
    param_9[3] = param_9[3] & 0xbfff;
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
      switch(*(undefined *)(param_11 + iVar10 + 0x81)) {
      case 1:
        uVar12 = FUN_8004312c();
        dVar11 = (double)FUN_80055464(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,0x60,'\0',uVar8,param_12,param_13,param_14,param_15,param_16)
        ;
        break;
      case 2:
        uVar12 = FUN_8004312c();
        dVar11 = (double)FUN_8022cd44(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,(int)param_9,extraout_r4,uVar8,param_12,param_13,param_14,
                                      param_15,param_16);
        break;
      case 4:
        uVar8 = 1;
        FUN_80043604(0,0,1);
        FUN_80043938(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        dVar11 = (double)FUN_8004316c();
        break;
      case 5:
        if ((*(char *)(iVar9 + 0x47b) == '\0') && (uVar4 = FUN_80020078(0xc85), uVar4 != 0)) {
          FUN_80043070(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
          uVar7 = FUN_8004832c(0xb);
          FUN_80043658(uVar7,0);
        }
        else {
          FUN_80043070(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (uint)(byte)(&DAT_803dd030)[*(byte *)(iVar9 + 0x47b)]);
          uVar7 = FUN_8004832c((uint)(byte)(&DAT_803dd030)[*(byte *)(iVar9 + 0x47b)]);
          FUN_80043658(uVar7,0);
        }
        cVar1 = *(char *)(param_9 + 0x56);
        if (cVar1 == '<') {
          FUN_800201ac(0x458,0);
          FUN_800201ac(0x47c,0);
          FUN_800201ac(0x4a3,0);
          uVar8 = 1;
          param_12 = *DAT_803dd72c;
          (**(code **)(param_12 + 0x50))(0xc,0);
          dVar11 = (double)FUN_800201ac(0xd73,0);
        }
        else if (cVar1 < '<') {
          if ((cVar1 != ':') && ('9' < cVar1)) {
            (**(code **)(*DAT_803dd72c + 0x50))(0x13,0,1);
            uVar8 = 1;
            param_12 = *DAT_803dd72c;
            dVar11 = (double)(**(code **)(param_12 + 0x50))(0x13,0x16);
          }
        }
        else if (cVar1 == '>') {
          FUN_800201ac(0x5db,0);
          (**(code **)(*DAT_803dd72c + 0x50))(2,0xf,1);
          uVar8 = 1;
          param_12 = *DAT_803dd72c;
          (**(code **)(param_12 + 0x50))(2,0x10);
          FUN_800201ac(0xe7b,0);
          dVar11 = (double)FUN_800201ac(0x9e9,0);
        }
        else if (cVar1 < '>') {
          FUN_800201ac(0x36a,0);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,0,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,1,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,5,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,10,1);
          uVar8 = 1;
          param_12 = *DAT_803dd72c;
          (**(code **)(param_12 + 0x50))(0xd,0xb);
          dVar11 = (double)FUN_800201ac(0xe05,0);
        }
        break;
      case 6:
        uVar8 = 1;
        FUN_80043604(0,0,1);
        FUN_80043070(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
        uVar7 = FUN_8004832c(0x29);
        FUN_80043658(uVar7,0);
        break;
      case 7:
        if (-1 < *(char *)(iVar9 + 0x339)) {
          iVar6 = *(int *)(param_9 + 0x5c);
          *(short *)(iVar6 + 0x47c) = *(short *)(iVar6 + 0x47c) + 200;
          uVar2 = *(ushort *)(iVar6 + 0x47c);
          if (9999 < uVar2) {
            uVar2 = 9999;
          }
          *(ushort *)(iVar6 + 0x47c) = uVar2;
        }
        uVar8 = (uint)*(byte *)(iVar9 + 0x470);
        param_12 = 2;
        FUN_801299d4(*(byte *)(iVar9 + 0x47e),(uint)*(ushort *)(iVar9 + 0x47c),uVar8,'\x02');
        break;
      case 8:
        psVar3 = FUN_8000facc();
        *(float *)(iVar9 + 0x484) = *(float *)(psVar3 + 6) - *(float *)(param_9 + 6);
        *(float *)(iVar9 + 0x488) = *(float *)(psVar3 + 8) - *(float *)(param_9 + 8);
        dVar11 = (double)*(float *)(psVar3 + 10);
        *(float *)(iVar9 + 0x48c) = (float)(dVar11 - (double)*(float *)(param_9 + 10));
        *(ushort *)(iVar9 + 0x490) = *param_9 - *psVar3;
        if (0x8000 < *(short *)(iVar9 + 0x490)) {
          *(short *)(iVar9 + 0x490) = *(short *)(iVar9 + 0x490) + 1;
        }
        if (*(short *)(iVar9 + 0x490) < -0x8000) {
          *(short *)(iVar9 + 0x490) = *(short *)(iVar9 + 0x490) + -1;
        }
        *(ushort *)(iVar9 + 0x492) = param_9[1] - psVar3[1];
        uVar8 = (uint)*(short *)(iVar9 + 0x492);
        if (0x8000 < (int)uVar8) {
          *(short *)(iVar9 + 0x492) = *(short *)(iVar9 + 0x492) + 1;
        }
        if (*(short *)(iVar9 + 0x492) < -0x8000) {
          *(short *)(iVar9 + 0x492) = *(short *)(iVar9 + 0x492) + -1;
        }
        *(ushort *)(iVar9 + 0x494) = psVar3[2] - param_9[2];
        *(undefined *)(iVar9 + 0x47f) = 1;
        break;
      case 9:
        *(undefined *)(iVar9 + 0x47f) = 0;
        break;
      case 10:
        uVar4 = FUN_8002e144();
        if ((uVar4 & 0xff) != 0) {
          puVar5 = FUN_8002becc(0x24,0x608);
          *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(param_9 + 6);
          *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(param_9 + 8);
          *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(param_9 + 10);
          *(undefined *)(puVar5 + 2) = 1;
          *(undefined *)((int)puVar5 + 5) = 1;
          iVar6 = FUN_8002b678(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               (int)param_9,puVar5);
          if (iVar6 != 0) {
            dVar11 = (double)FUN_8022fc1c(iVar6,300);
          }
        }
        break;
      case 0xb:
        *(undefined *)(iVar9 + 0x44c) = 1;
        uVar8 = (uint)*(byte *)(iVar9 + 0x43d);
        dVar11 = (double)FUN_8022be28(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,param_9,iVar9,uVar8);
        *(byte *)(iVar9 + 0x43d) = *(byte *)(iVar9 + 0x43d) ^ 1;
        break;
      case 0xc:
        uVar12 = FUN_8022c05c(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                              ,iVar9,0,1,1);
        uVar8 = 1;
        param_12 = 1;
        param_13 = 0;
        dVar11 = (double)FUN_8022c05c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,param_9,iVar9,1,1,0);
        break;
      case 0xd:
        dVar11 = (double)FUN_80125e88(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,0x13);
        break;
      case 0xe:
        dVar11 = (double)FUN_80125e88(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,0x14);
      }
    }
  }
  return 0;
}

