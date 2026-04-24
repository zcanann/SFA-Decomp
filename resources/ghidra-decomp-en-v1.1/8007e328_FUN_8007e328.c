// Function: FUN_8007e328
// Entry: 8007e328
// Size: 1144 bytes

void FUN_8007e328(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  bool bVar2;
  char cVar7;
  char cVar8;
  undefined4 uVar3;
  ushort *puVar4;
  int iVar5;
  byte bVar9;
  uint uVar6;
  undefined4 uVar10;
  int iVar11;
  int *piVar12;
  int *piVar13;
  int *in_r9;
  int *in_r10;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  uint *puVar18;
  int iVar19;
  undefined8 uVar20;
  double dVar21;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  int5 iVar22;
  undefined4 local_98;
  int local_94;
  int local_90;
  int iStack_8c;
  int iStack_88;
  uint local_84 [9];
  undefined4 local_60 [8];
  longlong local_40;
  
  cVar7 = FUN_80286820();
  iVar16 = 0;
  bVar1 = false;
  bVar2 = false;
  DAT_803ddcd8 = 0;
  cVar8 = FUN_80245ff4();
  if (((((cVar8 != '\x05') || (cVar7 == '\0')) || ((DAT_803dc360 != 2 && (DAT_803dc360 != 3)))) &&
      (DAT_803dc360 != 0xd)) && ((cVar7 == '\0' || (DAT_803dc360 != 0xc)))) {
    do {
      FUN_80020390();
      FUN_80014f6c();
      FUN_800235b0();
      FUN_8004a9e4();
      local_98 = DAT_803dc368;
      uVar3 = FUN_8006c8b8();
      piVar12 = (int *)0x200;
      piVar13 = (int *)0x0;
      FUN_80076ef4(uVar3,0,0,&local_98,0x200,0);
      if (bVar1) {
        local_60[0] = 6;
        local_60[1] = 5;
        local_84[1] = 0x327;
        local_84[2] = 0x321;
        local_84[3] = 800;
        local_84[0] = 2;
      }
      else {
        FUN_8007e08c(local_60,local_84 + 1,local_84);
      }
      iVar11 = 0x40;
      uVar3 = 0xff;
      uVar20 = FUN_80019940(0xff,0xc0,0x40,0xff);
      puVar18 = local_84;
      iVar17 = 100;
      for (iVar15 = 0; puVar18 = puVar18 + 1, iVar15 < (int)(local_84[0] + 1); iVar15 = iVar15 + 1)
      {
        puVar4 = FUN_800195a8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              *puVar18);
        if (iVar15 < 1) {
          iVar11 = 0;
        }
        else {
          iVar11 = 100;
        }
        iVar11 = iVar17 + iVar11;
        iVar19 = 0;
        for (iVar14 = 0; iVar14 < (int)(uint)puVar4[1]; iVar14 = iVar14 + 1) {
          FUN_80015e00(*(undefined4 *)(*(int *)(puVar4 + 4) + iVar19),0,0,iVar11);
          piVar12 = &iStack_88;
          piVar13 = &iStack_8c;
          in_r9 = &local_90;
          in_r10 = &local_94;
          FUN_800163fc(*(undefined4 *)(*(int *)(puVar4 + 4) + iVar19),0,0,0,piVar12,piVar13,in_r9,
                       in_r10);
          iVar5 = FUN_80019c30();
          uVar6 = local_94 - local_90;
          if ((int)uVar6 <=
              (int)(uint)*(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar5 * 8] * 0x10))
          {
            iVar5 = FUN_80019c30();
            uVar6 = (uint)*(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar5 * 8] * 0x10)
            ;
          }
          iVar11 = uVar6 + iVar11 + 5;
          iVar19 = iVar19 + 4;
        }
        if (iVar15 == iVar16) {
          dVar21 = (double)FUN_80294224();
          param_2 = (double)FLOAT_803dfc14;
          iVar11 = (int)(param_2 * dVar21 + (double)FLOAT_803dfc10);
          local_40 = (longlong)iVar11;
          uVar3 = 0xff;
          bVar9 = (byte)iVar11;
          uVar20 = FUN_80019940(bVar9,bVar9,bVar9,0xff);
        }
        else {
          iVar11 = 0xa0;
          uVar3 = 0xff;
          uVar20 = FUN_80019940(0xa0,0xa0,0xa0,0xff);
        }
        iVar17 = iVar17 + 0x14;
      }
      FUN_80019c5c(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8004a5b8('\x01');
      iVar22 = FUN_80014c98(0);
      uVar10 = (undefined4)iVar22;
      uVar20 = extraout_f1;
      if (iVar22 < 0) {
LAB_8007e608:
        if (!bVar2) {
          iVar16 = iVar16 + 1;
          bVar2 = true;
        }
      }
      else {
        iVar22 = FUN_80014bf0(0);
        uVar10 = (undefined4)iVar22;
        uVar20 = extraout_f1_00;
        if (iVar22 < 0) goto LAB_8007e608;
        iVar22 = FUN_80014c98(0);
        uVar10 = (undefined4)iVar22;
        uVar20 = extraout_f1_01;
        if (iVar22 < 0x100000000) {
          iVar22 = FUN_80014bf0(0);
          uVar10 = (undefined4)iVar22;
          uVar20 = extraout_f1_02;
          if (0xffffffff < iVar22) goto LAB_8007e648;
          bVar2 = false;
        }
        else {
LAB_8007e648:
          if (!bVar2) {
            iVar16 = iVar16 + -1;
            bVar2 = true;
          }
        }
      }
      if (iVar16 < 0) {
        iVar16 = 0;
      }
      else if ((int)(local_84[0] - 1) < iVar16) {
        iVar16 = local_84[0] - 1;
      }
      uVar6 = FUN_80014e9c(0);
      if ((uVar6 & 0x100) != 0) {
        switch(local_60[iVar16]) {
        case 0:
          bVar1 = true;
          iVar16 = 0;
          break;
        case 1:
          DAT_803dc360 = 0xd;
          DAT_803ddcd8 = 1;
          break;
        case 2:
          DAT_803dc084 = 0;
          DAT_803dc360 = 0xd;
          break;
        case 3:
          FUN_800206d8(6);
          DAT_803dc084 = 0;
          DAT_803dc360 = 0xd;
          break;
        case 4:
          FUN_8007db18(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_8007de80(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\0',uVar10,
                       iVar11,uVar3,piVar12,piVar13,(uint)in_r9,(uint)in_r10);
          if (DAT_803dc360 == 0xd) {
            DAT_803ddcd8 = 1;
          }
          break;
        case 5:
          bVar1 = false;
          iVar15 = FUN_8007d8a8();
          if (iVar15 != 0) {
            FUN_8007de80(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\0',uVar10,
                         iVar11,uVar3,piVar12,piVar13,(uint)in_r9,(uint)in_r10);
          }
          if (DAT_803dc360 == 0xd) {
            DAT_803ddcd8 = 1;
          }
          break;
        case 6:
          bVar1 = false;
          break;
        default:
          DAT_803dc360 = 0xd;
        }
      }
    } while (DAT_803dc360 != 0xd);
  }
  FUN_8028686c();
  return;
}

