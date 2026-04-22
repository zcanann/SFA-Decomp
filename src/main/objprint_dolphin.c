#include "ghidra_import.h"
#include "main/objprint_dolphin.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_8000e054();
extern undefined4 FUN_8000ea98();
extern undefined4 FUN_8000edcc();
extern undefined4 FUN_8000f4a0();
extern undefined4 FUN_8000f56c();
extern void* FUN_8000facc();
extern undefined4 FUN_8000fb20();
extern undefined4 FUN_80013a84();
extern undefined8 FUN_80014f6c();
extern undefined4 FUN_80015650();
extern undefined4 FUN_80019c5c();
extern undefined4 FUN_8001d8bc();
extern int FUN_8001d8dc();
extern int FUN_8001da48();
extern undefined4 FUN_8001dbb4();
extern int FUN_8001dbe0();
extern undefined4 FUN_8001dbf0();
extern undefined4 FUN_8001dd54();
extern undefined4 FUN_8001e568();
extern undefined4 FUN_8001e6cc();
extern undefined4 FUN_8001e6f8();
extern undefined4 FUN_8001e9b8();
extern undefined4 FUN_8001ed58();
extern undefined4 FUN_8001f07c();
extern undefined4 FUN_8001f448();
extern void* FUN_8001f58c();
extern undefined4 FUN_80020390();
extern undefined4 FUN_80021634();
extern int FUN_80021884();
extern undefined4 FUN_80021fac();
extern uint FUN_80022264();
extern undefined4 FUN_80022790();
extern undefined4 FUN_80022a88();
extern int FUN_80022b0c();
extern undefined4 FUN_80022de4();
extern int FUN_8002337c();
extern undefined8 FUN_800235b0();
extern undefined4 FUN_800238c4();
extern undefined4 FUN_800238f8();
extern uint FUN_80023cec();
extern undefined4 FUN_80023d80();
extern uint FUN_80023d8c();
extern undefined4 FUN_800241f8();
extern undefined4 FUN_800271c8();
extern undefined4 FUN_80027280();
extern undefined4 FUN_8002736c();
extern undefined4 FUN_800274c8();
extern undefined4 FUN_80027c04();
extern undefined4 FUN_80028438();
extern int FUN_800284e8();
extern undefined4 FUN_80028588();
extern undefined4 FUN_800285f8();
extern undefined4 FUN_80028600();
extern undefined4 FUN_80028608();
extern undefined4 FUN_8002861c();
extern undefined4 FUN_80028630();
extern undefined4 FUN_8002867c();
extern undefined4 FUN_80028c18();
extern undefined4 FUN_8002990c();
extern undefined4 FUN_80029c7c();
extern undefined4 FUN_8002b554();
extern undefined4 FUN_8002b660();
extern int FUN_8002bac4();
extern undefined4 FUN_8003bde0();
extern undefined4 FUN_8003bf30();
extern undefined4 FUN_8003c270();
extern undefined4 FUN_8003c360();
extern undefined4 FUN_8003cd14();
extern undefined8 FUN_80044548();
extern undefined8 FUN_80048350();
extern undefined4 FUN_8004a5b8();
extern undefined8 FUN_8004a9e4();
extern char FUN_8004c3c4();
extern int FUN_8004c3cc();
extern undefined4 FUN_8004c460();
extern undefined4 FUN_8004c4ac();
extern undefined4 FUN_8004d3ac();
extern undefined4 FUN_8004d730();
extern undefined4 FUN_8004d854();
extern undefined4 FUN_8004daa4();
extern undefined4 FUN_8004e974();
extern undefined4 FUN_80050298();
extern undefined4 FUN_800506d4();
extern undefined4 FUN_80050ba4();
extern uint FUN_80050c54();
extern undefined4 FUN_80050fa4();
extern undefined4 FUN_800510a8();
extern undefined4 FUN_80051170();
extern undefined4 FUN_8005126c();
extern undefined4 FUN_800514c4();
extern undefined4 FUN_800519e4();
extern undefined4 FUN_80051c7c();
extern undefined4 FUN_80051ed8();
extern undefined4 FUN_80052134();
extern undefined4 FUN_8005254c();
extern undefined4 FUN_80052668();
extern undefined4 FUN_800527b4();
extern undefined4 FUN_800528e0();
extern undefined4 FUN_80052a38();
extern undefined4 FUN_80052a6c();
extern uint FUN_8005383c();
extern undefined4 FUN_8005387c();
extern uint FUN_80054dac();
extern undefined4 FUN_8006c63c();
extern undefined4 FUN_8006c76c();
extern int FUN_8006ff74();
extern undefined4 FUN_80070434();
extern undefined4 FUN_8007048c();
extern undefined4 FUN_80070540();
extern undefined4 FUN_80070658();
extern undefined4 FUN_80072f78();
extern undefined4 FUN_80076ef4();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_80089ab8();
extern undefined4 FUN_80089ba8();
extern undefined4 FUN_80089bfc();
extern undefined4 FUN_801184e8();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_802493c8();
extern int FUN_8024ba84();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_802585d8();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a454();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d63c();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d848();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined8 FUN_80286818();
extern undefined8 FUN_80286820();
extern int FUN_80286828();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286864();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_802c22ec;
extern byte DAT_802cbaa8;
extern undefined4 DAT_802cbab1;
extern byte DAT_802cbab4;
extern undefined4 DAT_802cbabd;
extern undefined4 DAT_802cbac0;
extern int DAT_802cc8a8;
extern undefined4 DAT_802cc9d4;
extern undefined4 DAT_80343a70;
extern undefined4 DAT_80346c04;
extern undefined4 DAT_80346c08;
extern undefined4 DAT_80346c38;
extern undefined4 DAT_80346c3c;
extern undefined4 DAT_80346c50;
extern undefined4 DAT_80346c54;
extern undefined4 DAT_80346c5c;
extern undefined4 DAT_80346c60;
extern undefined4 DAT_80346c64;
extern undefined4 DAT_80346c68;
extern undefined4 DAT_80346c78;
extern undefined4 DAT_80346c7c;
extern undefined4 DAT_80346c8c;
extern undefined4 DAT_80346c90;
extern undefined4 DAT_80346ce4;
extern undefined4 DAT_80346ce8;
extern undefined4 DAT_80346cec;
extern undefined4 DAT_80346cf0;
extern undefined4 DAT_80346cf4;
extern undefined4 DAT_80346cf8;
extern undefined4 DAT_80346cfc;
extern undefined4 DAT_80346d00;
extern undefined4 DAT_80346d04;
extern undefined4 DAT_80346d08;
extern undefined4 DAT_80346d1c;
extern undefined4 DAT_80346d20;
extern undefined4 DAT_80346d24;
extern undefined4 DAT_80346d28;
extern undefined DAT_80346d30;
extern undefined DAT_8034ec70;
extern undefined DAT_80350c70;
extern undefined DAT_80352c70;
extern undefined DAT_80356c70;
extern undefined DAT_8035ac70;
extern undefined DAT_8035db50;
extern undefined DAT_8035fb50;
extern undefined4 DAT_8035fba8;
extern undefined4 DAT_8035fbdc;
extern undefined4 DAT_8035fc14;
extern undefined4 DAT_8035fc28;
extern undefined4 DAT_8035fc34;
extern undefined4 DAT_8035fc3c;
extern undefined4 DAT_8035fc54;
extern undefined4 DAT_8035fc68;
extern undefined4 DAT_8035fcc0;
extern undefined4 DAT_8035fcc4;
extern undefined4 DAT_8035fcd0;
extern undefined4 DAT_8035fcd4;
extern undefined4 DAT_8035fcdc;
extern undefined4 DAT_8035fcf8;
extern undefined4 DAT_8035fcfc;
extern int DAT_8035fd08;
extern undefined4 DAT_8035fe68;
extern uint DAT_80360048;
extern undefined4 DAT_803600d8;
extern undefined4 DAT_80360180;
extern undefined* DAT_80360188;
extern short DAT_803601a8;
extern undefined4 DAT_803601f2;
extern undefined4 DAT_80360236;
extern undefined4 DAT_80397450;
extern undefined4 DAT_803dc0c8;
extern undefined4 DAT_803dc0cc;
extern undefined4 DAT_803dc0d0;
extern undefined4 DAT_803dc0d4;
extern undefined4 DAT_803dc0d8;
extern undefined4 DAT_803dc0d9;
extern undefined4 DAT_803dc0dc;
extern undefined4 DAT_803dc0e0;
extern undefined4 DAT_803dc0e1;
extern undefined4 DAT_803dc0e2;
extern undefined4 DAT_803dc0e4;
extern undefined4 DAT_803dc0e8;
extern undefined4 DAT_803dc210;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803dd8a0;
extern undefined4 DAT_803dd8a4;
extern undefined4 DAT_803dd8a8;
extern undefined4 DAT_803dd8a9;
extern undefined4 DAT_803dd8aa;
extern undefined4 DAT_803dd8ac;
extern undefined4 DAT_803dd8b0;
extern undefined4 DAT_803dd8b4;
extern undefined4 DAT_803dd8b5;
extern undefined4 DAT_803dd8bc;
extern undefined4 DAT_803dd8bd;
extern undefined4 DAT_803dd8be;
extern undefined4 DAT_803dd8c0;
extern undefined4 DAT_803dd8c4;
extern undefined4 DAT_803dd8c8;
extern undefined4 DAT_803dd8cc;
extern undefined4 DAT_803dd8d4;
extern undefined4 DAT_803dd8d8;
extern undefined4 DAT_803dd8dc;
extern byte DAT_803dd8e0;
extern int DAT_803dd8e4;
extern undefined4 DAT_803dd8f0;
extern undefined4 DAT_803dd8f4;
extern undefined4 DAT_803dd8f8;
extern undefined4 DAT_803dd900;
extern undefined4 DAT_803dd904;
extern undefined4 DAT_803dd908;
extern undefined4 DAT_803dd90c;
extern undefined4 DAT_803dd914;
extern undefined4 DAT_803df670;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803df6c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dd8b8;
extern f32 FLOAT_803dd8d0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803df684;
extern f32 FLOAT_803df69c;
extern f32 FLOAT_803df6b4;
extern f32 FLOAT_803df6b8;
extern f32 FLOAT_803df6c8;
extern f32 FLOAT_803df6cc;
extern f32 FLOAT_803df6d0;
extern f32 FLOAT_803df6d4;
extern f32 FLOAT_803df6d8;
extern f32 FLOAT_803df6dc;
extern f32 FLOAT_803df6e0;
extern f32 FLOAT_803df6e4;
extern f32 FLOAT_803df6e8;
extern f32 FLOAT_803df6ec;
extern int iRam803dc214;
extern undefined4 uRam803dc214;
extern undefined uRam803dd8d9;
extern undefined2 uRam803dd8da;

/*
 * --INFO--
 *
 * Function: FUN_8003d7f0
 * EN v1.0 Address: 0x8003D7F0
 * EN v1.0 Size: 648b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003d7f0(int param_1)
{
  int *piVar1;
  double dVar2;
  uint local_58;
  undefined4 local_54;
  uint local_50;
  uint local_4c;
  undefined4 uStack_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  float afStack_38 [12];
  
  local_3c = DAT_803df670;
  piVar1 = FUN_8001f58c(param_1,'\0');
  if (piVar1 != (int *)0x0) {
    FUN_8001dbf0((int)piVar1,4);
    FUN_8001dd54((double)FLOAT_803df684,(double)FLOAT_803df6b4,(double)FLOAT_803df684,piVar1);
    FUN_8001dbb4((int)piVar1,0xff,0xff,0xff,0xff);
    FUN_8001e9b8(0);
    FUN_8001e6cc(2,0,0);
    local_4c = DAT_803dc0d0;
    FUN_8025a2ec(2,&local_4c);
    local_50 = DAT_803dc0c8;
    FUN_8025a454(2,&local_50);
    FUN_8001e568(2,piVar1,param_1);
    FUN_8001e6f8();
    FUN_8001f448((uint)piVar1);
  }
  local_54 = local_3c;
  FUN_8025c510(0,(byte *)&local_54);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c584(0,0xc);
  FUN_8006c63c(&local_40,&local_44,&uStack_48);
  FUN_8004c460(*(int *)(local_40 + ((DAT_803dd8c4 >> 2) + (uint)DAT_803dd8bd * local_44) * 4),0);
  FUN_80247a7c((double)FLOAT_803df6b8,(double)FLOAT_803df6b8,(double)FLOAT_803df69c,afStack_38);
  FUN_8025d8c4(afStack_38,0x40,0);
  FUN_80258674(1,1,4,0x3c,1,0x40);
  FUN_8025be80(0);
  FUN_8025c828(0,1,0,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c224(0,7,4,5,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,3,1,0);
  FUN_8025ca04(1);
  FUN_8025be54(0);
  FUN_80258944(2);
  FUN_80259288(2);
  local_58 = DAT_803dc0c8;
  dVar2 = (double)FLOAT_803df684;
  FUN_8025ca38(dVar2,dVar2,dVar2,dVar2,0,(uint3 *)&local_58);
  FUN_8007048c(1,3,0);
  FUN_80070434(1);
  FUN_8025cce8(1,4,5,5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003da78
 * EN v1.0 Address: 0x8003DA78
 * EN v1.0 Size: 720b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003da78(ushort *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8003dd48
 * EN v1.0 Address: 0x8003DD48
 * EN v1.0 Size: 1040b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003dd48(void)
{
  byte bVar1;
  ushort uVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  int *piVar10;
  byte *pbVar11;
  int iVar12;
  undefined8 uVar13;
  uint local_68;
  uint local_64;
  uint local_60;
  uint local_5c;
  uint local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  undefined4 local_44;
  int local_40;
  undefined4 local_3c [15];
  
  uVar13 = FUN_80286840();
  iVar12 = (int)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  local_40 = 0;
  DAT_803dd8dc = 0;
  bVar1 = *(byte *)(iVar12 + 0x24);
  if ((bVar1 & 0x10) == 0) {
    iVar8 = 0;
  }
  else {
    iVar8 = 4;
  }
  if ((*(ushort *)(iVar12 + 0xe2) & 2) == 0) {
    FUN_8001e9b8(0);
    FUN_8001e6cc(iVar8,0,(uint)((bVar1 & 2) != 0));
    uVar2 = *(ushort *)(iVar12 + 0xe2);
    if ((uVar2 & 9) == 0) {
      if ((uVar2 & 0xc) == 0) {
        uVar6 = 6;
        uVar5 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x8d);
        if (uVar5 == 0) {
          FUN_80089bfc((uint)*(byte *)(iVar4 + 0xf2));
          FUN_80089ba8((uint)*(byte *)(iVar4 + 0xf2),(undefined *)&local_44,
                       (undefined *)((int)&local_44 + 1),(undefined *)((int)&local_44 + 2));
        }
        else {
          FUN_8001f07c(uVar5,(undefined *)&local_44,(undefined *)((int)&local_44 + 1),
                       (undefined *)((int)&local_44 + 2));
        }
        local_44 = local_44 & 0xffffff00;
        local_50 = local_44;
        FUN_8025a2ec(iVar8,&local_50);
      }
      else {
        uVar6 = 2;
        local_4c = DAT_803dc0cc;
        FUN_8025a2ec(iVar8,&local_4c);
      }
      uVar5 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x8c);
      if (uVar5 != 0) {
        FUN_8001ed58(iVar4,local_3c,uVar5,&local_40,uVar6);
      }
      if (local_40 == 0) {
        local_54 = DAT_803dc0cc;
        FUN_8025a454(iVar8,&local_54);
      }
      else {
        local_58 = DAT_803dc0c8;
        FUN_8025a454(iVar8,&local_58);
      }
      puVar9 = local_3c;
      for (iVar7 = 0; iVar7 < local_40; iVar7 = iVar7 + 1) {
        FUN_8001e568(iVar8,*puVar9,iVar4);
        puVar9 = puVar9 + 1;
      }
    }
    else if ((uVar2 & 1) == 0) {
      local_60 = DAT_803dc0cc;
      FUN_8025a454(iVar8,&local_60);
    }
    else {
      local_5c = DAT_803dc0c8;
      FUN_8025a454(iVar8,&local_5c);
    }
    if (*(byte *)(iVar12 + 0xfa) != 0) {
      FUN_8001ed58(iVar4,&DAT_803dd8e4,(uint)*(byte *)(iVar12 + 0xfa),&DAT_803dd8dc,8);
      if (((*(byte *)(*(int *)(iVar4 + 0x50) + 0x5f) & 4) != 0) || (DAT_803dd8cc != '\0')) {
        DAT_803dd8dc = 0;
      }
      bVar3 = false;
      piVar10 = &DAT_803dd8e4;
      pbVar11 = &DAT_803dd8e0;
      for (iVar12 = 0; iVar12 < DAT_803dd8dc; iVar12 = iVar12 + 1) {
        iVar8 = FUN_8001dbe0(*piVar10);
        if ((bVar3) || (iVar8 != 1)) {
          if (iVar12 == 0) {
            *pbVar11 = 2;
          }
          else {
            *pbVar11 = 3;
          }
        }
        else {
          *pbVar11 = 1;
          bVar3 = true;
        }
        FUN_8001e6cc((uint)*pbVar11,2,0);
        FUN_8001e568((uint)*pbVar11,*piVar10,iVar4);
        local_64 = DAT_803dc0d0;
        FUN_8025a2ec((uint)*pbVar11,&local_64);
        local_68 = DAT_803dc0c8;
        FUN_8025a454((uint)*pbVar11,&local_68);
        piVar10 = piVar10 + 1;
        pbVar11 = pbVar11 + 1;
      }
    }
    FUN_8001e6f8();
    bVar1 = *(byte *)(*(int *)(iVar4 + 0x50) + 0x5f);
    if (((bVar1 & 4) == 0) && (DAT_803dd8cc == '\0')) {
      if ((bVar1 & 0x11) != 0) {
        DAT_803dd8dc = 1;
      }
    }
    else {
      DAT_803dd8dc = 2;
    }
  }
  else if (((bVar1 & 2) == 0) && ((bVar1 & 0x10) == 0)) {
    FUN_8025a608(4,0,0,0,0,0,2);
    FUN_8025a608(5,0,0,0,0,0,2);
    FUN_8025a5bc(0);
  }
  else {
    DAT_803dd8d4 = DAT_803dd8d4 & 0xffffff00;
    local_48 = DAT_803dd8d4;
    FUN_8025a2ec(iVar8,&local_48);
    FUN_8025a608(0,1,0,1,0,0,2);
    FUN_8025a608(2,0,0,1,0,0,2);
    FUN_8025a5bc(1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003e158
 * EN v1.0 Address: 0x8003E158
 * EN v1.0 Size: 392b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e158(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4)
{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined uVar7;
  undefined uVar8;
  int iVar9;
  float *pfVar10;
  uint uVar11;
  uint uVar12;
  undefined *puVar13;
  float *pfVar14;
  int iVar15;
  byte *pbVar16;
  undefined8 uVar17;
  float afStack_58 [22];
  
  uVar17 = FUN_80286834();
  iVar15 = (int)((ulonglong)uVar17 >> 0x20);
  iVar9 = FUN_80022b0c();
  if (DAT_803dd8c8 == 1) {
    pfVar10 = (float *)FUN_80022b0c();
    bVar1 = *(byte *)(iVar15 + 0xf3);
    bVar2 = *(byte *)(iVar15 + 0xf4);
    pfVar14 = pfVar10 + 0x9c0;
    FUN_80022a88(0);
    for (iVar15 = 0; iVar15 < (int)((uint)bVar1 + (uint)bVar2); iVar15 = iVar15 + 1) {
      FUN_80247618(param_4,pfVar14,pfVar10);
      pfVar14 = pfVar14 + 0x10;
      pfVar10 = pfVar10 + 0xc;
    }
    DAT_803dd8c8 = 2;
  }
  uVar12 = param_3[4];
  uVar8 = *(undefined *)(*param_3 + ((int)uVar12 >> 3));
  iVar15 = *param_3 + ((int)uVar12 >> 3);
  uVar3 = *(undefined *)(iVar15 + 1);
  uVar4 = *(undefined *)(iVar15 + 2);
  param_3[4] = uVar12 + 4;
  pbVar16 = &DAT_802cbaa8;
  for (iVar15 = 0;
      iVar15 < (int)((uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar8)) >> (uVar12 & 7)) & 0xf);
      iVar15 = iVar15 + 1) {
    uVar11 = param_3[4];
    puVar13 = (undefined *)(*param_3 + ((int)uVar11 >> 3));
    uVar5 = *puVar13;
    uVar6 = puVar13[1];
    uVar7 = puVar13[2];
    param_3[4] = uVar11 + 8;
    uVar11 = (uint3)(CONCAT12(uVar7,CONCAT11(uVar6,uVar5)) >> (uVar11 & 7)) & 0xff;
    if (DAT_803dd8c8 == 2) {
      FUN_8025d80c((float *)(iVar9 + uVar11 * 0x30),(uint)*pbVar16);
    }
    else {
      pfVar10 = (float *)FUN_80028630((int *)uVar17,uVar11);
      FUN_80247618(param_4,pfVar10,afStack_58);
      FUN_8025d80c(afStack_58,(uint)*pbVar16);
    }
    pbVar16 = pbVar16 + 1;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003e2e0
 * EN v1.0 Address: 0x8003E2E0
 * EN v1.0 Size: 684b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e2e0(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4,float *param_5,
                 uint param_6,uint param_7,uint param_8)
{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  uint uVar9;
  uint uVar10;
  undefined *puVar11;
  float *pfVar12;
  byte *pbVar13;
  byte *pbVar14;
  undefined8 uVar15;
  float afStack_68 [3];
  float local_5c;
  float local_4c;
  float local_3c;
  
  uVar15 = FUN_80286820();
  iVar7 = (int)((ulonglong)uVar15 >> 0x20);
  pbVar14 = &DAT_802cbaa8;
  iVar6 = FUN_80022b0c();
  if (DAT_803dd8c8 == 1) {
    if ((param_8 & 0xff) == 0) {
      FUN_8003bf30(iVar7,(int *)uVar15,param_5,param_4);
    }
    else {
      pfVar8 = (float *)FUN_80022b0c();
      bVar1 = *(byte *)(iVar7 + 0xf3);
      bVar2 = *(byte *)(iVar7 + 0xf4);
      pfVar12 = pfVar8 + 0x9c0;
      FUN_80022a88(0);
      for (iVar7 = 0; iVar7 < (int)((uint)bVar1 + (uint)bVar2); iVar7 = iVar7 + 1) {
        FUN_80247618(param_5,pfVar12,pfVar8);
        pfVar12 = pfVar12 + 0x10;
        pfVar8 = pfVar8 + 0xc;
      }
      DAT_803dd8c8 = 2;
    }
  }
  uVar10 = param_3[4];
  uVar5 = *(undefined *)(*param_3 + ((int)uVar10 >> 3));
  iVar7 = *param_3 + ((int)uVar10 >> 3);
  uVar3 = *(undefined *)(iVar7 + 1);
  uVar4 = *(undefined *)(iVar7 + 2);
  param_3[4] = uVar10 + 4;
  uVar10 = (uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar5)) >> (uVar10 & 7)) & 0xf;
  if (0x14 < uVar10) {
    FUN_8007d858();
  }
  pbVar13 = &DAT_802cbab4;
  for (iVar7 = 0; iVar7 < (int)uVar10; iVar7 = iVar7 + 1) {
    uVar9 = param_3[4];
    puVar11 = (undefined *)(*param_3 + ((int)uVar9 >> 3));
    uVar3 = *puVar11;
    uVar4 = puVar11[1];
    uVar5 = puVar11[2];
    param_3[4] = uVar9 + 8;
    uVar9 = (uint3)(CONCAT12(uVar5,CONCAT11(uVar4,uVar3)) >> (uVar9 & 7)) & 0xff;
    if (DAT_803dd8c8 == 2) {
      pfVar8 = (float *)(iVar6 + uVar9 * 0x30);
      pfVar12 = pfVar8 + 0x4b0;
      FUN_8025d80c(pfVar8,(uint)*pbVar14);
      if (((param_8 & 0xff) == 0) && ((param_7 & 0xff) != 0)) {
        FUN_8025d8c4(pfVar12,(uint)*pbVar13,0);
      }
      if (((param_8 & 0xff) == 0) && ((param_6 & 0xff) != 0)) {
        FUN_8025d848(pfVar12,(uint)*pbVar14);
      }
    }
    else {
      pfVar8 = (float *)FUN_80028630((int *)uVar15,uVar9);
      FUN_80247618(param_5,pfVar8,afStack_68);
      FUN_8025d80c(afStack_68,(uint)*pbVar14);
      if (((param_8 & 0xff) == 0) && (((param_6 & 0xff) != 0 || ((param_7 & 0xff) != 0)))) {
        local_5c = FLOAT_803df684;
        local_4c = FLOAT_803df684;
        local_3c = FLOAT_803df684;
        FUN_80247618(afStack_68,param_4,afStack_68);
        if ((param_7 & 0xff) != 0) {
          FUN_8025d8c4(afStack_68,(uint)*pbVar13,0);
        }
        if ((param_6 & 0xff) != 0) {
          FUN_8025d848(afStack_68,(uint)*pbVar14);
        }
      }
    }
    pbVar14 = pbVar14 + 1;
    pbVar13 = pbVar13 + 1;
  }
  FUN_8028686c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003e58c
 * EN v1.0 Address: 0x8003E58C
 * EN v1.0 Size: 360b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e58c(int param_1,undefined4 param_2,int *param_3)
{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  uVar7 = (uint)(1 < *(byte *)(param_1 + 0xf3));
  uVar5 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar5 >> 3));
  iVar4 = *param_3 + ((int)uVar5 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar5 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar5 & 7) & 1) == 0) {
    uVar5 = 0;
  }
  else {
    uVar5 = 2;
  }
  uVar6 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar6 >> 3));
  iVar4 = *param_3 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar6 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7) & 1) == 0) {
    uVar6 = 0;
  }
  else {
    uVar6 = 4;
  }
  uVar8 = uVar7 | uVar5 | uVar6;
  if (DAT_803dc0d4 != uVar8) {
    FUN_80257b5c();
    if (uVar7 == 0) {
      FUN_8025d888((uint)DAT_802cbaa8);
    }
    else {
      FUN_802570dc(0,1);
    }
    if (uVar5 == 0) {
      uVar5 = 2;
    }
    else {
      uVar5 = 3;
    }
    FUN_802570dc(9,uVar5);
    if (uVar6 == 0) {
      uVar5 = 2;
    }
    else {
      uVar5 = 3;
    }
    FUN_802570dc(0xd,uVar5);
    DAT_803dc0d4 = uVar8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003e6f4
 * EN v1.0 Address: 0x8003E6F4
 * EN v1.0 Size: 912b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e6f4(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,uint param_5,
                 undefined *param_6,undefined *param_7)
{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  bool bVar4;
  uint3 uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  undefined8 uVar14;
  int local_38;
  undefined4 auStack_34 [13];
  
  uVar14 = FUN_8028682c();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  iVar7 = (int)uVar14;
  FUN_80257b5c();
  if (*(byte *)(iVar6 + 0xf3) < 2) {
    FUN_8025d888(0);
    *param_7 = 1;
  }
  else {
    FUN_802570dc(0,1);
    iVar12 = 1;
    if ((*param_3 != 0) || (param_3[1] != 0)) {
      iVar13 = iVar12;
      if (*(int *)(iVar7 + 0x34) != 0) {
        FUN_802570dc(1,1);
        iVar13 = 3;
        FUN_802570dc(2,1);
      }
      iVar12 = iVar13 + 1;
      FUN_802570dc(iVar13,1);
    }
    iVar13 = 8;
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(iVar6 + 0xfa); iVar10 = iVar10 + 1) {
      if (((param_5 & 0xff) == 4) && (iVar10 == 0)) {
        if ((DAT_803dd8dc == 0) || (FUN_8001d8bc(DAT_803dd8e4,&local_38,auStack_34), local_38 != 0))
        {
          bVar4 = false;
        }
        else {
          bVar4 = true;
        }
      }
      else if ((iVar10 < DAT_803dd8dc) && ((param_5 & 0xff) == 0)) {
        bVar4 = true;
      }
      else {
        bVar4 = false;
      }
      if (bVar4) {
        FUN_802570dc(iVar12,1);
        iVar11 = iVar13;
        iVar12 = iVar12 + 1;
      }
      else {
        iVar11 = iVar13 + -1;
        FUN_802570dc(iVar13,1);
      }
      iVar13 = iVar11;
    }
    if (iVar12 < 2) {
      *param_7 = 0;
    }
    else {
      *param_7 = 1;
    }
  }
  uVar9 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
  iVar12 = *param_4 + ((int)uVar9 >> 3);
  uVar1 = *(undefined *)(iVar12 + 1);
  uVar2 = *(undefined *)(iVar12 + 2);
  param_4[4] = uVar9 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7) & 1) == 0) {
    uVar9 = 2;
  }
  else {
    uVar9 = 3;
  }
  FUN_802570dc(9,uVar9);
  if ((*(byte *)(iVar7 + 0x40) & 1) == 0) {
    *param_6 = 0;
  }
  else {
    uVar9 = param_4[4];
    uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
    iVar12 = *param_4 + ((int)uVar9 >> 3);
    uVar1 = *(undefined *)(iVar12 + 1);
    uVar2 = *(undefined *)(iVar12 + 2);
    param_4[4] = uVar9 + 1;
    uVar5 = CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7);
    if ((*(byte *)(iVar6 + 0x24) & 8) == 0) {
      if ((uVar5 & 1) == 0) {
        uVar9 = 2;
      }
      else {
        uVar9 = 3;
      }
      FUN_802570dc(10,uVar9);
    }
    else {
      if ((uVar5 & 1) == 0) {
        uVar9 = 2;
      }
      else {
        uVar9 = 3;
      }
      FUN_802570dc(0x19,uVar9);
    }
    *param_6 = 1;
  }
  if ((*(byte *)(iVar7 + 0x40) & 2) != 0) {
    uVar9 = param_4[4];
    uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
    iVar6 = *param_4 + ((int)uVar9 >> 3);
    uVar1 = *(undefined *)(iVar6 + 1);
    uVar2 = *(undefined *)(iVar6 + 2);
    param_4[4] = uVar9 + 1;
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7) & 1) == 0) {
      uVar9 = 2;
    }
    else {
      uVar9 = 3;
    }
    FUN_802570dc(0xb,uVar9);
  }
  uVar9 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
  iVar6 = *param_4 + ((int)uVar9 >> 3);
  uVar1 = *(undefined *)(iVar6 + 1);
  uVar2 = *(undefined *)(iVar6 + 2);
  param_4[4] = uVar9 + 1;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar7 + 0x41); iVar6 = iVar6 + 1) {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7) & 1) == 0) {
      uVar8 = 2;
    }
    else {
      uVar8 = 3;
    }
    FUN_802570dc(iVar6 + 0xd,uVar8);
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003ea84
 * EN v1.0 Address: 0x8003EA84
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003ea84(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5,
                 int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8003eeec
 * EN v1.0 Address: 0x8003EEEC
 * EN v1.0 Size: 1976b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003eeec(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8003f6a4
 * EN v1.0 Address: 0x8003F6A4
 * EN v1.0 Size: 584b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003f6a4(undefined4 param_1,undefined4 param_2,int param_3)
{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char cVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  iVar2 = (int)uVar8;
  if ((*(char *)((int)((ulonglong)uVar8 >> 0x20) + 0x37) == -1) &&
     ((*(uint *)(param_3 + 0x3c) & 0x40000000) == 0)) {
    if ((*(uint *)(param_3 + 0x3c) & 0x400) == 0) {
      cVar7 = '\0';
      bVar1 = (*(ushort *)(iVar2 + 2) & 0x400) == 0;
      uVar6 = (uint)bVar1;
      uVar5 = (uint)bVar1;
      uVar4 = 1;
      uVar3 = 0;
    }
    else {
      cVar7 = '\0';
      bVar1 = (*(ushort *)(iVar2 + 2) & 0x400) == 0;
      uVar6 = (uint)bVar1;
      uVar5 = (uint)bVar1;
      uVar4 = 0;
      uVar3 = 0x40;
    }
  }
  else {
    cVar7 = '\x01';
    if ((*(ushort *)(iVar2 + 2) & 0x400) == 0) {
      if ((*(ushort *)(iVar2 + 2) & 0x2000) == 0) {
        uVar6 = 1;
        uVar5 = 0;
        uVar4 = 1;
        uVar3 = 0;
      }
      else {
        uVar6 = 1;
        uVar5 = 1;
        uVar4 = 0;
        uVar3 = 0xdf;
      }
    }
    else {
      uVar6 = 0;
      uVar5 = 0;
      uVar4 = 1;
      uVar3 = 0;
    }
  }
  bVar1 = (*(uint *)(param_3 + 0x3c) & 8) != 0;
  if (DAT_803dc0d8 != cVar7) {
    if (cVar7 == '\0') {
      FUN_8025cce8(0,1,0,5);
      DAT_803dc0d8 = cVar7;
    }
    else {
      FUN_8025cce8(1,4,5,5);
      DAT_803dc0d8 = cVar7;
    }
  }
  if ((DAT_803dc0e0 != uVar6) || (DAT_803dc0e1 != uVar5)) {
    FUN_8007048c(uVar6,3,uVar5);
    DAT_803dc0e0 = (byte)uVar6;
    DAT_803dc0e1 = (byte)uVar5;
  }
  if (DAT_803dc0d9 != uVar4) {
    FUN_80070434(uVar4);
    DAT_803dc0d9 = (byte)uVar4;
  }
  if (DAT_803dc0dc != uVar3) {
    DAT_803dc0dc = uVar3;
    if (uVar3 == 0) {
      FUN_8025c754(7,0,0,7,0);
    }
    else {
      FUN_8025c754(4,uVar3,0,4,uVar3);
    }
  }
  if (bVar1 != (bool)DAT_803dc0e2) {
    DAT_803dc0e2 = bVar1;
    if (bVar1) {
      FUN_80259288(2);
    }
    else {
      FUN_80259288(0);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003f8ec
 * EN v1.0 Address: 0x8003F8EC
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003f8ec(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8003fd58
 * EN v1.0 Address: 0x8003FD58
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003fd58(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8003fda8
 * EN v1.0 Address: 0x8003FDA8
 * EN v1.0 Size: 1808b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003fda8(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800404b8
 * EN v1.0 Address: 0x800404B8
 * EN v1.0 Size: 3160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800404b8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80041110
 * EN v1.0 Address: 0x80041110
 * EN v1.0 Size: 236b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041110(void)
{
  ushort *puVar1;
  int *piVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  float *pfVar7;
  short *psVar8;
  
  puVar1 = (ushort *)FUN_80286838();
  psVar6 = *(short **)(*(int *)(puVar1 + 0x28) + 0x40);
  pfVar7 = *(float **)(puVar1 + 0x3a);
  if ((*(byte *)((int)puVar1 + 0xaf) & 0x28) == 0) {
    piVar2 = (int *)FUN_8002b660((int)puVar1);
    psVar8 = psVar6;
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x72); iVar5 = iVar5 + 1)
    {
      iVar4 = (int)*(char *)((int)psVar8 + *(char *)((int)puVar1 + 0xad) + 0x12);
      if (iVar4 < 0) {
        pfVar3 = (float *)0x0;
      }
      else {
        pfVar3 = (float *)FUN_80028630(piVar2,iVar4);
      }
      FUN_800411fc((float *)0x0,pfVar7 + 3,psVar8 + 3,*(byte *)(psVar6 + 8) & 0x10,puVar1,0);
      FUN_800411fc(pfVar3,pfVar7,psVar8,*(byte *)(psVar6 + 8) & 0x10,puVar1,1);
      psVar8 = psVar8 + 0xc;
      pfVar7 = pfVar7 + 6;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800411fc
 * EN v1.0 Address: 0x800411FC
 * EN v1.0 Size: 436b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800411fc(float *param_1,float *param_2,short *param_3,int param_4,ushort *param_5,
                 int param_6)
{
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  ushort local_80;
  ushort local_7e;
  ushort local_7c;
  float local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float afStack_68 [16];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  uStack_24 = (int)*param_3 ^ 0x80000000;
  local_28 = 0x43300000;
  local_8c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df6c0);
  uStack_1c = (int)param_3[1] ^ 0x80000000;
  local_20 = 0x43300000;
  local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df6c0);
  uStack_14 = (int)param_3[2] ^ 0x80000000;
  local_18 = 0x43300000;
  local_84 = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df6c0);
  if (param_6 != 0) {
    local_8c = local_8c * FLOAT_803df6d8;
    local_88 = local_88 * FLOAT_803df6d8;
    local_84 = local_84 * FLOAT_803df6d8;
  }
  if (param_1 == (float *)0x0) {
    local_74 = *(undefined4 *)(param_5 + 0xc);
    local_70 = *(undefined4 *)(param_5 + 0xe);
    local_6c = *(undefined4 *)(param_5 + 0x10);
    if (param_4 == 0) {
      local_80 = *param_5;
      local_7e = param_5[1];
      local_7c = param_5[2];
    }
    else {
      local_80 = 0;
      local_7e = 0;
      local_7c = 0;
    }
    local_78 = FLOAT_803df69c;
    FUN_80021fac(afStack_68,&local_80);
    FUN_80022790((double)local_8c,(double)local_88,(double)local_84,afStack_68,param_2,param_2 + 1,
                 param_2 + 2);
  }
  else {
    if (param_4 == 0) {
      FUN_80247bf8(param_1,&local_8c,&local_98);
      *param_2 = local_98;
      param_2[1] = local_94;
      param_2[2] = local_90;
    }
    else {
      *param_2 = param_1[3] + local_8c;
      param_2[1] = param_1[7] + local_88;
      param_2[2] = param_1[0xb] + local_84;
    }
    *param_2 = *param_2 + FLOAT_803dda58;
    param_2[2] = param_2[2] + FLOAT_803dda5c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800413b0
 * EN v1.0 Address: 0x800413B0
 * EN v1.0 Size: 28b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800413b0(undefined param_1,undefined param_2,undefined param_3)
{
  DAT_803dd8a8 = 1;
  DAT_803dd8d8 = param_1;
  uRam803dd8d9 = param_2;
  uRam803dd8da = param_3;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800413cc
 * EN v1.0 Address: 0x800413CC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800413cc(undefined4 param_1)
{
  DAT_803dd8a4 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800413d4
 * EN v1.0 Address: 0x800413D4
 * EN v1.0 Size: 248b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800413d4(int param_1)
{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  
  DAT_803dd8c0 = 1;
  piVar2 = (int *)FUN_8002b660(param_1);
  uVar1 = DAT_803dd8a4;
  DAT_803dd8bd = (undefined)(int)FLOAT_803dd8b8;
  FUN_80028600((int)piVar2,FUN_8003c360);
  for (DAT_803dd8c4 = 0; DAT_803dd8c4 < 0x10; DAT_803dd8c4 = DAT_803dd8c4 + DAT_803dd8c0) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    FUN_800404b8(param_1,iVar3,*piVar2,8);
    DAT_803dd8a4 = uVar1;
  }
  DAT_803dd8a4 = 0;
  FUN_80028600((int)piVar2,0);
  FLOAT_803dd8b8 = FLOAT_803dd8b8 + FLOAT_803dc074;
  if (FLOAT_803df6e0 < FLOAT_803dd8b8) {
    FLOAT_803dd8b8 = FLOAT_803dd8b8 - FLOAT_803df6dc;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800414cc
 * EN v1.0 Address: 0x800414CC
 * EN v1.0 Size: 224b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800414cc(int param_1)
{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  
  DAT_803dd8c0 = 4;
  piVar2 = (int *)FUN_8002b660(param_1);
  uVar1 = DAT_803dd8a4;
  DAT_803dd8bd = (undefined)(int)FLOAT_803dd8b8;
  for (DAT_803dd8c4 = 0; DAT_803dd8c4 < 0x10; DAT_803dd8c4 = DAT_803dd8c4 + DAT_803dd8c0) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    DAT_803dd8a4 = uVar1;
    FUN_800404b8(param_1,iVar3,*piVar2,2);
  }
  DAT_803dd8a4 = 0;
  FLOAT_803dd8b8 = FLOAT_803dd8b8 + FLOAT_803dc074;
  if (FLOAT_803df6e0 < FLOAT_803dd8b8) {
    FLOAT_803dd8b8 = FLOAT_803dd8b8 - FLOAT_803df6dc;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800415ac
 * EN v1.0 Address: 0x800415AC
 * EN v1.0 Size: 572b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800415ac(int param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  undefined2 *puVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  
  puVar6 = FUN_8000facc();
  if (((((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0) && (*(char *)(param_1 + 0xac) != '?')) &&
      (*(short *)(param_1 + 0x46) != 0x882)) && (*(short *)(param_1 + 0x46) != 0x887)) {
    bVar5 = false;
    iVar9 = 3;
  }
  else {
    bVar5 = true;
    if (((*(short *)(param_1 + 0x44) == 1) || (sVar1 = *(short *)(param_1 + 0x46), sVar1 == 0x77d))
       || ((sVar1 == 0x882 || (sVar1 == 0x887)))) {
      iVar9 = 0xf;
    }
    else {
      iVar9 = 7;
    }
  }
  if (DAT_803dd8a4 == 0) {
    fVar2 = *(float *)(param_1 + 0x18) - *(float *)(puVar6 + 6);
    fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(puVar6 + 8);
    fVar4 = *(float *)(param_1 + 0x20) - *(float *)(puVar6 + 10);
  }
  else {
    fVar2 = *(float *)(DAT_803dd8a4 + 0xc) - (*(float *)(puVar6 + 6) - FLOAT_803dda58);
    fVar3 = *(float *)(DAT_803dd8a4 + 0x1c) - *(float *)(puVar6 + 8);
    fVar4 = *(float *)(DAT_803dd8a4 + 0x2c) - (*(float *)(puVar6 + 10) - FLOAT_803dda5c);
  }
  dVar11 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
  if (bVar5) {
    fVar2 = (float)((double)FLOAT_803df6e8 * dVar11) /
            (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8));
    DAT_803dd8c0 = 1;
  }
  else {
    fVar2 = (FLOAT_803df6e4 * (float)((double)FLOAT_803df6e8 * dVar11)) /
            (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8));
    DAT_803dd8c0 = 2;
  }
  iVar10 = 0x10 - (int)fVar2;
  if (0 < iVar10) {
    if (iVar9 < iVar10) {
      iVar10 = iVar9;
    }
    piVar7 = (int *)FUN_8002b660(param_1);
    iVar9 = DAT_803dd8a4;
    FUN_80028600((int)piVar7,FUN_8003cd14);
    for (DAT_803dd8c4 = 0; DAT_803dd8c4 < iVar10; DAT_803dd8c4 = DAT_803dd8c4 + 1) {
      iVar8 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar8 = *(int *)(param_1 + 0xc4);
      }
      FUN_800404b8(param_1,iVar8,*piVar7,4);
      DAT_803dd8a4 = iVar9;
    }
    DAT_803dd8a4 = 0;
    FUN_80028600((int)piVar7,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800417e8
 * EN v1.0 Address: 0x800417E8
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800417e8(int param_1)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (FLOAT_803df684 == *(float *)(param_1 + 8)) {
    DAT_803dd8a4 = 0;
  }
  else {
    piVar1 = (int *)FUN_8002b660(param_1);
    iVar2 = *piVar1;
    if (*(char *)(iVar2 + 0xf6) == '\0') {
      FUN_800404b8(param_1,param_1,iVar2,1);
    }
    else {
      FUN_8003fda8(param_1,param_1,iVar2);
    }
    if (*(short *)(param_1 + 0x44) == 1) {
      iVar2 = param_1;
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar3 = iVar3 + 1) {
        if (*(int *)(iVar2 + 200) != 0) {
          FUN_800418b8(*(int *)(iVar2 + 200),param_1,1);
        }
        iVar2 = iVar2 + 4;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800418b8
 * EN v1.0 Address: 0x800418B8
 * EN v1.0 Size: 772b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800418b8(undefined4 param_1,undefined4 param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80041bbc
 * EN v1.0 Address: 0x80041BBC
 * EN v1.0 Size: 612b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041bbc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80041e20
 * EN v1.0 Address: 0x80041E20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041e20(undefined param_1)
{
  DAT_803dd8a9 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80041e28
 * EN v1.0 Address: 0x80041E28
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041e28(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    DAT_803dd908 = DAT_803dd908 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80041e90
 * EN v1.0 Address: 0x80041E90
 * EN v1.0 Size: 140b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80041e90(int param_1)
{
  int iVar1;
  
  if (param_1 == 0) {
    iVar1 = -1;
  }
  else {
    iVar1 = FUN_8024ba84(param_1);
    switch(iVar1) {
    case 0:
      break;
    case 1:
      break;
    case 2:
      break;
    case 3:
      break;
    case 4:
      break;
    case 5:
      break;
    case 6:
      break;
    case 7:
      break;
    case 8:
      break;
    case 9:
      break;
    case 10:
      break;
    case 0xb:
      break;
    case -1:
      break;
    default:
      iVar1 = 0;
    }
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80041f1c
 * EN v1.0 Address: 0x80041F1C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041f1c(void)
{
  DAT_803dd8f0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80041f28
 * EN v1.0 Address: 0x80041F28
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041f28(void)
{
  DAT_803dd8f0 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80041f34
 * EN v1.0 Address: 0x80041F34
 * EN v1.0 Size: 1028b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041f34(void)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  uint *puVar7;
  short *psVar8;
  int *piVar9;
  undefined *puVar10;
  int iVar11;
  
  iVar2 = FUN_80286828();
  bVar1 = false;
  iVar11 = 0;
  FUN_80023d80(2);
  FUN_80243e74();
  iVar6 = DAT_803dd900;
  FUN_80243e9c();
  if (iVar6 == 0) {
    if ((iVar2 == 0) && (DAT_803dd8f8 == 0)) {
      FUN_8005387c();
      DAT_803dd8f8 = 6;
    }
    else {
      if (iVar2 != 0) {
        FUN_80022de4(1);
        iVar6 = 0;
        puVar7 = &DAT_80360048;
        psVar8 = &DAT_803601a8;
        piVar9 = &DAT_8035fd08;
        puVar10 = &DAT_8035fb50;
        do {
          switch(iVar6) {
          case 0xd:
          case 0x1b:
          case 0x23:
          case 0x25:
          case 0x2b:
          case 0x30:
          case 0x46:
          case 0x47:
          case 0x4a:
          case 0x4d:
          case 0x54:
          case 0x55:
            if (((((*puVar7 != 0) && (*psVar8 != -1)) && (iVar3 = FUN_8002337c(*puVar7), iVar3 == 0)
                 ) && ((iVar2 != 2 ||
                       (((iVar6 != 0x20 && (iVar6 != 0x4b)) && ((iVar6 != 0x23 && (iVar6 != 0x4d))))
                       )))) && (uVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d), uVar4 != 0)) {
              FUN_80003494(uVar4,*puVar7,*piVar9);
              uVar5 = FUN_800238f8(0);
              FUN_800238c4(*puVar7);
              *puVar7 = 0;
              *puVar7 = uVar4;
              FUN_800238f8(uVar5);
            }
          }
          *puVar10 = 0;
          puVar7 = puVar7 + 1;
          psVar8 = psVar8 + 1;
          piVar9 = piVar9 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
        FUN_80022de4(0xffffffff);
      }
      for (; (!bVar1 && (iVar11 < 10)); iVar11 = iVar11 + 1) {
        bVar1 = true;
        iVar6 = 0;
        puVar7 = &DAT_80360048;
        psVar8 = &DAT_803601a8;
        piVar9 = &DAT_8035fd08;
        puVar10 = &DAT_8035fb50;
        do {
          switch(iVar6) {
          case 0xd:
          case 0x1b:
          case 0x23:
          case 0x25:
          case 0x2b:
          case 0x30:
          case 0x46:
          case 0x47:
          case 0x4a:
          case 0x4d:
          case 0x54:
          case 0x55:
            if (((*puVar7 == 0) || (*psVar8 == -1)) || (iVar3 = FUN_8002337c(*puVar7), iVar3 != 0))
            {
              if (((((iVar2 != 2) && (iVar11 != 0)) && ((*puVar7 != 0 && (*psVar8 != -1)))) &&
                  ((iVar3 = FUN_8002337c(*puVar7), iVar3 == 1 ||
                   (iVar3 = FUN_8002337c(*puVar7), iVar3 == 2)))) &&
                 ((uVar4 = FUN_80023cec(*puVar7), 0x2fff < (int)uVar4 &&
                  (uVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d), uVar4 != 0)))) {
                iVar3 = FUN_8002337c(uVar4);
                if (iVar3 == 0) {
                  FUN_80003494(uVar4,*puVar7,*piVar9);
                  uVar5 = FUN_800238f8(0);
                  FUN_800238c4(*puVar7);
                  *puVar7 = 0;
                  *puVar7 = uVar4;
                  FUN_800238f8(uVar5);
                  bVar1 = false;
                }
                else {
                  uVar5 = FUN_800238f8(0);
                  FUN_800238c4(uVar4);
                  FUN_800238f8(uVar5);
                }
              }
            }
            else {
              uVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d);
              if (uVar4 != 0) {
                iVar3 = *piVar9;
                if ((iVar3 < 210000) || (uVar4 <= *puVar7)) {
                  if ((iVar3 < 210000) && (uVar4 < *puVar7)) {
                    uVar5 = FUN_800238f8(0);
                    FUN_800238c4(uVar4);
                    FUN_800238f8(uVar5);
                  }
                  else {
                    FUN_80003494(uVar4,*puVar7,iVar3);
                    uVar5 = FUN_800238f8(0);
                    FUN_800238c4(*puVar7);
                    *puVar7 = 0;
                    *puVar7 = uVar4;
                    FUN_800238f8(uVar5);
                    bVar1 = false;
                  }
                }
                else {
                  uVar5 = FUN_800238f8(0);
                  FUN_800238c4(uVar4);
                  FUN_800238f8(uVar5);
                }
              }
            }
          }
          *puVar10 = 0;
          puVar7 = puVar7 + 1;
          psVar8 = psVar8 + 1;
          piVar9 = piVar9 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
      }
      FUN_80023d80(0);
    }
  }
  FUN_80286874();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042338
 * EN v1.0 Address: 0x80042338
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042338(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x10000000) == 0) {
      if ((DAT_803dd900 & 0x40000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x40000000;
        DAT_80346d24 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x10000000;
      DAT_80346c04 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800423f0
 * EN v1.0 Address: 0x800423F0
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800423f0(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x20000000) == 0) {
      if ((DAT_803dd900 & 0x80000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x80000000;
        DAT_80346d28 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x20000000;
      DAT_80346c08 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800424a8
 * EN v1.0 Address: 0x800424A8
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800424a8(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x1000000) == 0) {
      if ((DAT_803dd900 & 0x4000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x4000000;
        DAT_80346d20 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x1000000;
      DAT_80346c3c = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042560
 * EN v1.0 Address: 0x80042560
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042560(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x2000000) == 0) {
      if ((DAT_803dd900 & 0x8000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x8000000;
        DAT_80346d1c = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x2000000;
      DAT_80346c38 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042618
 * EN v1.0 Address: 0x80042618
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042618(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x20000) == 0) {
      if ((DAT_803dd900 & 0x80000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x80000;
        DAT_80346cf0 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x20000;
      DAT_80346c68 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800426d0
 * EN v1.0 Address: 0x800426D0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800426d0(int param_1,int *param_2)
{
  DAT_803dd8f4 = 0;
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042734
 * EN v1.0 Address: 0x80042734
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042734(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x10000) == 0) {
      if ((DAT_803dd900 & 0x40000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x40000;
        DAT_80346cec = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x10000;
      DAT_80346c64 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800427ec
 * EN v1.0 Address: 0x800427EC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800427ec(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    FUN_800238c4(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x8000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x8000;
      DAT_80346d00 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x8000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x8000;
      DAT_80346d00 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800428b8
 * EN v1.0 Address: 0x800428B8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800428b8(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    FUN_800238c4(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x4000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x4000;
      DAT_80346c54 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x4000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x4000;
      DAT_80346c54 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042984
 * EN v1.0 Address: 0x80042984
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042984(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x1000) == 0) {
      if ((DAT_803dd900 & 0x2000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x2000;
        DAT_80346cfc = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x1000;
      DAT_80346c50 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042a3c
 * EN v1.0 Address: 0x80042A3C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042a3c(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    FUN_800238c4(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x800) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x800;
      DAT_80346d08 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x800) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x800;
      DAT_80346d08 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042b08
 * EN v1.0 Address: 0x80042B08
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042b08(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    FUN_800238c4(DAT_803600d8);
    DAT_803600d8 = 0;
    DAT_80346c60 = 0;
    if ((DAT_803dd900 & 0x400) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x400;
      DAT_80346c60 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x400) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x400;
      DAT_80346c60 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042bd4
 * EN v1.0 Address: 0x80042BD4
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042bd4(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x100) == 0) {
      if ((DAT_803dd900 & 0x200) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x200;
        DAT_80346d04 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x100;
      DAT_80346c5c = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042c8c
 * EN v1.0 Address: 0x80042C8C
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042c8c(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x10) == 0) {
      if ((DAT_803dd900 & 0x20) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x20;
        DAT_80346cf8 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x10;
      DAT_80346c90 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042d44
 * EN v1.0 Address: 0x80042D44
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042d44(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 1) == 0) {
      if ((DAT_803dd900 & 2) != 0) {
        DAT_803dd904 = DAT_803dd904 | 2;
        DAT_80346ce8 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 1;
      DAT_80346c7c = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042dfc
 * EN v1.0 Address: 0x80042DFC
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042dfc(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x40) == 0) {
      if ((DAT_803dd900 & 0x80) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x80;
        DAT_80346cf4 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x40;
      DAT_80346c8c = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042eb4
 * EN v1.0 Address: 0x80042EB4
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042eb4(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 4) == 0) {
      if ((DAT_803dd900 & 8) != 0) {
        DAT_803dd904 = DAT_803dd904 | 8;
        DAT_80346ce4 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 4;
      DAT_80346c78 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042f6c
 * EN v1.0 Address: 0x80042F6C
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042f6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  undefined8 extraout_f1;
  undefined8 uVar2;
  
  if (*(short *)(&DAT_802cc9d4 + param_9 * 2) != -1) {
    iVar1 = (**(code **)(*DAT_803dd72c + 0x90))();
    *(char *)(iVar1 + 0xe) = (char)param_9;
    param_1 = extraout_f1;
  }
  uVar2 = FUN_80044548(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80043070
 * EN v1.0 Address: 0x80043070
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80043070(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_9 < 0x4b) {
    iVar3 = (&DAT_802cc8a8)[param_9];
  }
  else {
    iVar3 = 5;
  }
  iVar2 = (int)*(short *)(&DAT_802cc9d4 + iVar3 * 2);
  if (iVar2 != -1) {
    if (DAT_803601f2 == iVar2) {
      iVar1 = 0;
    }
    else if (DAT_80360236 == iVar2) {
      iVar1 = 1;
    }
    else {
      iVar1 = -1;
    }
    if (iVar1 == -1) {
      FUN_80042f6c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2);
      return iVar2;
    }
  }
  FUN_80042f6c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_8004312c
 * EN v1.0 Address: 0x8004312C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004312c(void)
{
  FUN_80243e74();
  if ((DAT_803dd900 & 0x100000) != 0) {
    DAT_803dd900 = DAT_803dd900 ^ 0x100000;
  }
  FUN_80243e9c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004316c
 * EN v1.0 Address: 0x8004316C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004316c(void)
{
  FUN_80243e74();
  DAT_803dd900 = DAT_803dd900 | 0x100000;
  FUN_80243e9c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004319c
 * EN v1.0 Address: 0x8004319C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004319c(void)
{
  return DAT_803dd8f4;
}

/*
 * --INFO--
 *
 * Function: FUN_800431a4
 * EN v1.0 Address: 0x800431A4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800431a4(void)
{
  undefined4 uVar1;
  
  FUN_80243e74();
  uVar1 = DAT_803dd900;
  FUN_80243e9c();
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800431d8
 * EN v1.0 Address: 0x800431D8
 * EN v1.0 Size: 1068b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800431d8(void)
{
  uint uVar1;
  
  FUN_80243e74();
  FUN_80243e74();
  uVar1 = DAT_803dd900;
  FUN_80243e9c();
  if ((((DAT_803dd914 & 4) != 0) && ((uVar1 & 4) == 0)) && (DAT_8035fc54 == -1)) {
    FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
  }
  if ((((DAT_803dd914 & 8) != 0) && ((uVar1 & 8) == 0)) && (DAT_8035fcc0 == -1)) {
    FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
  }
  if ((((DAT_803dd914 & 0x40) != 0) && ((uVar1 & 0x40) == 0)) && (DAT_8035fc68 == -1)) {
    FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
  }
  if ((((DAT_803dd914 & 0x80) != 0) && ((uVar1 & 0x80) == 0)) && (DAT_8035fcd0 == -1)) {
    FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
  }
  if ((((DAT_803dd914 & 0x400) != 0) && ((uVar1 & 0x400) == 0)) && (DAT_8035fc34 == -1)) {
    FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
  }
  if ((((DAT_803dd914 & 0x800) != 0) && ((uVar1 & 0x800) == 0)) && (DAT_8035fcdc == -1)) {
    FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
  }
  if ((((DAT_803dd914 & 0x4000) != 0) && ((uVar1 & 0x4000) == 0)) && (DAT_8035fc28 == -1)) {
    FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
  }
  if ((((DAT_803dd914 & 0x8000) != 0) && ((uVar1 & 0x8000) == 0)) && (DAT_8035fcd4 == -1)) {
    FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
  }
  if ((((DAT_803dd914 & 0x20000) != 0) && ((uVar1 & 0x20000) == 0)) && (DAT_8035fc3c == -1)) {
    FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
  }
  if ((((DAT_803dd914 & 0x80000) != 0) && ((uVar1 & 0x80000) == 0)) && (DAT_8035fcc4 == -1)) {
    FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
  }
  if ((((DAT_803dd914 & 0x2000000) != 0) && ((uVar1 & 0x2000000) == 0)) && (DAT_8035fc14 == -1)) {
    FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
  }
  if ((((DAT_803dd914 & 0x8000000) != 0) && ((uVar1 & 0x8000000) == 0)) && (DAT_8035fcf8 == -1)) {
    FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
  }
  if ((((DAT_803dd914 & 0x20000000) != 0) && ((uVar1 & 0x20000000) == 0)) && (DAT_8035fbdc == -1)) {
    FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
  }
  if ((((DAT_803dd914 & 0x80000000) != 0) && ((uVar1 & 0x80000000) == 0)) && (DAT_8035fcfc == -1)) {
    FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
  }
  DAT_803dd914 = uVar1;
  DAT_803dd900 = DAT_803dd900 ^ DAT_803dd904;
  DAT_803dd904 = 0;
  FUN_80243e9c();
  return DAT_803dd900;
}

/*
 * --INFO--
 *
 * Function: FUN_80043604
 * EN v1.0 Address: 0x80043604
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80043604(int param_1,int param_2,int param_3)
{
  int iVar1;
  
  if (param_3 == 1) {
    DAT_803dc210 = 0xfffffffe;
    uRam803dc214 = 0xfffffffe;
    return -1;
  }
  iVar1 = (&DAT_803dc210)[param_2];
  if ((param_1 != iVar1) && (iVar1 != -2)) {
    return iVar1;
  }
  (&DAT_803dc210)[param_2] = 0xfffffffe;
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_80043658
 * EN v1.0 Address: 0x80043658
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80043658(undefined4 param_1,int param_2)
{
  if ((&DAT_803dc210)[param_2] == -2) {
    (&DAT_803dc210)[param_2] = param_1;
    return -1;
  }
  return (&DAT_803dc210)[param_2];
}

/*
 * --INFO--
 *
 * Function: FUN_80043680
 * EN v1.0 Address: 0x80043680
 * EN v1.0 Size: 480b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80043680(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined8 uVar9;
  longlong lVar10;
  
  lVar10 = FUN_8028683c();
  iVar4 = (int)((ulonglong)lVar10 >> 0x20);
  iVar5 = (int)lVar10;
  iVar3 = 0;
  puVar7 = (undefined *)0x0;
  bVar1 = false;
  uVar6 = 0;
  puVar8 = puVar7;
  if (iVar4 != 0x25) {
    if (lVar10 < 0x2500000000) {
      if (iVar4 == 0x1a) {
        iVar3 = 0x800;
        puVar8 = &DAT_8034ec70;
      }
      else if (lVar10 < 0x1a00000000) {
        if (iVar4 == 0xe) {
          iVar3 = 0x1fd0;
          uVar6 = 0xa0000000;
          puVar8 = &DAT_80346d30;
        }
      }
      else if (iVar4 == 0x21) {
        iVar3 = 0x1000;
        puVar8 = &DAT_80352c70;
      }
      else if ((0x20ffffffff < lVar10) && (0x23ffffffff < lVar10)) {
        iVar3 = 0x1000;
        puVar8 = &DAT_80356c70;
      }
    }
    else if (iVar4 == 0x2f) {
      iVar3 = 3000;
      puVar8 = &DAT_8035ac70;
    }
    else if (lVar10 < 0x2f00000000) {
      if (iVar4 == 0x2a) {
        iVar3 = 0x800;
        uVar6 = 0xc;
        puVar8 = &DAT_8035db50;
      }
      else if ((lVar10 < 0x2a00000000) && (lVar10 < 0x2700000000)) {
        iVar3 = 0x800;
        puVar8 = &DAT_80350c70;
      }
    }
    else {
      puVar8 = DAT_80360188;
      if (iVar4 != 0x50) {
        puVar8 = puVar7;
      }
    }
  }
  if ((-1 < iVar5) && (iVar5 < iVar3)) {
    while( true ) {
      FUN_80243e74();
      uVar2 = DAT_803dd900;
      FUN_80243e9c();
      if ((uVar6 & uVar2) == 0) break;
      uVar9 = FUN_80014f6c();
      FUN_80020390();
      if (bVar1) {
        uVar9 = FUN_8004a9e4();
      }
      uVar9 = FUN_80048350(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80015650(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (bVar1) {
        uVar9 = FUN_800235b0();
        FUN_80019c5c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004a5b8('\x01');
      }
      if (DAT_803dd5d0 != '\0') {
        bVar1 = true;
      }
    }
    if (puVar8 != (undefined *)0x0) {
      *param_11 = *(undefined4 *)(puVar8 + iVar5 * 4);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80043860
 * EN v1.0 Address: 0x80043860
 * EN v1.0 Size: 216b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_80043860(int param_1)
{
  if (param_1 != 0x25) {
    if (param_1 < 0x25) {
      if (param_1 == 0x1a) {
        return &DAT_8034ec70;
      }
      if (param_1 < 0x1a) {
        if (param_1 == 0xe) {
          return &DAT_80346d30;
        }
      }
      else {
        if (param_1 == 0x21) {
          return &DAT_80352c70;
        }
        if ((0x20 < param_1) && (0x23 < param_1)) {
          return &DAT_80356c70;
        }
      }
    }
    else {
      if (param_1 == 0x2f) {
        return &DAT_8035ac70;
      }
      if (param_1 < 0x2f) {
        if (param_1 == 0x2a) {
          return &DAT_8035db50;
        }
        if ((param_1 < 0x2a) && (param_1 < 0x27)) {
          return &DAT_80350c70;
        }
      }
      else if (param_1 == 0x50) {
        return DAT_80360188;
      }
    }
  }
  return (undefined *)0x0;
}

/*
 * --INFO--
 *
 * Function: FUN_80043938
 * EN v1.0 Address: 0x80043938
 * EN v1.0 Size: 1324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80043938(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80043e64
 * EN v1.0 Address: 0x80043E64
 * EN v1.0 Size: 1708b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80043e64(uint *param_1,int param_2,int param_3)
{
  bool bVar1;
  bool bVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint *puVar7;
  uint *puVar8;
  uint *puVar9;
  uint *puVar10;
  
  iVar4 = 0;
  bVar1 = false;
  bVar2 = false;
  iVar5 = 0;
  puVar8 = (uint *)(&DAT_80360048)[param_2];
  if (((puVar8 == (uint *)0x0) || ((&DAT_80360048)[param_3] == 0)) &&
     (bVar1 = puVar8 == (uint *)0x0, (&DAT_80360048)[param_3] == 0)) {
    bVar2 = true;
  }
  puVar3 = (uint *)(&DAT_80360048)[param_3];
  if (param_1 == (uint *)&DAT_8035db50) {
    iVar5 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_8035ac70) {
    iVar5 = 3000;
  }
  else if (param_1 == (uint *)&DAT_80356c70) {
    iVar5 = 0x1000;
  }
  else if (param_1 == (uint *)&DAT_80352c70) {
    iVar5 = 0x1000;
  }
  else if (param_1 == (uint *)&DAT_80350c70) {
    iVar5 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_8034ec70) {
    iVar5 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_80346d30) {
    iVar5 = 0x1fd0;
  }
  puVar9 = param_1;
  if ((param_1 == (uint *)&DAT_80356c70) || (param_1 == (uint *)&DAT_80352c70)) {
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      if ((!bVar1) && (*puVar8 == 0xffffffff)) {
        bVar1 = true;
      }
      if ((!bVar2) && (*puVar3 == 0xffffffff)) {
        bVar2 = true;
      }
      if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)) {
        if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)) {
          if ((bVar1) || (*puVar8 == 0)) {
            if ((bVar2) || (*puVar3 == 0)) {
              *puVar9 = 0;
            }
            else {
              *puVar9 = *puVar3;
            }
          }
          else {
            *puVar9 = *puVar8;
          }
        }
        else {
          *puVar9 = uVar6;
        }
      }
      else {
        *puVar9 = uVar6 & 0x7fffffff;
        *puVar9 = *puVar9 | 0x40000000;
      }
      puVar8 = puVar8 + 1;
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      puVar9 = puVar9 + 1;
    }
  }
  else if (param_1 == (uint *)&DAT_80350c70) {
    puVar9 = (uint *)&DAT_80350c70;
    puVar7 = puVar8;
    puVar10 = puVar3;
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      if (((bVar1) || (uVar6 = *puVar7, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
        if (((bVar2) || (uVar6 = *puVar10, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
          if ((bVar1) || (*puVar7 != 0xffffffff)) {
            if ((bVar2) || (*puVar10 != 0xffffffff)) {
              if ((bVar1) || (*puVar7 == 0)) {
                if ((bVar2) || (*puVar10 == 0)) {
                  *puVar9 = 0;
                }
                else {
                  *puVar9 = *puVar10;
                }
              }
              else {
                *puVar9 = *puVar7;
              }
            }
            else {
              *puVar9 = 0;
              bVar2 = true;
            }
          }
          else {
            *puVar9 = 0;
            bVar1 = true;
          }
        }
        else {
          *puVar9 = uVar6 & 0xffffff | 0x20000000;
          if ((puVar8 != (uint *)0x0) && (*puVar7 == 0xffffffff)) {
            bVar1 = true;
          }
        }
      }
      else {
        *puVar9 = uVar6;
        if ((puVar3 != (uint *)0x0) && (*puVar10 == 0xffffffff)) {
          bVar2 = true;
        }
      }
      puVar7 = puVar7 + 1;
      puVar9 = puVar9 + 1;
      puVar10 = puVar10 + 1;
      iVar4 = iVar4 + 1;
    }
  }
  else if (param_1 == (uint *)&DAT_8034ec70) {
    puVar9 = (uint *)&DAT_8034ec70;
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      if ((bVar1) || (*puVar8 != 0xffffffff)) {
        if ((bVar2) || (*puVar3 != 0xffffffff)) {
          if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)) {
            if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
            {
              if ((bVar1) || (*puVar8 == 0)) {
                if ((bVar2) || (*puVar3 == 0)) {
                  *puVar9 = 0;
                }
                else {
                  *puVar9 = *puVar3;
                }
              }
              else {
                *puVar9 = *puVar8;
              }
            }
            else {
              *puVar9 = uVar6 & 0x7fffffff | 0x20000000;
            }
          }
          else {
            *puVar9 = uVar6;
          }
        }
        else {
          *puVar9 = 0;
          bVar2 = true;
        }
      }
      else {
        *puVar9 = 0;
        bVar1 = true;
      }
      puVar8 = puVar8 + 1;
      puVar9 = puVar9 + 1;
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
    }
  }
  else {
    puVar9 = puVar8;
    puVar7 = puVar3;
    puVar10 = param_1;
    if (param_1 == (uint *)&DAT_80346d30) {
      puVar9 = (uint *)&DAT_80346d30;
      for (; iVar5 != 0; iVar5 = iVar5 + -1) {
        if ((bVar1) || (*puVar8 != 0xffffffff)) {
          if ((bVar2) || (*puVar3 != 0xffffffff)) {
            if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
            {
              if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)
                 ) {
                if ((bVar1) || (*puVar8 == 0)) {
                  if ((bVar2) || (*puVar3 == 0)) {
                    *puVar9 = 0;
                  }
                  else {
                    *puVar9 = *puVar3;
                  }
                }
                else {
                  *puVar9 = *puVar8;
                }
              }
              else {
                *puVar9 = uVar6 & 0x7fffffff | 0x20000000;
              }
            }
            else {
              *puVar9 = uVar6;
            }
          }
          else {
            *puVar9 = 0;
            bVar2 = true;
          }
        }
        else {
          *puVar9 = 0;
          bVar1 = true;
        }
        puVar8 = puVar8 + 1;
        puVar9 = puVar9 + 1;
        puVar3 = puVar3 + 1;
        iVar4 = iVar4 + 1;
      }
    }
    else {
      for (; iVar5 != 0; iVar5 = iVar5 + -1) {
        if ((!bVar1) && (*puVar9 == 0xffffffff)) {
          bVar1 = true;
        }
        if ((!bVar2) && (*puVar7 == 0xffffffff)) {
          bVar2 = true;
        }
        if (((bVar1) || (uVar6 = *puVar9, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
          if (((bVar2) || (uVar6 = *puVar7, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
            if ((bVar1) || (puVar8 == (uint *)0x0)) {
              if ((bVar2) || (puVar3 == (uint *)0x0)) {
                *puVar10 = 0;
              }
              else {
                *puVar10 = *puVar7;
              }
            }
            else {
              *puVar10 = *puVar9;
            }
          }
          else {
            *puVar10 = uVar6 & 0xffffff | 0x20000000;
          }
        }
        else {
          *puVar10 = uVar6;
        }
        iVar4 = iVar4 + 1;
        puVar9 = puVar9 + 1;
        puVar7 = puVar7 + 1;
        puVar10 = puVar10 + 1;
      }
    }
  }
  param_1[iVar4 + -1] = 0xffffffff;
  return 1;
}
