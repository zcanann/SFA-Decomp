#include "ghidra_import.h"
#include "main/objprint_dolphin.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_80006938();
extern undefined4 FUN_80006940();
extern undefined4 FUN_80006958();
extern undefined4 FUN_80006974();
extern void* FUN_800069a8();
extern undefined4 FUN_800069d4();
extern undefined4 FUN_80006adc();
extern undefined8 FUN_80006c1c();
extern undefined4 FUN_80006c28();
extern undefined4 FUN_800174b8();
extern undefined4 FUN_80017550();
extern int FUN_80017558();
extern int FUN_80017570();
extern undefined4 FUN_8001759c();
extern int FUN_800175a4();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d4();
extern undefined4 FUN_800175fc();
extern undefined4 FUN_80017600();
extern undefined4 FUN_80017604();
extern undefined4 FUN_80017608();
extern undefined4 FUN_80017610();
extern undefined4 FUN_80017614();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_800176a8();
extern undefined4 FUN_80017700();
extern int FUN_80017730();
extern undefined4 FUN_80017754();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017794();
extern int FUN_8001779c();
extern undefined4 FUN_800177b4();
extern int FUN_80017800();
extern undefined8 FUN_80017810();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017818();
extern uint FUN_80017824();
extern undefined4 FUN_8001782c();
extern uint FUN_80017830();
extern undefined4 FUN_8001784c();
extern undefined4 FUN_800178c8();
extern undefined4 FUN_800178cc();
extern undefined4 FUN_800178d0();
extern undefined4 FUN_800178d4();
extern undefined4 FUN_800178f0();
extern undefined4 FUN_80017914();
extern int FUN_8001792c();
extern undefined4 FUN_8001794c();
extern undefined4 FUN_8001795c();
extern undefined4 FUN_80017964();
extern undefined4 FUN_80017968();
extern undefined4 FUN_8001796c();
extern undefined4 FUN_80017970();
extern undefined4 FUN_80017978();
extern undefined4 FUN_80017988();
extern undefined4 FUN_800179c8();
extern undefined4 FUN_800179cc();
extern undefined4 FUN_80017a50();
extern undefined4 FUN_80017a54();
extern int FUN_80017a98();
extern undefined4 FUN_8003bbfc();
extern undefined4 FUN_8003bda0();
extern undefined4 FUN_8003c10c();
extern undefined4 FUN_8003c1f8();
extern undefined4 FUN_8003cb48();
extern undefined8 FUN_800443fc();
extern undefined8 FUN_80044424();
extern undefined4 FUN_80045c4c();
extern undefined8 FUN_8004600c();
extern char FUN_80048094();
extern int FUN_800480a0();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_80048178();
extern undefined4 FUN_80048bc4();
extern undefined4 FUN_80048f00();
extern undefined4 FUN_80049024();
extern undefined4 FUN_80049260();
extern undefined4 FUN_80049910();
extern undefined4 FUN_8004afc0();
extern undefined4 FUN_8004b41c();
extern undefined4 FUN_8004b8cc();
extern uint FUN_8004b960();
extern undefined4 FUN_8004bc68();
extern undefined4 FUN_8004bd68();
extern undefined4 FUN_8004be30();
extern undefined4 FUN_8004bf28();
extern undefined4 FUN_8004c174();
extern undefined4 FUN_80051868();
extern undefined4 FUN_80051b04();
extern undefined4 FUN_80051d64();
extern undefined4 FUN_80051fc4();
extern undefined4 FUN_800523e4();
extern undefined4 FUN_80052500();
extern undefined4 FUN_8005264c();
extern undefined4 FUN_80052778();
extern undefined4 FUN_800528d0();
extern undefined4 FUN_80052904();
extern uint FUN_80053078();
extern undefined4 FUN_800530b4();
extern uint FUN_8005375c();
extern void newshadows_getShadowTextureTable4x8();
extern undefined4 FUN_8006b03c();
extern int FUN_8006f690();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern void trackIntersect_drawColorBand(void);
extern void trackIntersect_getColorRgb();
extern undefined4 FUN_8006fb14();
extern undefined4 FUN_800709e4();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f88();
extern undefined4 FUN_80080f90();
extern undefined4 FUN_80080f94();
extern undefined4 FUN_8011846c();
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
 * Function: FUN_8003d6f8
 * EN v1.0 Address: 0x8003D6F8
 * EN v1.0 Size: 644b
 * EN v1.1 Address: 0x8003D7F0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003d6f8(int param_1)
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
  piVar1 = FUN_80017624(param_1,'\0');
  if (piVar1 != (int *)0x0) {
    FUN_800175b0((int)piVar1,4);
    FUN_800175d4((double)FLOAT_803df684,(double)FLOAT_803df6b4,(double)FLOAT_803df684,piVar1);
    FUN_8001759c((int)piVar1,0xff,0xff,0xff,0xff);
    FUN_80017608(0);
    FUN_80017600(2,0,0);
    local_4c = DAT_803dc0d0;
    FUN_8025a2ec(2,&local_4c);
    local_50 = DAT_803dc0c8;
    FUN_8025a454(2,&local_50);
    FUN_800175fc(2,piVar1,param_1);
    FUN_80017604();
    FUN_80017620((uint)piVar1);
  }
  local_54 = local_3c;
  FUN_8025c510(0,(byte *)&local_54);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c584(0,0xc);
  newshadows_getShadowTextureTable4x8(&local_40,&local_44,&uStack_48);
  FUN_8004812c(*(int *)(local_40 + ((DAT_803dd8c4 >> 2) + (uint)DAT_803dd8bd * local_44) * 4),0);
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
  FUN_8006f8fc(1,3,0);
  FUN_8006f8a4(1);
  FUN_8025cce8(1,4,5,5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003d97c
 * EN v1.0 Address: 0x8003D97C
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x8003DA78
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003d97c(ushort *param_1,int param_2)
{
  float fVar1;
  float *pfVar2;
  uint uVar3;
  ushort *puVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  double dVar13;
  undefined2 local_f8;
  undefined2 local_f6;
  undefined2 local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float afStack_e0[12];
  float afStack_b0[3];
  float local_a4;
  float local_94;
  float local_84;
  float afStack_70[16];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar11 = *(int **)(param_2 + 0x58);
  pfVar2 = (float *)FUN_80006974();
  FUN_80017a50(param_1, afStack_70, '\0');
  FUN_80247618(pfVar2, afStack_70, afStack_b0);
  FUN_8025d80c(afStack_b0, (uint)DAT_802cbaa8);
  FUN_8025d888((uint)DAT_802cbaa8);
  dVar13 = (double)(float)((double)FLOAT_803df69c / (double)*(float *)(param_1 + 4));
  FUN_80247a7c(dVar13, dVar13, (double)FLOAT_803df69c, afStack_e0);
  local_a4 = FLOAT_803df684;
  local_94 = FLOAT_803df684;
  local_84 = FLOAT_803df684;
  FUN_80247618(afStack_b0, afStack_e0, afStack_b0);
  FUN_8025d8c4(afStack_b0, 0x1e, 0);
  FUN_8006fb14(param_1, param_2, 0);
  FUN_80257b5c();
  FUN_802570dc(9, 1);
  FUN_802570dc(10, 1);
  FUN_802570dc(0xd, 1);
  iVar10 = piVar11[1];
  iVar9 = piVar11[2];
  FUN_80259000(0x90, 7, (uint)*(ushort *)(piVar11 + 3) * 3 & 0xffff);
  iVar5 = 0;
  for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(piVar11 + 3); iVar7 = iVar7 + 1) {
    puVar8 = (ushort *)(*piVar11 + iVar5);
    iVar12 = 3;
    puVar4 = puVar8;
    do {
      puVar6 = (undefined2 *)(iVar10 + (uint)*puVar4 * 6);
      *(undefined2 *)&DAT_cc008000 = *puVar6;
      *(undefined2 *)&DAT_cc008000 = puVar6[1];
      *(undefined2 *)&DAT_cc008000 = puVar6[2];
      *(undefined *)&DAT_cc008000 = *(undefined *)(puVar8 + 3);
      *(undefined *)&DAT_cc008000 = *(undefined *)((int)puVar8 + 7);
      *(undefined *)&DAT_cc008000 = *(undefined *)(puVar8 + 4);
      puVar6 = (undefined2 *)(iVar9 + (uint)*puVar4 * 4);
      *(undefined2 *)&DAT_cc008000 = *puVar6;
      *(undefined2 *)&DAT_cc008000 = puVar6[1];
      puVar4 = puVar4 + 1;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
    iVar5 = iVar5 + 10;
  }
  FUN_8025d888(0);
  uVar3 = FUN_80017760(0, 5);
  if (uVar3 == 0) {
    uVar3 = FUN_80017760(0, (int)*(short *)((int)piVar11 + 0xe) - 1);
    fVar1 = *(float *)(param_1 + 4);
    uStack_2c = (int)*(short *)(iVar10 + uVar3 * 6) >> 8 ^ 0x80000000;
    local_30 = 0x43300000;
    local_ec = fVar1 * (float)((double)CONCAT44(0x43300000, uStack_2c) - DOUBLE_803df6c0) +
               *(float *)(param_1 + 6);
    iVar10 = iVar10 + uVar3 * 6;
    uStack_24 = (int)*(short *)(iVar10 + 2) >> 8 ^ 0x80000000;
    local_28 = 0x43300000;
    local_e8 = fVar1 * (float)((double)CONCAT44(0x43300000, uStack_24) - DOUBLE_803df6c0) +
               *(float *)(param_1 + 8);
    uStack_1c = (int)*(short *)(iVar10 + 4) >> 8 ^ 0x80000000;
    local_20 = 0x43300000;
    local_e4 = fVar1 * (float)((double)CONCAT44(0x43300000, uStack_1c) - DOUBLE_803df6c0) +
               *(float *)(param_1 + 10);
    local_f0 = FLOAT_803df69c;
    local_f8 = 0;
    local_f4 = 0;
    local_f6 = 0;
    (**(code **)(*DAT_803dd708 + 8))(param_1, 0x7fd, &local_f8, 0x200001, 0xffffffff, 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003db90
 * EN v1.0 Address: 0x8003DB90
 * EN v1.0 Size: 980b
 * EN v1.1 Address: 0x8003DD48
 * EN v1.1 Size: 1040b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003db90(void)
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
    FUN_80017608(0);
    FUN_80017600(iVar8,0,(uint)((bVar1 & 2) != 0));
    uVar2 = *(ushort *)(iVar12 + 0xe2);
    if ((uVar2 & 9) == 0) {
      if ((uVar2 & 0xc) == 0) {
        uVar6 = 6;
        uVar5 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x8d);
        if (uVar5 == 0) {
          FUN_80080f94((uint)*(byte *)(iVar4 + 0xf2));
          FUN_80080f90((uint)*(byte *)(iVar4 + 0xf2),(undefined *)&local_44,
                       (undefined *)((int)&local_44 + 1),(undefined *)((int)&local_44 + 2));
        }
        else {
          FUN_80017614(uVar5,(undefined *)&local_44,(undefined *)((int)&local_44 + 1),
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
        FUN_80017610(iVar4,local_3c,uVar5,&local_40,uVar6);
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
        FUN_800175fc(iVar8,*puVar9,iVar4);
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
      FUN_80017610(iVar4,&DAT_803dd8e4,(uint)*(byte *)(iVar12 + 0xfa),&DAT_803dd8dc,8);
      if (((*(byte *)(*(int *)(iVar4 + 0x50) + 0x5f) & 4) != 0) || (DAT_803dd8cc != '\0')) {
        DAT_803dd8dc = 0;
      }
      bVar3 = false;
      piVar10 = &DAT_803dd8e4;
      pbVar11 = &DAT_803dd8e0;
      for (iVar12 = 0; iVar12 < DAT_803dd8dc; iVar12 = iVar12 + 1) {
        iVar8 = FUN_800175a4(*piVar10);
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
        FUN_80017600((uint)*pbVar11,2,0);
        FUN_800175fc((uint)*pbVar11,*piVar10,iVar4);
        local_64 = DAT_803dc0d0;
        FUN_8025a2ec((uint)*pbVar11,&local_64);
        local_68 = DAT_803dc0c8;
        FUN_8025a454((uint)*pbVar11,&local_68);
        piVar10 = piVar10 + 1;
        pbVar11 = pbVar11 + 1;
      }
    }
    FUN_80017604();
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
 * Function: FUN_8003df64
 * EN v1.0 Address: 0x8003DF64
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8003E158
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003df64(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4)
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
  iVar9 = FUN_8001779c();
  if (DAT_803dd8c8 == 1) {
    pfVar10 = (float *)FUN_8001779c();
    bVar1 = *(byte *)(iVar15 + 0xf3);
    bVar2 = *(byte *)(iVar15 + 0xf4);
    pfVar14 = pfVar10 + 0x9c0;
    FUN_80017794(0);
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
      pfVar10 = (float *)FUN_80017970((int *)uVar17,uVar11);
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
 * Function: FUN_8003e0ec
 * EN v1.0 Address: 0x8003E0EC
 * EN v1.0 Size: 620b
 * EN v1.1 Address: 0x8003E2E0
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e0ec(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4,float *param_5,
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
  iVar6 = FUN_8001779c();
  if (DAT_803dd8c8 == 1) {
    if ((param_8 & 0xff) == 0) {
      FUN_8003bda0(iVar7,(int *)uVar15,param_5,param_4);
    }
    else {
      pfVar8 = (float *)FUN_8001779c();
      bVar1 = *(byte *)(iVar7 + 0xf3);
      bVar2 = *(byte *)(iVar7 + 0xf4);
      pfVar12 = pfVar8 + 0x9c0;
      FUN_80017794(0);
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
    FUN_800723a0();
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
      pfVar8 = (float *)FUN_80017970((int *)uVar15,uVar9);
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
 * Function: FUN_8003e358
 * EN v1.0 Address: 0x8003E358
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x8003E58C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e358(int param_1,undefined4 param_2,int *param_3)
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
 * Function: FUN_8003e4a0
 * EN v1.0 Address: 0x8003E4A0
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x8003E6F4
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003e4a0(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,uint param_5,
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
        if ((DAT_803dd8dc == 0) || (FUN_80017550(DAT_803dd8e4,&local_38,auStack_34), local_38 != 0))
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
 * Function: fn_8003EA84
 * EN v1.0 Address: 0x8003E7E0
 * EN v1.0 Size: 1144b
 * EN v1.1 Address: 0x8003EA84
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
char fn_8003EA84(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5,
                int param_6)
{
  char cVar1;
  bool bVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  uint *puVar6;
  uint *puVar7;
  uint uVar8;
  int iVar9;
  char *pcVar10;
  float *pfVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  undefined8 uVar16;
  char local_88;
  char local_87;
  char local_86;
  char local_85;
  float afStack_84[13];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  uVar16 = FUN_80286820();
  iVar5 = (int)((ulonglong)uVar16 >> 0x20);
  pcVar10 = (char *)(u32)uVar16;
  bVar2 = true;
  if ((*param_3 != 0) || (param_3[1] != 0)) {
    bVar4 = 0;
    for (iVar13 = 0; iVar13 < (int)(uint)(byte)pcVar10[0x41]; iVar13 = iVar13 + 1) {
      iVar9 = FUN_800480a0((int)pcVar10, iVar13);
      if ((*(byte *)(iVar9 + 4) & 0x80) != 0) {
        bVar4 = bVar4 + 1;
      }
    }
    if (1 < bVar4) {
      bVar2 = false;
    }
  }
  puVar7 = (uint *)0x0;
  iVar13 = 0;
  do {
    if ((int)(uint)(byte)pcVar10[0x41] <= iVar13) {
      FUN_8028686c();
      return '\0';
    }
    puVar6 = (uint *)FUN_800480a0((int)pcVar10, iVar13);
    if ((*(byte *)(puVar6 + 1) & 0x80) == param_4) {
      if (((*(uint *)(pcVar10 + 0x3c) & 0x100000) != 0) && (iVar13 == 1)) {
        FUN_8004bc68(*param_3 != 0);
        FUN_8028686c();
        return '\x01';
      }
      cVar1 = (char)((*(byte *)(iVar5 + 0x37) + 1) * (uint)(byte)pcVar10[0xc] >> 8);
      if (*puVar6 == 0) {
        local_88 = pcVar10[4];
        local_87 = pcVar10[5];
        local_86 = pcVar10[6];
        if ((*param_3 == 0) && (((*pcVar10 != -1 || (pcVar10[1] != -1)) || (pcVar10[2] != -1)))) {
          if (param_5 == 0) {
            if ((pcVar10[0x40] & 0x10U) == 0) {
              local_85 = cVar1;
              FUN_80052500(&local_88);
            }
            else {
              local_85 = cVar1;
              FUN_800523e4();
              if (local_85 != -1) {
                FUN_80052778(&local_88);
              }
            }
          }
          else {
            *(char *)((int)&DAT_803dd8d4 + 3) = cVar1;
            local_85 = cVar1;
            FUN_80052778((char *)&DAT_803dd8d4);
          }
        }
        else {
          local_85 = cVar1;
          FUN_80052778(&local_88);
        }
      }
      else {
        uVar8 = FUN_80053078(*puVar6);
        if (*(char *)((int)puVar6 + 5) == '\0') {
          pfVar11 = (float *)0x0;
        }
        else {
          iVar9 = *(int *)(*(int *)(iVar5 + 0x50) + 0xc);
          iVar12 = 0;
          for (uVar3 = (uint)*(byte *)(*(int *)(iVar5 + 0x50) + 0x59); uVar3 != 0; uVar3 = uVar3 - 1
              ) {
            if (*(char *)((int)puVar6 + 5) == *(char *)(iVar9 + 1)) {
              uVar8 = FUN_8005375c(uVar8, *(int *)(*(int *)(iVar5 + 0x70) + iVar12 * 0x10));
              break;
            }
            iVar9 = iVar9 + 2;
            iVar12 = iVar12 + 1;
          }
          iVar9 = *(int *)(*(int *)(iVar5 + 0x50) + 0xc);
          iVar12 = 0;
          for (uVar3 = (uint)*(byte *)(*(int *)(iVar5 + 0x50) + 0x59); uVar3 != 0; uVar3 = uVar3 - 1
              ) {
            if (*(char *)((int)puVar6 + 5) == *(char *)(iVar9 + 1)) {
              iVar9 = *(int *)(iVar5 + 0x70) + iVar12 * 0x10;
              uStack_4c = (int)*(short *)(iVar9 + 8) ^ 0x80000000;
              local_50 = 0x43300000;
              dVar14 = (double)(FLOAT_803df6c8 *
                               (float)((double)CONCAT44(0x43300000, uStack_4c) - DOUBLE_803df6c0));
              uStack_44 = (int)*(short *)(iVar9 + 10) ^ 0x80000000;
              local_48 = 0x43300000;
              dVar15 = (double)(FLOAT_803df6c8 *
                               (float)((double)CONCAT44(0x43300000, uStack_44) - DOUBLE_803df6c0));
              goto LAB_8003eca4;
            }
            iVar9 = iVar9 + 2;
            iVar12 = iVar12 + 1;
          }
          dVar14 = (double)FLOAT_803df684;
          dVar15 = dVar14;
LAB_8003eca4:
          FUN_80247a48(dVar14, dVar15, (double)FLOAT_803df684, afStack_84);
          pfVar11 = afStack_84;
        }
        if (iVar13 == 0) {
          if ((((*param_3 == 0) && (param_3[1] == 0)) && (param_6 == 0)) || (!bVar2)) {
            uVar3 = 0;
            local_85 = cVar1;
          }
          else {
            uVar3 = 8;
            local_85 = cVar1;
          }
        }
        else {
          uVar3 = *(byte *)(puVar7 + 1) & 0x7f;
          local_85 = -1;
        }
        local_88 = -1;
        local_87 = -1;
        local_86 = -1;
        if ((*param_3 == 0) && (((*pcVar10 != -1 || (pcVar10[1] != -1)) || (pcVar10[2] != -1)))) {
          if (param_5 == 0) {
            if ((pcVar10[0x40] & 0x10U) == 0) {
              FUN_80051d64(uVar8, pfVar11, uVar3, &local_88);
            }
            else {
              FUN_80051868(uVar8, pfVar11, uVar3);
              if (local_85 != -1) {
                FUN_80052778(&local_88);
              }
            }
          }
          else {
            *(char *)((int)&DAT_803dd8d4 + 3) = local_85;
            if ((pcVar10[0x40] & 0x10U) == 0) {
              FUN_80051fc4(uVar8, pfVar11, uVar3, (char *)&DAT_803dd8d4,
                           (uint)*(byte *)(param_3 + 2), 1);
            }
            else {
              FUN_80051b04(uVar8, pfVar11, uVar3, (char *)&DAT_803dd8d4);
            }
          }
        }
        else {
          FUN_80051fc4(uVar8, pfVar11, uVar3, &local_88, (uint)*(byte *)(param_3 + 2), 1);
        }
      }
    }
    iVar13 = iVar13 + 1;
    puVar7 = puVar6;
  } while (true);
}

/*
 * --INFO--
 *
 * Function: fn_8003EEEC
 * EN v1.0 Address: 0x8003EC58
 * EN v1.0 Size: 1884b
 * EN v1.1 Address: 0x8003EEEC
 * EN v1.1 Size: 1976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8003EEEC(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4)
{
  undefined uVar1;
  undefined uVar2;
  byte bVar3;
  undefined uVar4;
  bool bVar5;
  ushort *puVar6;
  int iVar7;
  code *pcVar8;
  char cVar12;
  int *piVar9;
  uint *puVar10;
  float *pfVar11;
  int iVar13;
  int iVar14;
  int iVar15;
  uint uVar16;
  int iVar17;
  int iVar18;
  byte *pbVar19;
  uint uVar20;
  int *piVar21;
  double dVar22;
  double dVar23;
  undefined8 uVar24;
  undefined4 local_128;
  uint local_124;
  undefined4 uStack_120;
  undefined4 local_11c;
  int local_118;
  int local_114;
  float afStack_110[12];
  float afStack_e0[12];
  float afStack_b0[12];
  undefined4 auStack_80[12];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  uVar24 = FUN_80286820();
  puVar6 = (ushort *)((ulonglong)uVar24 >> 0x20);
  iVar13 = (int)(u32)uVar24;
  bVar5 = false;
  uVar16 = param_4[4];
  uVar4 = *(undefined *)(*param_4 + ((int)uVar16 >> 3));
  iVar7 = *param_4 + ((int)uVar16 >> 3);
  uVar1 = *(undefined *)(iVar7 + 1);
  uVar2 = *(undefined *)(iVar7 + 2);
  param_4[4] = uVar16 + 6;
  uVar16 = (CONCAT12(uVar2, CONCAT11(uVar1, uVar4)) >> (uVar16 & 7)) & 0x3f;
  pcVar8 = (code *)FUN_8001795c((int)param_3);
  if ((pcVar8 == (code *)0x0) || (cVar12 = (*pcVar8)(puVar6, param_3, uVar16), cVar12 == '\0')) {
    iVar7 = FUN_8001792c(*param_3, uVar16);
    piVar9 = (int *)FUN_80017978((int)param_3, uVar16);
    FUN_80052904();
    uVar20 = 0;
    if (((*piVar9 != 0) || (piVar9[1] != 0)) && (*(uint *)(iVar7 + 0x34) != 0)) {
      uVar20 = FUN_80053078(*(uint *)(iVar7 + 0x34));
      iVar14 = DAT_803dd8dc + 1;
      if (*piVar9 != 0) {
        iVar14 = DAT_803dd8dc + 2;
      }
      if (piVar9[1] != 0) {
        iVar14 = iVar14 + 1;
      }
      uVar20 = FUN_8004b960(uVar20, iVar14, (uint)*(byte *)(iVar7 + 0x42), *(uint *)(iVar7 + 0x24));
      uVar20 = uVar20 & 0xff;
    }
    if (*piVar9 != 0) {
      FUN_8004c174(*piVar9, *(char *)((int)puVar6 + 0xf1));
    }
    if (piVar9[1] == 0) {
      local_128 = DAT_803dc0cc;
      FUN_8025c428(3, (byte *)&local_128);
    }
    else {
      local_11c = DAT_803dd8d4 & 0xffffff00;
      if (*(int *)(iVar7 + 0x1c) != 0) {
        local_11c = CONCAT31(0xffffff, *(undefined *)(iVar7 + 0x22));
      }
      local_124 = local_11c;
      FUN_8025c428(3, (byte *)&local_124);
      FUN_8004bf28(piVar9[1], *piVar9 != 0, (uint)*(byte *)(iVar7 + 0x20));
      if ((char)local_11c != '\0') {
        FUN_8004be30(*piVar9 != 0);
      }
    }
    iVar14 = DAT_803dd8dc;
    if (DAT_803dd8cc == '\0') {
      bVar3 = *(byte *)(*(int *)(puVar6 + 0x28) + 0x5f);
      if (((bVar3 & 4) == 0) || (*(float **)(*(int *)(puVar6 + 0x32) + 0xc) == (float *)0x0)) {
        if ((bVar3 & 0x10) == 0) {
          if ((bVar3 & 4) == 0) {
            piVar21 = &DAT_803dd8e4;
            pbVar19 = &DAT_803dd8e0;
            for (iVar18 = 0; iVar18 < DAT_803dd8dc; iVar18 = iVar18 + 1) {
              iVar17 = FUN_80017570(*piVar21);
              if (iVar17 != 0) {
                FUN_80017550(*piVar21, &local_114, &local_118);
                if (local_114 == 2) {
                  bVar5 = true;
                }
                iVar15 = FUN_80017558(*piVar21);
                FUN_8004b41c(iVar17, iVar15, local_114, local_118, (uint)*pbVar19);
              }
              piVar21 = piVar21 + 1;
              pbVar19 = pbVar19 + 1;
            }
          }
        }
        else {
          FUN_80049024();
          iVar14 = 0;
        }
      }
      else {
        FUN_8004afc0(*(float **)(*(int *)(puVar6 + 0x32) + 0xc));
        iVar14 = 0;
      }
    }
    else {
      FUN_80048bc4();
      bVar5 = true;
      iVar14 = 0;
    }
    if (uVar20 != 0) {
      FUN_8004b8cc(uVar20);
    }
    if (((*(uint *)(iVar7 + 0x18) != 0) && (*(int *)(iVar7 + 0x1c) == 0)) && (piVar9[1] != 0)) {
      FUN_80053078(*(uint *)(iVar7 + 0x18));
      FUN_8004bd68();
    }
    iVar18 = 0;
    if (((*(ushort *)(iVar13 + 0xe2) & 2) != 0) && ((*(byte *)(iVar13 + 0x24) & 2) == 0)) {
      iVar18 = 1;
    }
    cVar12 = fn_8003EA84((undefined4)(u32)puVar6, (undefined4)iVar7, piVar9, 0x80, iVar18, iVar14);
    if (cVar12 == '\0') {
      FUN_8004bc68(*piVar9 != 0);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 0x100000) != 0) {
      puVar10 = (uint *)FUN_800480a0(iVar7, 1);
      iVar17 = *(int *)(*(int *)(puVar6 + 0x28) + 0xc);
      iVar15 = 0;
      for (uVar20 = (uint)*(byte *)(*(int *)(puVar6 + 0x28) + 0x59); uVar20 != 0;
           uVar20 = uVar20 - 1) {
        if (*(char *)((int)puVar10 + 5) == *(char *)(iVar17 + 1)) {
          iVar17 = *(int *)(puVar6 + 0x38) + iVar15 * 0x10;
          uStack_4c = (int)*(short *)(iVar17 + 8) ^ 0x80000000;
          local_50 = 0x43300000;
          dVar22 = (double)(FLOAT_803df6c8 *
                           (float)((double)CONCAT44(0x43300000, uStack_4c) - DOUBLE_803df6c0));
          uStack_44 = (int)*(short *)(iVar17 + 10) ^ 0x80000000;
          local_48 = 0x43300000;
          dVar23 = (double)(FLOAT_803df6c8 *
                           (float)((double)CONCAT44(0x43300000, uStack_44) - DOUBLE_803df6c0));
          goto LAB_8003f328;
        }
        iVar17 = iVar17 + 2;
        iVar15 = iVar15 + 1;
      }
      dVar22 = (double)FLOAT_803df684;
      dVar23 = dVar22;
LAB_8003f328:
      FUN_80247a48(dVar22, dVar23, (double)FLOAT_803df684, auStack_80);
      FUN_80053078(*puVar10);
      FUN_80048178();
    }
    fn_8003EA84((undefined4)(u32)puVar6, (undefined4)iVar7, piVar9, 0, iVar18, iVar14);
    cVar12 = FUN_80048094();
    if ((cVar12 != '\0') && ((*(ushort *)(iVar13 + 2) & 0x100) == 0)) {
      trackIntersect_getColorRgb((undefined *)&uStack_120);
      FUN_80049910(&uStack_120);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 0x100) != 0) {
      pfVar11 = (float *)FUN_80006974();
      FUN_80017a50(puVar6, afStack_e0, '\0');
      FUN_80247618(pfVar11, afStack_e0, afStack_110);
      FUN_80247618((float *)&DAT_80397450, afStack_110, afStack_b0);
      FUN_8025d8c4(afStack_b0, 0x24, 0);
      FUN_80049260();
    }
    if ((*(byte *)(*(int *)(puVar6 + 0x28) + 0x5f) & 0x10) != 0) {
      FUN_80048f00(iVar7);
    }
    if (((*(byte *)((int)puVar6 + 0xe5) & 2) != 0) || ((*(byte *)((int)puVar6 + 0xe5) & 0x10) != 0))
    {
      local_11c = *(uint *)(puVar6 + 0x76);
      FUN_8005264c((char *)&local_11c);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 0x20000) != 0) {
      FUN_8011846c();
    }
    FUN_800528d0();
    pcVar8 = (code *)FUN_8001794c((int)param_3);
    if (pcVar8 == (code *)0x0) {
      uVar16 = 1;
      if (((*(char *)((int)puVar6 + 0x37) != -1) || ((*(uint *)(iVar7 + 0x3c) & 0x40000000) != 0))
         || (bVar5)) {
        FUN_8025cce8(1, 4, 5, 5);
        if ((*(ushort *)(iVar13 + 2) & 0x400) == 0) {
          if ((*(ushort *)(iVar13 + 2) & 0x2000) == 0) {
            FUN_8006f8fc(1, 3, 0);
            FUN_8025c754(7, 0, 0, 7, 0);
          }
          else {
            uVar16 = 0;
            FUN_8006f8fc(1, 3, 1);
            FUN_8025c754(4, (uint)DAT_803dd8bc, 0, 4, (uint)DAT_803dd8bc);
          }
        }
        else {
          FUN_8006f8fc(0, 3, 0);
          FUN_8025c754(7, 0, 0, 7, 0);
        }
      }
      else if ((*(uint *)(iVar7 + 0x3c) & 0x400) == 0) {
        FUN_8025cce8(0, 1, 0, 5);
        if ((*(ushort *)(iVar13 + 2) & 0x400) == 0) {
          FUN_8006f8fc(1, 3, 1);
        }
        else {
          FUN_8006f8fc(0, 3, 0);
        }
        FUN_8025c754(7, 0, 0, 7, 0);
      }
      else {
        FUN_8025cce8(0, 1, 0, 5);
        if ((*(ushort *)(iVar13 + 2) & 0x400) == 0) {
          FUN_8006f8fc(1, 3, 1);
        }
        else {
          FUN_8006f8fc(0, 3, 0);
        }
        FUN_8025c754(4, 0x40, 0, 4, 0x40);
      }
      if ((*(uint *)(iVar7 + 0x3c) & 0x400) != 0) {
        uVar16 = 0;
      }
      FUN_8006f8a4(uVar16);
    }
    else {
      (*pcVar8)(puVar6, param_3, uVar16);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 8) == 0) {
      FUN_80259288(0);
    }
    else {
      FUN_80259288(2);
    }
  }
  FUN_8028686c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003f3b4
 * EN v1.0 Address: 0x8003F3B4
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x8003F6A4
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003f3b4(undefined4 param_1,undefined4 param_2,int param_3)
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
    FUN_8006f8fc(uVar6,3,uVar5);
    DAT_803dc0e0 = (byte)uVar6;
    DAT_803dc0e1 = (byte)uVar5;
  }
  if (DAT_803dc0d9 != uVar4) {
    FUN_8006f8a4(uVar4);
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
 * Function: fn_8003F8EC
 * EN v1.0 Address: 0x8003F5D0
 * EN v1.0 Size: 1064b
 * EN v1.1 Address: 0x8003F8EC
 * EN v1.1 Size: 1132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8003F8EC(undefined4 param_1,undefined4 param_2,int param_3)
{
  ushort *puVar1;
  int *piVar2;
  float *pfVar3;
  code *pcVar4;
  char cVar8;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar9;
  uint local_a8;
  undefined4 uStack_a4;
  undefined4 local_a0;
  int local_9c[4];
  int local_8c;
  float afStack_88[12];
  float afStack_58[22];
  
  puVar1 = (ushort *)FUN_80286840();
  piVar2 = (int *)FUN_80017a54((int)puVar1);
  if (DAT_803dd8a4 == 0) {
    FUN_80017a50(puVar1, afStack_58, '\0');
  }
  else {
    FUN_802475e4((float *)DAT_803dd8a4, afStack_58);
    DAT_803dd8a4 = 0;
  }
  pfVar3 = (float *)FUN_80006974();
  FUN_80247618(pfVar3, afStack_58, afStack_88);
  if ((*(ushort *)(piVar2 + 6) & 8) == 0) {
    *(undefined *)(piVar2 + 0x18) = 0;
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_8001796c((int)piVar2);
      pfVar3 = (float *)FUN_80017970(piVar2, 0);
      FUN_802475e4((float *)&DAT_802cbac0, pfVar3);
      DAT_803dd8c8 = 3;
    }
    else if (DAT_803dd8b0 == param_3) {
      DAT_803dd8c8 = 1;
    }
    else {
      FUN_80017988(piVar2, param_3, (int)puVar1, &DAT_802cbac0);
      FUN_8003c10c(param_3, piVar2);
    }
    iVar9 = *(int *)(puVar1 + 0x2a);
    if (iVar9 != 0) {
      *(char *)(iVar9 + 0xaf) = *(char *)(iVar9 + 0xaf) + -1;
      if (*(char *)(*(int *)(puVar1 + 0x2a) + 0xaf) < '\0') {
        *(undefined *)(*(int *)(puVar1 + 0x2a) + 0xaf) = 0;
      }
    }
    *(ushort *)(piVar2 + 6) = *(ushort *)(piVar2 + 6) | 8;
  }
  uVar5 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80006adc(local_9c, *(undefined4 *)(param_3 + 0xd4), uVar5, uVar5);
  if ((*(ushort *)(param_3 + 0xe2) & 2) == 0) {
    local_a0 = 0xffffff00;
  }
  else if (DAT_803dd8a8 == '\0') {
    FUN_80080f88((uint)*(byte *)(puVar1 + 0x79), (byte *)&local_a0, (byte *)((int)&local_a0 + 1),
                 (byte *)((int)&local_a0 + 2));
  }
  else {
    *(byte *)&local_a0 = *(byte *)&DAT_803dd8d8;
    *(byte *)((int)&local_a0 + 1) = *(byte *)((int)&DAT_803dd8d8 + 1);
    *(byte *)((int)&local_a0 + 2) = *(byte *)((int)&DAT_803dd8d8 + 2);
    local_a0 = local_a0 << 8;
    DAT_803dd8a8 = '\0';
  }
  *(undefined *)((int)&local_a0 + 3) = *(undefined *)((int)puVar1 + 0x37);
  pcVar4 = (code *)FUN_8001795c((int)piVar2);
  if ((DAT_803dd8aa == '\0') || (pcVar4 != (code *)0x0)) {
    FUN_800069d4();
    if ((pcVar4 == (code *)0x0) || (cVar8 = (*pcVar4)(puVar1, piVar2, 0), cVar8 == '\0')) {
      trackIntersect_drawColorBand();
      FUN_80052904();
      uVar5 = FUN_80053078(*(uint *)(*(int *)(param_3 + 0x38) + 0x24));
      FUN_80051fc4(uVar5, 0, 0, (char *)&local_a0, 0, 0);
      cVar8 = FUN_80048094();
      if (cVar8 != '\0') {
        trackIntersect_getColorRgb((undefined *)&uStack_a4);
        FUN_80049910(&uStack_a4);
      }
      FUN_800528d0();
      FUN_8025a608(4, 0, 0, 0, 0, 0, 2);
      FUN_8025a608(5, 0, 0, 0, 0, 0, 2);
      FUN_8025a5bc(0);
      DAT_803dd8aa = '\x01';
      DAT_803dc0e4 = local_a0;
    }
  }
  else {
    uVar5 = FUN_80053078(*(uint *)(*(int *)(param_3 + 0x38) + 0x24));
    if (DAT_803dd8ac != uVar5) {
      DAT_803dd8ac = uVar5;
      FUN_8004812c(uVar5, 0);
    }
    if ((*(byte *)&DAT_803dc0e4 != *(byte *)&local_a0) ||
       (*(byte *)((int)&DAT_803dc0e4 + 1) != *(byte *)((int)&local_a0 + 1)) ||
       (*(byte *)((int)&DAT_803dc0e4 + 2) != *(byte *)((int)&local_a0 + 2)) ||
       (*(byte *)((int)&DAT_803dc0e4 + 3) != *(byte *)((int)&local_a0 + 3))) {
      local_a8 = local_a0;
      FUN_8025c510(0, (byte *)&local_a8);
      DAT_803dc0e4 = local_a0;
    }
  }
  if (DAT_803dd8b0 != param_3) {
    FUN_802585d8(9, piVar2[(*(ushort *)(piVar2 + 6) >> 1 & 1) + 7], 6);
    FUN_802585d8(0xd, *(uint *)(param_3 + 0x34), 4);
    DAT_803dd8b0 = param_3;
  }
  FUN_8003f3b4((undefined4)(u32)puVar1, (undefined4)param_3, *(int *)(param_3 + 0x38));
  local_8c = local_8c + 4;
  FUN_8003e358(param_3, *(undefined4 *)(param_3 + 0x38), local_9c);
  local_8c = local_8c + 4;
  FUN_8003df64((undefined4)param_3, (undefined4)piVar2, local_9c, afStack_88);
  uVar5 = local_8c + 4;
  iVar9 = (int)uVar5 >> 3;
  iVar6 = local_9c[0] + iVar9;
  local_8c = local_8c + 0xc;
  puVar7 = (undefined4 *)
           FUN_80017914(param_3, (CONCAT12(*(undefined *)(iVar6 + 2),
                                           CONCAT11(*(undefined *)(iVar6 + 1),
                                                    *(undefined *)(local_9c[0] + iVar9))) >>
                                  (uVar5 & 7)) & 0xff);
  FUN_8025d63c(*puVar7, (uint)*(ushort *)(puVar7 + 1));
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003f9f8
 * EN v1.0 Address: 0x8003F9F8
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8003FD58
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003f9f8(void)
{
  DAT_803dd8aa = 0;
  DAT_803dd8ac = 0;
  DAT_803dd8b0 = 0;
  DAT_803dd8b4 = 0;
  DAT_803dc0d4 = 0xffffffff;
  DAT_803dc0d8 = 0xff;
  DAT_803dc0d9 = 0xff;
  DAT_803dc0dc = 0xffffffff;
  DAT_803dc0e0 = 0xff;
  DAT_803dc0e1 = 0xff;
  DAT_803dc0e2 = 0xff;
  DAT_803dc0e4 = 0;
}

/*
 * --INFO--
 *
 * Function: fn_8003FDA8
 * EN v1.0 Address: 0x8003FA38
 * EN v1.0 Size: 1652b
 * EN v1.1 Address: 0x8003FDA8
 * EN v1.1 Size: 1808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8003FDA8(undefined4 param_1,undefined4 param_2,int param_3)
{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  ushort *puVar4;
  ushort *puVar5;
  int *piVar6;
  float *pfVar7;
  float *pfVar8;
  ushort *puVar9;
  undefined4 *puVar10;
  int iVar11;
  uint uVar12;
  undefined *puVar13;
  int iVar14;
  double dVar15;
  undefined8 uVar16;
  uint local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  int local_f8[4];
  uint local_e8;
  float afStack_e4[16];
  float afStack_a4[16];
  float afStack_64[25];
  
  uVar16 = FUN_80286838();
  puVar5 = (ushort *)((ulonglong)uVar16 >> 0x20);
  piVar6 = (int *)FUN_80017a54((int)puVar5);
  pfVar7 = (float *)FUN_80006974();
  if (DAT_803dd8a4 == 0) {
    FUN_80017a50(puVar5, afStack_a4, '\0');
  }
  else {
    FUN_802475e4((float *)DAT_803dd8a4, afStack_a4);
    DAT_803dd8a4 = 0;
  }
  if ((*(ushort *)(piVar6 + 6) & 8) == 0) {
    bVar1 = false;
    *(undefined *)(piVar6 + 0x18) = 0;
    FUN_80017968((int)piVar6);
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_8001796c((int)piVar6);
      pfVar8 = (float *)FUN_80017970(piVar6, 0);
      FUN_802475e4(afStack_a4, pfVar8);
    }
    else {
      bVar1 = *(int *)(param_3 + 0xa4) == 0;
      if (bVar1) {
        FUN_80017988(piVar6, param_3, (int)puVar5, afStack_a4);
      }
      else {
        FUN_802475b8(afStack_e4);
        FUN_80017988(piVar6, param_3, (int)puVar5, afStack_e4);
        FUN_800178d0(piVar6, afStack_a4, (float *)&DAT_80343a70);
      }
      bVar1 = !bVar1;
      if ((*(code **)(puVar5 + 0x84) != (code *)0x0) && ((ushort *)(u32)uVar16 == puVar5)) {
        (**(code **)(puVar5 + 0x84))(puVar5, piVar6, afStack_a4);
      }
    }
    if (*(char *)(param_3 + 0xf9) != '\0') {
      FUN_800178d4();
    }
    if (bVar1) {
      if (*(char *)(piVar6 + 0x18) == '\0') {
        iVar11 = *(int *)(param_3 + 0x28);
      }
      else {
        iVar11 = piVar6[(*(ushort *)(piVar6 + 6) >> 1 & 1) + 7];
      }
      FUN_800179cc(&DAT_80343a70, param_3 + 0x88, iVar11, (int *)piVar6[0x10],
                   piVar6[(*(ushort *)(piVar6 + 6) >> 1 & 1) + 7]);
      FUN_800179c8(&DAT_80343a70, param_3 + 0xac, *(int *)(param_3 + 0x2c), (uint *)piVar6[0x11],
                   *(byte *)(param_3 + 0x24) & 8);
    }
    if (*(char *)(param_3 + 0xf7) == '\0') {
      iVar11 = *(int *)(puVar5 + 0x2a);
      if (iVar11 != 0) {
        *(char *)(iVar11 + 0xaf) = *(char *)(iVar11 + 0xaf) + -1;
        if (*(char *)(*(int *)(puVar5 + 0x2a) + 0xaf) < '\0') {
          *(undefined *)(*(int *)(puVar5 + 0x2a) + 0xaf) = 0;
        }
      }
    }
    else {
      FUN_800178f0(piVar6, param_3, (int)puVar5, (float *)0x0, (int)(ushort *)(u32)uVar16);
    }
    *(ushort *)(piVar6 + 6) = *(ushort *)(piVar6 + 6) | 8;
  }
  FUN_8003c10c(param_3, piVar6);
  uVar12 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80006adc(local_f8, *(undefined4 *)(param_3 + 0xd4), uVar12, uVar12);
  puVar4 = puVar5;
  if (*(int *)(param_3 + 0xa4) != 0) {
    FUN_80247618(pfVar7, afStack_a4, afStack_64);
    FUN_8025d80c(afStack_64, (uint)DAT_802cbab1);
  }
  do {
    puVar9 = puVar4;
    puVar4 = *(ushort **)(puVar9 + 0x62);
  } while (puVar4 != (ushort *)0x0);
  uVar12 = (uint)*(byte *)(*(int *)(*(int *)(puVar9 + 0x32) + 0xc) + 0x65);
  if (uVar12 == 0xff) {
    local_100 = DAT_803dc0c8;
    FUN_8025c428(3, (byte *)&local_100);
    FUN_8025cce8(0, 1, 0, 5);
  }
  else {
    if (uVar12 < 8) {
      local_fc = ((1 << uVar12) << 0x18) >> 0x10;
    }
    else {
      local_fc = (1 << (uVar12 - 8)) & 0xff;
    }
    local_fc = local_fc << 0x10;
    local_fc = CONCAT31((u32)local_fc >> 8, 0xff);
    local_104 = local_fc;
    FUN_8025c428(3, (byte *)&local_104);
    FUN_8025cce8(2, 1, 0, 7);
  }
  FUN_80258944(0);
  FUN_8025ca04(1);
  FUN_8025be54(0);
  FUN_8025c828(0, 0xff, 0xff, 4);
  FUN_8025be80(0);
  FUN_8025c1a4(0, 0xf, 0xf, 0xf, 6);
  FUN_8025c224(0, 7, 7, 7, 3);
  FUN_8025c65c(0, 0, 0);
  FUN_8025c2a8(0, 0, 0, 0, 1, 0);
  FUN_8025c368(0, 0, 0, 0, 1, 0);
  local_108 = DAT_803dc0c8;
  dVar15 = (double)FLOAT_803df684;
  FUN_8025ca38(dVar15, dVar15, dVar15, dVar15, 0, (uint3 *)&local_108);
  FUN_8006f8a4(1);
  FUN_8025c754(7, 0, 0, 7, 0);
  FUN_8025a608(4, 0, 0, 0, 0, 0, 2);
  FUN_8025a5bc(1);
  if ((*(byte *)(*(int *)(puVar5 + 0x28) + 0x5f) & 4) == 0) {
    FUN_8006f8fc(0, 3, 0);
    FUN_80259288(0);
  }
  else {
    FUN_8006f8fc(1, 3, 1);
    FUN_80259288(1);
  }
  FUN_802585d8(9, piVar6[(*(ushort *)(piVar6 + 6) >> 1 & 1) + 7], 6);
  bVar1 = false;
  uVar12 = local_e8;
  while (local_e8 = uVar12, !bVar1) {
    puVar13 = (undefined *)(local_f8[0] + ((int)local_e8 >> 3));
    uVar3 = local_e8 + 4;
    uVar2 = (CONCAT12(puVar13[2], CONCAT11(puVar13[1], *puVar13)) >> (local_e8 & 7)) & 0xf;
    if (uVar2 == 3) {
      local_e8 = uVar3;
      FUN_80257b5c();
      if (1 < *(byte *)(param_3 + 0xf3)) {
        FUN_802570dc(0, 1);
      }
      puVar13 = (undefined *)(local_f8[0] + ((int)local_e8 >> 3));
      if ((CONCAT12(puVar13[2], CONCAT11(puVar13[1], *puVar13)) >> (local_e8 & 7) & 1) == 0) {
        uVar12 = 2;
      }
      else {
        uVar12 = 3;
      }
      local_e8 = local_e8 + 1;
      FUN_802570dc(9, uVar12);
      if ((*(byte *)(iVar14 + 0x40) & 1) != 0) {
        local_e8 = local_e8 + 1;
      }
      if ((*(byte *)(iVar14 + 0x40) & 2) != 0) {
        local_e8 = local_e8 + 1;
      }
      FUN_802570dc(0xb, 1);
      uVar12 = local_e8 + 1;
    }
    else if (uVar2 < 3) {
      if (uVar2 == 1) {
        puVar13 = (undefined *)(local_f8[0] + ((int)uVar3 >> 3));
        local_e8 = local_e8 + 10;
        iVar14 = FUN_8001792c(param_3,
                              (CONCAT12(puVar13[2], CONCAT11(puVar13[1], *puVar13)) >>
                               (uVar3 & 7)) & 0x3f);
        uVar12 = local_e8;
      }
      else if (uVar2 != 0) {
        puVar13 = (undefined *)(local_f8[0] + ((int)uVar3 >> 3));
        local_e8 = local_e8 + 0xc;
        puVar10 = (undefined4 *)
                  FUN_80017914(param_3, (uint)*(byte *)(param_3 + 0xf5) +
                                       ((CONCAT12(puVar13[2], CONCAT11(puVar13[1], *puVar13)) >>
                                        (uVar3 & 7)) & 0xff));
        FUN_8025d63c(*puVar10, (uint)*(ushort *)(puVar10 + 1));
        uVar12 = local_e8;
      }
    }
    else if (uVar2 == 5) {
      bVar1 = true;
    }
    else if (uVar2 == 4) {
      local_e8 = uVar3;
      FUN_8003df64((undefined4)param_3, (undefined4)piVar6, local_f8, pfVar7);
      uVar12 = local_e8;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800400ac
 * EN v1.0 Address: 0x800400AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800404B8
 * EN v1.1 Size: 3160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800400ac(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800400b0
 * EN v1.0 Address: 0x800400B0
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80041110
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800400b0(void)
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
    piVar2 = (int *)FUN_80017a54((int)puVar1);
    psVar8 = psVar6;
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x72); iVar5 = iVar5 + 1)
    {
      iVar4 = (int)*(char *)((int)psVar8 + *(char *)((int)puVar1 + 0xad) + 0x12);
      if (iVar4 < 0) {
        pfVar3 = (float *)0x0;
      }
      else {
        pfVar3 = (float *)FUN_80017970(piVar2,iVar4);
      }
      FUN_800401a0((float *)0x0,pfVar7 + 3,psVar8 + 3,*(byte *)(psVar6 + 8) & 0x10,puVar1,0);
      FUN_800401a0(pfVar3,pfVar7,psVar8,*(byte *)(psVar6 + 8) & 0x10,puVar1,1);
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
 * Function: FUN_800401a0
 * EN v1.0 Address: 0x800401A0
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x800411FC
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800401a0(float *param_1,float *param_2,short *param_3,int param_4,ushort *param_5,
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
    FUN_80017754(afStack_68,&local_80);
    FUN_80017778((double)local_8c,(double)local_88,(double)local_84,afStack_68,param_2,param_2 + 1,
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
 * Function: FUN_8004034c
 * EN v1.0 Address: 0x8004034C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x800413B0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004034c(undefined param_1,undefined param_2,undefined param_3)
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
 * Function: FUN_8004036c
 * EN v1.0 Address: 0x8004036C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800413CC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004036c(undefined4 param_1)
{
  DAT_803dd8a4 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040374
 * EN v1.0 Address: 0x80040374
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x800413D4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040374(int param_1)
{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  
  DAT_803dd8c0 = 1;
  piVar2 = (int *)FUN_80017a54(param_1);
  uVar1 = DAT_803dd8a4;
  DAT_803dd8bd = (undefined)(int)FLOAT_803dd8b8;
  FUN_80017964((int)piVar2,FUN_8003c1f8);
  for (DAT_803dd8c4 = 0; DAT_803dd8c4 < 0x10; DAT_803dd8c4 = DAT_803dd8c4 + DAT_803dd8c0) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    FUN_800400ac(param_1,iVar3,*piVar2,8);
    DAT_803dd8a4 = uVar1;
  }
  DAT_803dd8a4 = 0;
  FUN_80017964((int)piVar2,0);
  FLOAT_803dd8b8 = FLOAT_803dd8b8 + FLOAT_803dc074;
  if (FLOAT_803df6e0 < FLOAT_803dd8b8) {
    FLOAT_803dd8b8 = FLOAT_803dd8b8 - FLOAT_803df6dc;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040434
 * EN v1.0 Address: 0x80040434
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800414CC
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040434(int param_1)
{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  
  DAT_803dd8c0 = 4;
  piVar2 = (int *)FUN_80017a54(param_1);
  uVar1 = DAT_803dd8a4;
  DAT_803dd8bd = (undefined)(int)FLOAT_803dd8b8;
  for (DAT_803dd8c4 = 0; DAT_803dd8c4 < 0x10; DAT_803dd8c4 = DAT_803dd8c4 + DAT_803dd8c0) {
    iVar3 = param_1;
    if (*(int *)(param_1 + 0xc4) != 0) {
      iVar3 = *(int *)(param_1 + 0xc4);
    }
    DAT_803dd8a4 = uVar1;
    FUN_800400ac(param_1,iVar3,*piVar2,2);
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
 * Function: FUN_800404cc
 * EN v1.0 Address: 0x800404CC
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x800415AC
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800404cc(int param_1)
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
  
  puVar6 = FUN_800069a8();
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
    piVar7 = (int *)FUN_80017a54(param_1);
    iVar9 = DAT_803dd8a4;
    FUN_80017964((int)piVar7,FUN_8003cb48);
    for (DAT_803dd8c4 = 0; DAT_803dd8c4 < iVar10; DAT_803dd8c4 = DAT_803dd8c4 + 1) {
      iVar8 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar8 = *(int *)(param_1 + 0xc4);
      }
      FUN_800400ac(param_1,iVar8,*piVar7,4);
      DAT_803dd8a4 = iVar9;
    }
    DAT_803dd8a4 = 0;
    FUN_80017964((int)piVar7,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800406cc
 * EN v1.0 Address: 0x800406CC
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x800417E8
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800406cc(int param_1)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (FLOAT_803df684 == *(float *)(param_1 + 8)) {
    DAT_803dd8a4 = 0;
  }
  else {
    piVar1 = (int *)FUN_80017a54(param_1);
    iVar2 = *piVar1;
    if (*(char *)(iVar2 + 0xf6) == '\0') {
      FUN_800400ac(param_1,param_1,iVar2,1);
    }
    else {
      fn_8003FDA8(param_1,param_1,iVar2);
    }
    if (*(short *)(param_1 + 0x44) == 1) {
      iVar2 = param_1;
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar3 = iVar3 + 1) {
        if (*(int *)(iVar2 + 200) != 0) {
          FUN_80040784(*(int *)(iVar2 + 200),param_1,1);
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
 * Function: FUN_80040784
 * EN v1.0 Address: 0x80040784
 * EN v1.0 Size: 772b
 * EN v1.1 Address: 0x800418B8
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040784(undefined4 param_1,undefined4 param_2,uint param_3)
{
  undefined2 *puVar1;
  int *piVar2;
  float *pfVar3;
  undefined2 *puVar4;
  ushort *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_e8;
  undefined4 local_e4;
  float local_e0;
  ushort local_dc;
  undefined2 local_da;
  undefined2 local_d8;
  float local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  float afStack_c4[3];
  float local_b8;
  undefined4 local_a8;
  float local_98;
  float afStack_84[27];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_80286840();
  puVar1 = (undefined2 *)(ulonglong)(uVar11 >> 0x20);
  puVar5 = (ushort *)(u32)uVar11;
  if (FLOAT_803df684 == *(float *)(puVar1 + 4)) {
    DAT_803dd8a4 = 0;
  }
  else {
    FUN_80017a54((int)puVar1);
    piVar2 = (int *)FUN_80017a54((int)puVar5);
    iVar8 = ((ushort)puVar1[0x58] & 7) * 0x18;
    iVar7 = *(int *)(*(int *)(puVar5 + 0x28) + 0x2c) + iVar8;
    iVar6 = (int)*(char *)(iVar7 + *(char *)((int)puVar5 + 0xad) + 0x12);
    local_d0 = *(undefined4 *)(*(int *)(*(int *)(puVar5 + 0x28) + 0x2c) + iVar8);
    local_cc = *(undefined4 *)(iVar7 + 4);
    local_c8 = *(undefined4 *)(iVar7 + 8);
    if (iVar6 == -1) {
      FUN_80017a50(puVar5, afStack_84, '\0');
      pfVar3 = afStack_84;
    }
    else {
      pfVar3 = (float *)FUN_80017970(piVar2, iVar6);
    }
    if ((*(byte *)(*(int *)(puVar1 + 0x28) + 0x5f) & 8) == 0) {
      local_d4 = FLOAT_803df69c;
      iVar8 = *(int *)(*(int *)(puVar5 + 0x28) + 0x2c) + iVar8;
      local_dc = *(ushort *)(iVar8 + 0xc);
      local_da = *(undefined2 *)(iVar8 + 0xe);
      local_d8 = *(undefined2 *)(iVar8 + 0x10);
      FUN_80017700(&local_dc, afStack_c4);
      FUN_80247618(pfVar3, afStack_c4, afStack_c4);
    }
    else {
      puVar4 = FUN_800069a8();
      local_d4 = *(float *)(puVar1 + 4);
      dVar10 = (double)(*(float *)(puVar1 + 6) - *(float *)(puVar4 + 6));
      dVar9 = (double)(*(float *)(puVar1 + 10) - *(float *)(puVar4 + 10));
      iVar8 = FUN_80017730();
      local_dc = (short)iVar8 + 0x8000;
      FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
      iVar8 = FUN_80017730();
      local_da = (undefined2)iVar8;
      local_d8 = puVar4[2];
      FUN_80017700(&local_dc, afStack_c4);
      local_e8 = local_b8;
      local_e4 = local_a8;
      local_e0 = local_98;
      FUN_80247bf8(pfVar3, &local_e8, &local_e8);
      local_b8 = local_e8;
      local_a8 = local_e4;
      local_98 = local_e0;
    }
    if ((param_3 & 0xff) == 0) {
      *(float *)(puVar1 + 0xc) = local_b8 + FLOAT_803dda58;
      *(undefined4 *)(puVar1 + 0xe) = local_a8;
      *(float *)(puVar1 + 0x10) = local_98 + FLOAT_803dda5c;
      if (*(int *)(puVar1 + 0x18) == 0) {
        *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(puVar1 + 0xc);
        *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(puVar1 + 0xe);
        *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(puVar1 + 0x10);
      }
      else {
        FUN_800068f4((double)*(float *)(puVar1 + 0xc), (double)*(float *)(puVar1 + 0xe),
                     (double)*(float *)(puVar1 + 0x10), (float *)(puVar1 + 6),
                     (float *)(puVar1 + 8), (float *)(puVar1 + 10), *(int *)(puVar1 + 0x18));
      }
      FUN_8003bbfc(afStack_c4, puVar1, puVar1 + 1, puVar1 + 2);
    }
    *(char *)((int)puVar1 + 0x37) =
         (char)((*(byte *)(puVar1 + 0x1b) + 1) * (uint)*(byte *)((int)puVar5 + 0x37) >> 8);
    *(undefined *)((int)puVar1 + 0xf1) = *(undefined *)((int)puVar5 + 0xf1);
    if ((puVar1[3] & 0x4000) == 0) {
      DAT_803dd8a4 = (undefined4)afStack_c4;
      if ((param_3 & 0xff) == 0) {
        puVar1[0x58] = puVar1[0x58] | 0x800;
        FUN_80040a88((int)puVar1);
      }
      else {
        FUN_800406cc((int)puVar1);
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040a88
 * EN v1.0 Address: 0x80040A88
 * EN v1.0 Size: 584b
 * EN v1.1 Address: 0x80041BBC
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040a88(int param_1)
{
  short sVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 local_48;
  int local_44;
  int local_40;
  int local_3c;
  float local_38;
  float local_34;
  float local_30;
  int local_2c;
  int local_28;
  float local_24;
  undefined4 local_20[2];
  longlong local_18;
  
  piVar2 = (int *)FUN_80017a54(param_1);
  if (FLOAT_803df684 == *(float *)(param_1 + 8)) {
    DAT_803dd8a4 = 0;
  }
  else {
    iVar3 = *piVar2;
    if ((*(ushort *)(iVar3 + 2) & 0x8000) == 0) {
      iVar4 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar4 = *(int *)(param_1 + 0xc4);
      }
      FUN_800400ac(param_1, iVar4, iVar3, 0);
    }
    else {
      iVar4 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar4 = *(int *)(param_1 + 0xc4);
      }
      fn_8003F8EC(param_1, iVar4, iVar3);
    }
    iVar3 = param_1;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar4 = iVar4 + 1) {
      if (*(int *)(iVar3 + 200) != 0) {
        FUN_80040784(*(int *)(iVar3 + 200), param_1, 0);
      }
      iVar3 = iVar3 + 4;
    }
    if (((((*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 4) && (DAT_803dd8a9 == '\0')) &&
         ((sVar1 = *(short *)(param_1 + 0x46), sVar1 != 0x6a8 && (sVar1 != 0x6a9)))) &&
        ((sVar1 != 0x6aa && (sVar1 != 0x6ab)))) &&
       ((sVar1 != 0x6ac && (sVar1 != 0x752)))) {
      FUN_80006940((double)(*(float *)(param_1 + 0xc) - FLOAT_803dda58),
                   (double)*(float *)(param_1 + 0x10),
                   (double)(*(float *)(param_1 + 0x14) - FLOAT_803dda5c),
                   (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)), &local_30,
                   &local_34, &local_38);
      FUN_80006938((double)local_30, (double)local_34, (double)local_38, &local_3c, &local_40,
                   &local_44);
      iVar3 = FUN_8006f690(local_3c, local_40, param_1);
      if (iVar3 < local_44) {
        *(undefined2 *)(*(int *)(param_1 + 100) + 0x36) = 0xffe0;
      }
      else {
        *(undefined2 *)(*(int *)(param_1 + 100) + 0x36) = 0x20;
      }
      iVar4 = *(int *)(param_1 + 100);
      iVar3 = (uint)*(byte *)(iVar4 + 0x40) + (int)*(short *)(iVar4 + 0x36);
      if (iVar3 < 0x100) {
        if (iVar3 < 0) {
          *(undefined *)(iVar4 + 0x40) = 0;
        }
        else {
          *(char *)(iVar4 + 0x40) = (char)iVar3;
        }
      }
      else {
        *(undefined *)(iVar4 + 0x40) = 0xff;
      }
      *(undefined *)((int)&DAT_803dc0e8 + 3) = *(undefined *)(*(int *)(param_1 + 100) + 0x40);
      FUN_8006b03c(param_1, local_20, &local_24, &local_28, &local_2c);
      local_48 = DAT_803dc0e8;
      local_18 = (longlong)(int)(FLOAT_803df6ec * local_24);
      FUN_800709e4(local_20[0], local_28, local_2c, &local_48,
                   (int)(FLOAT_803df6ec * local_24), 1);
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_80040cd0
 * EN v1.0 Address: 0x80040CD0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80041E20
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040cd0(undefined param_1)
{
  DAT_803dd8a9 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040cdc
 * EN v1.0 Address: 0x80040CDC
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80041E28
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040cdc(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
    DAT_803dd908 = DAT_803dd908 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040d44
 * EN v1.0 Address: 0x80040D44
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80041E90
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80040d44(int param_1)
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
 * Function: FUN_80040d88
 * EN v1.0 Address: 0x80040D88
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80041F1C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040d88(void)
{
  DAT_803dd8f0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040d94
 * EN v1.0 Address: 0x80040D94
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80041F28
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040d94(void)
{
  DAT_803dd8f0 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80040da0
 * EN v1.0 Address: 0x80040DA0
 * EN v1.0 Size: 1036b
 * EN v1.1 Address: 0x80041F34
 * EN v1.1 Size: 1028b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80040da0(void)
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
  FUN_8001782c(2);
  FUN_80243e74();
  iVar6 = DAT_803dd900;
  FUN_80243e9c();
  if (iVar6 == 0) {
    if ((iVar2 == 0) && (DAT_803dd8f8 == 0)) {
      FUN_800530b4();
      DAT_803dd8f8 = 6;
    }
    else {
      if (iVar2 != 0) {
        FUN_800177b4(1);
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
            if (((((*puVar7 != 0) && (*psVar8 != -1)) && (iVar3 = FUN_80017800(*puVar7), iVar3 == 0)
                 ) && ((iVar2 != 2 ||
                       (((iVar6 != 0x20 && (iVar6 != 0x4b)) && ((iVar6 != 0x23 && (iVar6 != 0x4d))))
                       )))) && (uVar4 = FUN_80017830(*piVar9 + 0x20,0x7d7d7d7d), uVar4 != 0)) {
              FUN_80003494(uVar4,*puVar7,*piVar9);
              uVar5 = FUN_80017818(0);
              FUN_80017814(*puVar7);
              *puVar7 = 0;
              *puVar7 = uVar4;
              FUN_80017818(uVar5);
            }
          }
          *puVar10 = 0;
          puVar7 = puVar7 + 1;
          psVar8 = psVar8 + 1;
          piVar9 = piVar9 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
        FUN_800177b4(0xffffffff);
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
            if (((*puVar7 == 0) || (*psVar8 == -1)) || (iVar3 = FUN_80017800(*puVar7), iVar3 != 0))
            {
              if (((((iVar2 != 2) && (iVar11 != 0)) && ((*puVar7 != 0 && (*psVar8 != -1)))) &&
                  ((iVar3 = FUN_80017800(*puVar7), iVar3 == 1 ||
                   (iVar3 = FUN_80017800(*puVar7), iVar3 == 2)))) &&
                 ((uVar4 = FUN_80017824(*puVar7), 0x2fff < (int)uVar4 &&
                  (uVar4 = FUN_80017830(*piVar9 + 0x20,0x7d7d7d7d), uVar4 != 0)))) {
                iVar3 = FUN_80017800(uVar4);
                if (iVar3 == 0) {
                  FUN_80003494(uVar4,*puVar7,*piVar9);
                  uVar5 = FUN_80017818(0);
                  FUN_80017814(*puVar7);
                  *puVar7 = 0;
                  *puVar7 = uVar4;
                  FUN_80017818(uVar5);
                  bVar1 = false;
                }
                else {
                  uVar5 = FUN_80017818(0);
                  FUN_80017814(uVar4);
                  FUN_80017818(uVar5);
                }
              }
            }
            else {
              uVar4 = FUN_80017830(*piVar9 + 0x20,0x7d7d7d7d);
              if (uVar4 != 0) {
                iVar3 = *piVar9;
                if ((iVar3 < 210000) || (uVar4 <= *puVar7)) {
                  if ((iVar3 < 210000) && (uVar4 < *puVar7)) {
                    uVar5 = FUN_80017818(0);
                    FUN_80017814(uVar4);
                    FUN_80017818(uVar5);
                  }
                  else {
                    FUN_80003494(uVar4,*puVar7,iVar3);
                    uVar5 = FUN_80017818(0);
                    FUN_80017814(*puVar7);
                    *puVar7 = 0;
                    *puVar7 = uVar4;
                    FUN_80017818(uVar5);
                    bVar1 = false;
                  }
                }
                else {
                  uVar5 = FUN_80017818(0);
                  FUN_80017814(uVar4);
                  FUN_80017818(uVar5);
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
      FUN_8001782c(0);
    }
  }
  FUN_80286874();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800411ac
 * EN v1.0 Address: 0x800411AC
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042338
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800411ac(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041248
 * EN v1.0 Address: 0x80041248
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x800423F0
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041248(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_800412e4
 * EN v1.0 Address: 0x800412E4
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x800424A8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800412e4(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041380
 * EN v1.0 Address: 0x80041380
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042560
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041380(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_8004141c
 * EN v1.0 Address: 0x8004141C
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042618
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004141c(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_800414b8
 * EN v1.0 Address: 0x800414B8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800426D0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800414b8(int param_1,int *param_2)
{
  DAT_803dd8f4 = 0;
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004151c
 * EN v1.0 Address: 0x8004151C
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042734
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004151c(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_800415b8
 * EN v1.0 Address: 0x800415B8
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x800427EC
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800415b8(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
    FUN_80017814(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x8000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x8000;
      DAT_80346d00 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041664
 * EN v1.0 Address: 0x80041664
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x800428B8
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041664(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
    FUN_80017814(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x4000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x4000;
      DAT_80346c54 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041710
 * EN v1.0 Address: 0x80041710
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042984
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041710(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_800417ac
 * EN v1.0 Address: 0x800417AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80042A3C
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800417ac(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
    FUN_80017814(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x800) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x800;
      DAT_80346d08 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041858
 * EN v1.0 Address: 0x80041858
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80042B08
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041858(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
    FUN_80017814(DAT_803600d8);
    DAT_803600d8 = 0;
    DAT_80346c60 = 0;
    if ((DAT_803dd900 & 0x400) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x400;
      DAT_80346c60 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041904
 * EN v1.0 Address: 0x80041904
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042BD4
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041904(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_800419a0
 * EN v1.0 Address: 0x800419A0
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042C8C
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800419a0(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041a3c
 * EN v1.0 Address: 0x80041A3C
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042D44
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041a3c(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041ad8
 * EN v1.0 Address: 0x80041AD8
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042DFC
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041ad8(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041b74
 * EN v1.0 Address: 0x80041B74
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80042EB4
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041b74(int param_1,int *param_2)
{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_8001784c(DAT_803dd90c,param_2);
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
 * Function: FUN_80041c10
 * EN v1.0 Address: 0x80041C10
 * EN v1.0 Size: 1000b
 * EN v1.1 Address: 0x80042F6C
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80041c10(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
  uVar2 = FUN_800443fc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_800443fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80041ff8
 * EN v1.0 Address: 0x80041FF8
 * EN v1.0 Size: 2000b
 * EN v1.1 Address: 0x80043070
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80041ff8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
      FUN_80041c10(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2);
      return iVar2;
    }
  }
  FUN_80041c10(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_800427c8
 * EN v1.0 Address: 0x800427C8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x8004312C
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800427c8(void)
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
 * Function: FUN_80042800
 * EN v1.0 Address: 0x80042800
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8004316C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042800(void)
{
  FUN_80243e74();
  DAT_803dd900 = DAT_803dd900 | 0x100000;
  FUN_80243e9c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80042830
 * EN v1.0 Address: 0x80042830
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8004319C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80042830(void)
{
  return DAT_803dd8f4;
}

/*
 * --INFO--
 *
 * Function: FUN_80042838
 * EN v1.0 Address: 0x80042838
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800431A4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80042838(void)
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
 * Function: FUN_8004286c
 * EN v1.0 Address: 0x8004286C
 * EN v1.0 Size: 816b
 * EN v1.1 Address: 0x800431D8
 * EN v1.1 Size: 1068b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8004286c(void)
{
  uint uVar1;
  
  FUN_80243e74();
  FUN_80243e74();
  uVar1 = DAT_803dd900;
  FUN_80243e9c();
  if ((((DAT_803dd914 & 4) != 0) && ((uVar1 & 4) == 0)) && (DAT_8035fc54 == -1)) {
    FUN_80043034((uint *)&DAT_8035db50,0x2a,0x45);
  }
  if ((((DAT_803dd914 & 8) != 0) && ((uVar1 & 8) == 0)) && (DAT_8035fcc0 == -1)) {
    FUN_80043034((uint *)&DAT_8035db50,0x2a,0x45);
  }
  if ((((DAT_803dd914 & 0x40) != 0) && ((uVar1 & 0x40) == 0)) && (DAT_8035fc68 == -1)) {
    FUN_80043034((uint *)&DAT_8035ac70,0x2f,0x49);
  }
  if ((((DAT_803dd914 & 0x80) != 0) && ((uVar1 & 0x80) == 0)) && (DAT_8035fcd0 == -1)) {
    FUN_80043034((uint *)&DAT_8035ac70,0x2f,0x49);
  }
  if ((((DAT_803dd914 & 0x400) != 0) && ((uVar1 & 0x400) == 0)) && (DAT_8035fc34 == -1)) {
    FUN_80043034((uint *)&DAT_80356c70,0x24,0x4e);
  }
  if ((((DAT_803dd914 & 0x800) != 0) && ((uVar1 & 0x800) == 0)) && (DAT_8035fcdc == -1)) {
    FUN_80043034((uint *)&DAT_80356c70,0x24,0x4e);
  }
  if ((((DAT_803dd914 & 0x4000) != 0) && ((uVar1 & 0x4000) == 0)) && (DAT_8035fc28 == -1)) {
    FUN_80043034((uint *)&DAT_80352c70,0x21,0x4c);
  }
  if ((((DAT_803dd914 & 0x8000) != 0) && ((uVar1 & 0x8000) == 0)) && (DAT_8035fcd4 == -1)) {
    FUN_80043034((uint *)&DAT_80352c70,0x21,0x4c);
  }
  if ((((DAT_803dd914 & 0x20000) != 0) && ((uVar1 & 0x20000) == 0)) && (DAT_8035fc3c == -1)) {
    FUN_80043034((uint *)&DAT_80350c70,0x26,0x48);
  }
  if ((((DAT_803dd914 & 0x80000) != 0) && ((uVar1 & 0x80000) == 0)) && (DAT_8035fcc4 == -1)) {
    FUN_80043034((uint *)&DAT_80350c70,0x26,0x48);
  }
  if ((((DAT_803dd914 & 0x2000000) != 0) && ((uVar1 & 0x2000000) == 0)) && (DAT_8035fc14 == -1)) {
    FUN_80043034((uint *)&DAT_8034ec70,0x1a,0x53);
  }
  if ((((DAT_803dd914 & 0x8000000) != 0) && ((uVar1 & 0x8000000) == 0)) && (DAT_8035fcf8 == -1)) {
    FUN_80043034((uint *)&DAT_8034ec70,0x1a,0x53);
  }
  if ((((DAT_803dd914 & 0x20000000) != 0) && ((uVar1 & 0x20000000) == 0)) && (DAT_8035fbdc == -1)) {
    FUN_80043034((uint *)&DAT_80346d30,0xe,0x56);
  }
  if ((((DAT_803dd914 & 0x80000000) != 0) && ((uVar1 & 0x80000000) == 0)) && (DAT_8035fcfc == -1)) {
    FUN_80043034((uint *)&DAT_80346d30,0xe,0x56);
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
 * Function: FUN_80042b9c
 * EN v1.0 Address: 0x80042B9C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80043604
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80042b9c(int param_1,int param_2,int param_3)
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
 * Function: FUN_80042bec
 * EN v1.0 Address: 0x80042BEC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80043658
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80042bec(undefined4 param_1,int param_2)
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
 * Function: FUN_80042c18
 * EN v1.0 Address: 0x80042C18
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80043680
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80042c18(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
      uVar9 = FUN_80006c1c();
      FUN_800176a8();
      if (bVar1) {
        uVar9 = FUN_8004600c();
      }
      uVar9 = FUN_80044424(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80006c28(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (bVar1) {
        uVar9 = FUN_80017810();
        FUN_800174b8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80045c4c('\x01');
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
 * Function: FUN_80042f88
 * EN v1.0 Address: 0x80042F88
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80043860
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_80042f88(int param_1)
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
 * Function: FUN_80043030
 * EN v1.0 Address: 0x80043030
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80043938
 * EN v1.1 Size: 1324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80043030(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80043034
 * EN v1.0 Address: 0x80043034
 * EN v1.0 Size: 1712b
 * EN v1.1 Address: 0x80043E64
 * EN v1.1 Size: 1708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80043034(uint *param_1,int param_2,int param_3)
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

/* sda21 accessors. */
extern u32 lbl_803DCC24;
extern u8 lbl_803DCC29;
extern u32 lbl_803DCC74;
void fn_800412D4(u32 x) { lbl_803DCC24 = x; }
void fn_80041D28(u8 x) { lbl_803DCC29 = x; }
u32 fn_800430A4(void) { return lbl_803DCC74; }
