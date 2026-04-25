#include "ghidra_import.h"
#include "main/dll/DIM/DIMboss.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_80006b0c();
extern undefined8 FUN_80006c1c();
extern undefined4 FUN_80006c28();
extern undefined4 FUN_800174b8();
extern undefined4 FUN_80017620();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_800176a8();
extern undefined8 FUN_80017810();
extern undefined8 FUN_8001793c();
extern int FUN_80017a54();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 FUN_80037180();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80040da0();
extern undefined8 FUN_800427c8();
extern undefined8 FUN_80042800();
extern uint FUN_80042838();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined8 FUN_80043030();
extern undefined8 FUN_800443fc();
extern undefined4 FUN_80044404();
extern undefined8 FUN_80044424();
extern undefined4 FUN_80045c4c();
extern undefined8 FUN_8004600c();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_8005fe14();
extern undefined8 FUN_800723a0();
extern undefined8 FUN_801149b8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_801bb848();
extern undefined4 FUN_801bbed0();
extern undefined8 FUN_801bcc94();
extern undefined4 FUN_80286834();
extern undefined4 FUN_80286880();

extern undefined4 fn_8000FACC();
extern undefined4 fn_80013E2C();
extern undefined4 fn_8001F384();
extern undefined4 fn_800200E8();
extern undefined4 fn_8002CBC4();
extern undefined4 fn_80036FA4();
extern undefined4 fn_8003B8F4();
extern undefined4 fn_80055000();
extern undefined4 fn_800604B4();
extern undefined4 fn_80114DEC();
extern undefined4 fn_801BB598();

extern undefined4 DAT_803ad63c;
extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc78;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4 DAT_803de808;
extern f32 FLOAT_803e58dc;
extern f32 FLOAT_803e5908;
extern undefined4 lbl_803AC9DC[];
extern undefined4 lbl_803AD018[];
extern int lbl_803DCA8C;
extern undefined4* lbl_803DCAB8;
extern undefined4 lbl_803DDB88;
extern f32 lbl_803E4C44;

/*
 * --INFO--
 *
 * Function: DIMboss_updateState
 * EN v1.0 Address: 0x801BCB34
 * EN v1.0 Size: 3404b
 * EN v1.1 Address: 0x801BD0E8
 * EN v1.1 Size: 1836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_updateState(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8,undefined4 param_9,undefined4 param_10,int param_11,
                         undefined4 param_12,undefined4 param_13,int param_14,int param_15,
                         undefined4 param_16)
{
  byte bVar1;
  bool bVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  undefined8 uVar14;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  
  puVar3 = (undefined4 *)FUN_80286834();
  puVar13 = (undefined4 *)puVar3[0x2e];
  iVar12 = puVar3[0x13];
  FUN_80017a98();
  iVar11 = puVar13[0x103];
  *(undefined2 *)((int)puVar13 + 0x402) = 0;
  uVar14 = (**(code **)(*DAT_803dd72c + 0x50))(0x1c,5,0);
  if (puVar3[0x3d] == 0) {
    puVar7 = (undefined4 *)&DAT_803ad63c;
    puVar8 = (undefined4 *)0x1;
    puVar9 = (undefined4 *)0x1;
    uVar14 = FUN_801149b8(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                          param_11,(float *)&DAT_803ad63c,1,1,param_14,param_15,param_16);
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
      switch(*(undefined *)(param_11 + iVar10 + 0x81)) {
      case 1:
        (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x800,0,100,0);
        (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x800,0,100,0);
        (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x7ff,0,100,0);
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)0x64;
        puVar9 = (undefined4 *)0x0;
        param_14 = *DAT_803dd734;
        (**(code **)(param_14 + 0xc))(puVar3,0x7ff);
        iVar4 = FUN_80017a54((int)puVar3);
        uVar14 = FUN_8001793c(iVar4);
        FUN_800067c0((int *)0x27,1);
        break;
      case 2:
        *(undefined2 *)((int)puVar13 + 0x402) = 1;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 0x80;
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)*DAT_803dd72c;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,0);
        break;
      case 6:
        DAT_803de800 = DAT_803de800 | 0x40004;
        break;
      case 7:
        DAT_803de800 = DAT_803de800 | 2;
        break;
      case 8:
        iVar11 = puVar13[0x103];
        *(byte *)(iVar11 + 0xb6) = *(byte *)(iVar11 + 0xb6) & 0x7f | 0x80;
        FUN_800067c0((int *)0xee,0);
        break;
      case 9:
        DAT_803de800 = DAT_803de800 | 0x40;
        break;
      case 10:
        DAT_803de800 = DAT_803de800 & 0xffffffbf;
        break;
      case 0xc:
        DAT_803de800 = DAT_803de800 & 0xffffff7f;
        break;
      case 0xd:
        DAT_803de800 = DAT_803de800 | 0x100;
        break;
      case 0xe:
        DAT_803de800 = DAT_803de800 & 0xfffffeff;
        break;
      case 0xf:
        DAT_803de800 = DAT_803de800 | 0x2001;
        break;
      case 0x10:
        DAT_803de800 = DAT_803de800 | 0x8021;
        break;
      case 0x11:
        *(undefined4 *)(iVar11 + 0xb0) = 10;
        FUN_80017698(0x123,1);
        uVar14 = FUN_80017698(0x17,1);
        FUN_800067c0((int *)0x27,0);
        FUN_800067c0((int *)0x36,0);
        FUN_800067c0((int *)0xee,0);
        break;
      case 0x12:
        puVar8 = (undefined4 *)0x3c;
        puVar9 = (undefined4 *)*DAT_803dd6d4;
        puVar7 = puVar3;
        uVar14 = (*(code *)puVar9[0x14])(0x49,4);
        break;
      case 0x13:
        puVar7 = (undefined4 *)0x1;
        puVar8 = (undefined4 *)*DAT_803dd72c;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,2);
        break;
      case 0x14:
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)*DAT_803dd72c;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,2);
        break;
      case 0x15:
        FUN_800723a0();
        uVar14 = FUN_80042800();
        puVar7 = (undefined4 *)0x1;
        FUN_80042b9c(0,0,1);
        FUN_80044404(0x1c);
        uVar14 = FUN_80043030(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x1b);
        FUN_80043030(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        uVar14 = FUN_80040da0();
        break;
      case 0x16:
        uVar14 = FUN_800723a0();
        uVar5 = FUN_80044404(0x13);
        FUN_80042bec(uVar5,0);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        uVar14 = FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_80044404(0x13);
        FUN_800443fc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        bVar2 = false;
        while (uVar6 = FUN_80042838(), (uVar6 & 0xffefffff) != 0) {
          uVar14 = FUN_80006c1c();
          FUN_800176a8();
          if (bVar2) {
            uVar14 = FUN_8004600c();
          }
          uVar14 = FUN_80044424(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80006c28(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar14 = FUN_80017810();
            FUN_800174b8(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80045c4c('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
        uVar14 = FUN_800427c8();
        break;
      case 0x17:
        DAT_803de800 = DAT_803de800 | 0x80000;
        break;
      case 0x18:
        DAT_803de800 = DAT_803de800 & 0xfff7ffff;
      }
    }
    if (*(short *)(puVar3 + 0x2d) != -1) {
      puVar7 = (undefined4 *)0x1;
      puVar8 = (undefined4 *)*DAT_803dd738;
      iVar11 = (*(code *)puVar8[0xc])(puVar3,puVar13);
      if (iVar11 == 0) goto LAB_801bd7dc;
      if (puVar3[0x32] != 0) {
        *(undefined4 *)(puVar3[0x32] + 0x30) = puVar3[0xc];
      }
      uVar14 = extraout_f1;
      if (((int)*(short *)((int)puVar13 + 0x3f6) != 0xffffffff) &&
         (uVar6 = FUN_80017690((int)*(short *)((int)puVar13 + 0x3f6)), uVar6 != 0)) {
        puVar7 = (undefined4 *)*DAT_803dd6d4;
        uVar14 = (*(code *)puVar7[0x16])(param_11,(int)*(short *)(iVar12 + 0x2c));
        *(undefined2 *)((int)puVar13 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)((int)puVar13 + 0x405);
      if (bVar1 == 1) {
        puVar8 = &DAT_803adc78;
        puVar9 = &DAT_803adc60;
        param_14 = 0;
        param_15 = *DAT_803dd738;
        puVar7 = puVar13;
        iVar11 = (**(code **)(param_15 + 0x34))(puVar3,param_11);
        uVar14 = extraout_f1_00;
        if (iVar11 != 0) {
          puVar7 = (undefined4 *)0x1;
          puVar8 = (undefined4 *)*DAT_803dd738;
          uVar14 = (*(code *)puVar8[0xb])((double)FLOAT_803e5908,puVar3,puVar13);
        }
      }
      else if ((bVar1 != 0) && (bVar1 < 3)) {
        *(undefined2 *)(param_11 + 0x6e) = 0;
        puVar7 = puVar13;
        puVar8 = puVar13;
        uVar14 = FUN_801bcc94(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                              param_11,(int)puVar13,(int)puVar13);
        if (*(char *)((int)puVar13 + 0x405) == '\x01') {
          *(undefined2 *)(puVar13 + 0x9c) = 0;
          param_2 = (double)FLOAT_803e58dc;
          puVar7 = &DAT_803adc78;
          puVar8 = &DAT_803adc60;
          puVar9 = (undefined4 *)*DAT_803dd70c;
          uVar14 = (*(code *)puVar9[2])(puVar3,puVar13);
          *(undefined *)(param_11 + 0x56) = 0;
        }
      }
    }
    FUN_801bbed0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,puVar13,
                 puVar7,puVar8,puVar9,param_14,param_15,param_16);
    if (*(short *)(puVar3 + 0x2d) == -1) {
      *(ushort *)(puVar13 + 0x100) = *(ushort *)(puVar13 + 0x100) | 2;
    }
  }
LAB_801bd7dc:
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: dimboss_func11
 * EN v1.0 Address: 0x801BD240
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_func11(void)
{
}

/*
 * --INFO--
 *
 * Function: dimboss_setScale
 * EN v1.0 Address: 0x801BD244
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimboss_setScale(int param_1)
{
  return (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x274);
}

/*
 * --INFO--
 *
 * Function: dimboss_getExtraSize
 * EN v1.0 Address: 0x801BD250
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimboss_getExtraSize(void)
{
  return 0x4c8;
}

/*
 * --INFO--
 *
 * Function: dimboss_func08
 * EN v1.0 Address: 0x801BD258
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimboss_func08(void)
{
  return 0x49;
}

/*
 * --INFO--
 *
 * Function: dimboss_free
 * EN v1.0 Address: 0x801BD260
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_free(int param_1)
{
  int iVar1;

  iVar1 = *(int *)(param_1 + 0xb8);
  fn_800200E8(0xefd,0);
  fn_800200E8(0xc1e,1);
  fn_800200E8(0xc1f,0);
  fn_800200E8(0xc20,0);
  fn_800200E8(0xd8f,0);
  fn_800200E8(0x3e2,0);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0x7f;
  fn_8000FACC();
  fn_80036FA4(param_1,3);
  if (*(int *)(param_1 + 0xc8) != 0) {
    fn_8002CBC4();
    *(undefined4 *)(param_1 + 0xc8) = 0;
  }
  (**(code **)(*lbl_803DCAB8 + 0x40))(param_1,iVar1,0x20);
  if (lbl_803DDB88 != 0) {
    fn_80013E2C();
  }
  lbl_803DDB88 = 0;
  if (**(int **)(iVar1 + 0x40c) != 0) {
    fn_8001F384();
  }
  fn_80055000();
}

/*
 * --INFO--
 *
 * Function: dimboss_render
 * EN v1.0 Address: 0x801BD364
 * EN v1.0 Size: 176b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_render(int param_1)
{
  char in_r8;
  int iVar1;

  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    if (*(int *)(param_1 + 0xf4) == 0) {
      if (*(short *)(iVar1 + 0x402) != 3) {
        fn_8003B8F4((double)lbl_803E4C44);
        fn_801BB598(param_1,iVar1);
        fn_80114DEC(param_1,lbl_803AC9DC,0);
        iVar1 = **(int **)(iVar1 + 0x40c);
        if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) &&
            (*(char *)(iVar1 + 0x4c) != '\0')) {
          fn_800604B4();
        }
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: dimboss_hitDetect
 * EN v1.0 Address: 0x801BD414
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_hitDetect(int param_1)
{
  (*(code *)(*(int *)lbl_803DCA8C + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),
                                           lbl_803AD018);
}
